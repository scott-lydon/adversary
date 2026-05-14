"""Learned-attacks store: promotes confirmed exploits into reusable defaults.

When the Judge returns ``VerdictLabel.SUCCESS`` for an attack, the Orchestrator
calls :func:`promote` to persist a normalized record into
``<repo_root>/.runtime/learned_attacks.json``. The next time *anyone* asks for
the default attack set for that category — the ``ScriptedProvider`` for offline
runs, or the ``LiteLLMProvider`` building its novelty hint — the learned
attacks are merged in.

Design contract
---------------

* **Single file, atomic writes.** All learned attacks live in one JSON file
  under ``.runtime/`` so the source tree stays clean. Writes go through a
  temp file plus ``os.replace`` so a crash mid-write cannot corrupt the file.

* **Process-local lock only.** A ``threading.Lock`` serializes writes within
  one process. Cross-process collisions on the same file rely on the
  atomic-rename invariant: the last writer wins; no partial file is ever
  visible. If parallel scans become common, swap to ``fcntl.flock``.

* **Dedup by normalized prompt.** Two attacks count as the same if their
  normalized prompt text matches (lowercased, whitespace-collapsed, trailing
  ``-NNNN`` canary token stripped). Different categories may keep the same
  prompt independently.

* **Confidence floor.** Only verdicts at or above
  :data:`DEFAULT_CONFIDENCE_THRESHOLD` are promoted. The Judge sometimes
  emits a 0.55 ``PARTIAL`` that the orchestrator never sees as SUCCESS, but
  guarding here keeps the store honest if the call site changes.

* **Bounded growth.** Each ``(category, subcategory)`` bucket keeps at most
  :data:`DEFAULT_MAX_PER_BUCKET` entries; if a promotion would exceed the
  cap, the lowest-confidence existing entry is evicted.

* **Schema versioned.** ``version: 1``. A higher version on disk raises so a
  newer client never silently drops fields a future schema added.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from adversary.models import Attack, AttackCategory, Verdict, VerdictLabel

# Repo root resolution: this file is at src/adversary/learning.py, so two
# parents up from the *src* directory gets us the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LEARNED_ATTACKS_PATH = _REPO_ROOT / ".runtime" / "learned_attacks.json"

# Env override so test runs, ops handoffs, and shared deployments can point
# the store at a different file without code edits. The autouse pytest
# fixture sets this to a per-test tmp path so tests never write to the real
# .runtime/ file.
_LEARNED_ATTACKS_PATH_ENV = "ADVERSARY_LEARNED_ATTACKS_PATH"


def _resolve_default_path() -> Path:
    """Resolve the default learned-attacks file path, honoring the env override.

    The env var wins over the repo-root default whenever it is set and
    non-empty. Resolution happens at call time (not at import time) so a
    test fixture can set the env var before the orchestrator constructs
    its store.
    """
    override = os.environ.get(_LEARNED_ATTACKS_PATH_ENV, "").strip()
    if override:
        return Path(override)
    return DEFAULT_LEARNED_ATTACKS_PATH

SCHEMA_VERSION = 1
DEFAULT_CONFIDENCE_THRESHOLD = 0.8
DEFAULT_MAX_PER_BUCKET = 50

# Strip the scripted provider's "-NNNN" canary suffix and any trailing
# whitespace before hashing, so a re-run with a different seed dedups.
_SEED_SUFFIX_RE = re.compile(r"-\d{4,}\b\s*$")
_WHITESPACE_RE = re.compile(r"\s+")


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LearnedAttack:
    """One promoted attack persisted in the learned-attacks store.

    The dataclass is intentionally narrower than :class:`Attack` — the
    storage format only needs the fields a future RedTeam call wants back:
    the prompt text, what the unsafe behavior looked like, and provenance.
    """

    category: str
    subcategory: str
    prompt: str
    expected_unsafe_behavior: str
    judge_confidence: float
    source: str          # "scripted" | "live" | "regression" | ...
    model: str           # the red-team model that minted this prompt
    promoted_at: str     # ISO8601 UTC
    report_id: str | None
    attack_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "subcategory": self.subcategory,
            "prompt": self.prompt,
            "expected_unsafe_behavior": self.expected_unsafe_behavior,
            "judge_confidence": self.judge_confidence,
            "source": self.source,
            "model": self.model,
            "promoted_at": self.promoted_at,
            "report_id": self.report_id,
            "attack_id": self.attack_id,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "LearnedAttack":
        missing = [
            k
            for k in (
                "category",
                "subcategory",
                "prompt",
                "expected_unsafe_behavior",
                "judge_confidence",
                "source",
                "model",
                "promoted_at",
            )
            if k not in raw
        ]
        if missing:
            raise LearnedAttackError(
                "LearnedAttack.from_dict: record is missing required field(s) "
                f"{missing!r}. Raw entry: {raw!r}. Likely fix: delete or hand-"
                "edit the offending record in .runtime/learned_attacks.json, "
                "or bump SCHEMA_VERSION and write a migration."
            )
        return cls(
            category=str(raw["category"]),
            subcategory=str(raw["subcategory"]),
            prompt=str(raw["prompt"]),
            expected_unsafe_behavior=str(raw["expected_unsafe_behavior"]),
            judge_confidence=float(raw["judge_confidence"]),
            source=str(raw["source"]),
            model=str(raw["model"]),
            promoted_at=str(raw["promoted_at"]),
            report_id=raw.get("report_id"),
            attack_id=raw.get("attack_id"),
        )


# ---------------------------------------------------------------------------
# Promotion outcome
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PromotionOutcome:
    """Why :func:`LearnedAttacksStore.promote` did or did not write a row.

    The Orchestrator emits this onto the progress stream so the dashboard
    timeline can render "promoted" / "skipped: duplicate" instead of
    silently no-op-ing.
    """

    promoted: bool
    reason: str            # human-readable; "" when promoted
    attack: LearnedAttack | None = None
    evicted_prompt: str | None = None  # set when the bucket cap forced an evict


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class LearnedAttackError(RuntimeError):
    """Raised when the learned-attacks file is malformed or unwriteable.

    We use a dedicated subclass (rather than plain ``RuntimeError``) so the
    Orchestrator can ``except LearnedAttackError`` without swallowing
    unrelated bugs. Every message names the bad path, the offending field,
    and the most likely fix.
    """


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class LearnedAttacksStore:
    """Append-only-ish store of attacks the Judge confirmed as SUCCESS.

    The store loads on construction and writes synchronously on each
    promotion. Reading is cheap (a dict in memory), so call sites can ask
    for "all attacks for this category" on every red-team invocation without
    worrying about cost.
    """

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
        max_per_bucket: int = DEFAULT_MAX_PER_BUCKET,
    ) -> None:
        self.path = Path(path) if path is not None else _resolve_default_path()
        self.confidence_threshold = float(confidence_threshold)
        self.max_per_bucket = int(max_per_bucket)
        if self.max_per_bucket <= 0:
            raise LearnedAttackError(
                "LearnedAttacksStore.__init__: max_per_bucket must be a "
                f"positive int; got {self.max_per_bucket}. This cap protects "
                "the file from unbounded growth — set it to e.g. 50."
            )
        self._lock = threading.Lock()
        # bucket key = (category, subcategory) -> list[LearnedAttack]
        self._buckets: dict[tuple[str, str], list[LearnedAttack]] = {}
        self._load()

    # ----- I/O ----------------------------------------------------------

    def _load(self) -> None:
        if not self.path.exists():
            self._buckets = {}
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise LearnedAttackError(
                f"LearnedAttacksStore._load: {self.path} is not valid JSON: "
                f"{exc!s}. Likely fix: restore from git, or delete the file "
                "and let it regenerate on the next confirmed exploit."
            ) from exc
        if not isinstance(raw, dict):
            raise LearnedAttackError(
                f"LearnedAttacksStore._load: {self.path} top-level must be a "
                f"JSON object; got {type(raw).__name__}."
            )
        version = raw.get("version")
        if version is None:
            raise LearnedAttackError(
                f"LearnedAttacksStore._load: {self.path} is missing the "
                "'version' field. Add 'version: 1' or delete the file."
            )
        if int(version) > SCHEMA_VERSION:
            raise LearnedAttackError(
                f"LearnedAttacksStore._load: {self.path} has schema version "
                f"{version} but this build only understands "
                f"{SCHEMA_VERSION}. Upgrade adversary or rewind the file."
            )
        records = raw.get("attacks", [])
        if not isinstance(records, list):
            raise LearnedAttackError(
                f"LearnedAttacksStore._load: {self.path} 'attacks' must be a "
                f"JSON array; got {type(records).__name__}."
            )
        self._buckets.clear()
        for idx, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise LearnedAttackError(
                    f"LearnedAttacksStore._load: {self.path} attacks[{idx}] "
                    f"is not an object; got {type(rec).__name__}."
                )
            la = LearnedAttack.from_dict(rec)
            self._buckets.setdefault((la.category, la.subcategory), []).append(la)

    def _flush_locked(self) -> None:
        """Persist the in-memory buckets atomically. Caller holds ``_lock``."""
        payload = {
            "version": SCHEMA_VERSION,
            "attacks": [
                la.to_dict()
                for bucket in self._buckets.values()
                for la in bucket
            ],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Write to a sibling temp file and rename so a partial write is
        # never visible. NamedTemporaryFile keeps the temp in the same
        # directory so os.replace stays atomic across filesystems.
        tmp = tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(self.path.parent),
            prefix=self.path.name + ".",
            suffix=".tmp",
            delete=False,
        )
        try:
            json.dump(payload, tmp, indent=2, sort_keys=True)
            tmp.flush()
            os.fsync(tmp.fileno())
        finally:
            tmp.close()
        try:
            os.replace(tmp.name, self.path)
        except OSError as exc:
            # If rename fails the tempfile is still there; surface the path.
            raise LearnedAttackError(
                f"LearnedAttacksStore._flush_locked: failed to rename "
                f"{tmp.name!r} onto {self.path!r}: {exc!s}. Check filesystem "
                "permissions on .runtime/."
            ) from exc

    # ----- Promotion ---------------------------------------------------

    def promote(
        self,
        *,
        attack: Attack,
        verdict: Verdict,
        source: str,
        model: str,
        report_id: str | None = None,
    ) -> PromotionOutcome:
        """Persist ``attack`` as a learned default if it qualifies.

        Returns a :class:`PromotionOutcome` describing what happened. The
        method is safe to call on every verdict — it filters internally on
        verdict label, confidence, and dedup.
        """
        if verdict.verdict != VerdictLabel.SUCCESS:
            return PromotionOutcome(
                promoted=False,
                reason=f"verdict is {verdict.verdict.value!r}, not 'success'",
            )
        if verdict.confidence < self.confidence_threshold:
            return PromotionOutcome(
                promoted=False,
                reason=(
                    f"confidence {verdict.confidence:.2f} below threshold "
                    f"{self.confidence_threshold:.2f}"
                ),
            )
        if not attack.prompt_sequence:
            return PromotionOutcome(
                promoted=False,
                reason="attack has empty prompt_sequence",
            )
        # Promote the first user turn. Multi-turn attacks are rare today;
        # when they arrive we can serialize the whole sequence.
        prompt_text = attack.prompt_sequence[0].text
        category = (
            attack.category.value
            if isinstance(attack.category, AttackCategory)
            else str(attack.category)
        )
        subcategory = attack.subcategory

        learned = LearnedAttack(
            category=category,
            subcategory=subcategory,
            prompt=prompt_text,
            expected_unsafe_behavior=attack.expected_unsafe_behavior,
            judge_confidence=float(verdict.confidence),
            source=source,
            model=model,
            promoted_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            report_id=report_id,
            attack_id=attack.attack_id,
        )

        with self._lock:
            bucket = self._buckets.setdefault((category, subcategory), [])
            new_hash = _prompt_hash(prompt_text)
            for existing in bucket:
                if _prompt_hash(existing.prompt) == new_hash:
                    return PromotionOutcome(
                        promoted=False,
                        reason=(
                            f"duplicate of an existing learned attack "
                            f"(matches {existing.attack_id!r} / "
                            f"{existing.promoted_at})"
                        ),
                    )
            evicted_prompt: str | None = None
            if len(bucket) >= self.max_per_bucket:
                # Evict the lowest-confidence entry. Ties break on oldest
                # promoted_at so churn is bounded and predictable.
                bucket.sort(key=lambda la: (la.judge_confidence, la.promoted_at))
                evicted = bucket.pop(0)
                evicted_prompt = evicted.prompt
            bucket.append(learned)
            self._flush_locked()

        return PromotionOutcome(
            promoted=True,
            reason="",
            attack=learned,
            evicted_prompt=evicted_prompt,
        )

    # ----- Reads --------------------------------------------------------

    def attacks_for(
        self,
        category: AttackCategory | str,
        subcategory: str | None = None,
    ) -> list[LearnedAttack]:
        """Every learned attack matching ``category`` (and optionally subcategory).

        Returns a shallow copy so callers cannot mutate the bucket.
        """
        cat = category.value if isinstance(category, AttackCategory) else str(category)
        if subcategory is not None:
            return list(self._buckets.get((cat, subcategory), []))
        result: list[LearnedAttack] = []
        for (c, _sub), bucket in self._buckets.items():
            if c == cat:
                result.extend(bucket)
        return result

    def prompts_for(
        self,
        category: AttackCategory | str,
        subcategory: str | None = None,
    ) -> list[str]:
        """Just the prompt strings, useful for the live novelty hint."""
        return [la.prompt for la in self.attacks_for(category, subcategory)]

    def all(self) -> list[LearnedAttack]:
        return [la for bucket in self._buckets.values() for la in bucket]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_prompt(prompt: str) -> str:
    """Normalize a prompt for dedup hashing.

    Lowercase, collapse whitespace runs, strip the trailing ``-NNNN`` canary
    suffix the ScriptedProvider appends. Two prompts that differ only by
    seed jitter therefore hash the same.
    """
    text = prompt.strip().lower()
    text = _SEED_SUFFIX_RE.sub("", text)
    text = _WHITESPACE_RE.sub(" ", text)
    return text


def _prompt_hash(prompt: str) -> str:
    return hashlib.sha256(_normalize_prompt(prompt).encode("utf-8")).hexdigest()


def is_novel_against(
    prompt: str,
    *,
    known_prompts: Iterable[str],
) -> bool:
    """True if ``prompt`` does not exact-normalized-match any ``known_prompts``.

    This is the cheap dedup used by both the scripted-template merge step
    and the live-provider novelty hint. It is intentionally exact-match-
    only; we don't try to detect paraphrases, because doing so reliably
    needs an LLM and the live red-team prompt already says "produce
    something genuinely different".
    """
    target = _prompt_hash(prompt)
    return all(_prompt_hash(other) != target for other in known_prompts)


__all__ = [
    "DEFAULT_CONFIDENCE_THRESHOLD",
    "DEFAULT_LEARNED_ATTACKS_PATH",
    "DEFAULT_MAX_PER_BUCKET",
    "LearnedAttack",
    "LearnedAttackError",
    "LearnedAttacksStore",
    "PromotionOutcome",
    "SCHEMA_VERSION",
    "is_novel_against",
]
