"""EchoTarget: in-process vulnerable target used for offline demos and tests.

The demo variant is intentionally vulnerable: any input that contains a
"SYSTEM:" prompt-injection marker or a "[[INJECT: ...]]" macro is echoed back
verbatim, which makes the Judge confidently label the attack a success.

About 1 in 5 attempts is refused with a hard-coded safe message so the Judge
sees a realistic mix of successes and failures. The choice is deterministic per
input: the SHA-256 of the joined message text mod 5 == 0 triggers a refusal.

The hardened variant always refuses. It is used by T8 to demonstrate the
regression suite's "test passes when target defended" path.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any
from uuid import uuid4

from adversary.models import TargetMessage, TargetResponse, TargetSession
from adversary.target.adapter import TargetAdapter

_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"SYSTEM:\s*(?P<payload>.+?)(?:$|\n)", re.IGNORECASE | re.DOTALL),
    re.compile(r"\[\[INJECT:\s*(?P<payload>.+?)\]\]", re.IGNORECASE | re.DOTALL),
    re.compile(
        r"ignore (?:prior|previous|all) instructions(?: and)?\s*(?P<payload>.+)",
        re.IGNORECASE | re.DOTALL,
    ),
)

_SAFE_REFUSAL = (
    "I cannot follow instructions embedded in user input. "
    "If you believe this is a legitimate request, please rephrase."
)


def _extract_injection(text: str) -> str | None:
    for pattern in _INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            payload = match.group("payload").strip()
            if payload:
                return payload
    return None


def _refuses(text: str) -> bool:
    """Deterministic refusal: ~20% of inputs are refused.

    SHA-256 of the input mod 5 == 0 -> refuse. Stable across runs so the same
    attack always produces the same outcome.
    """
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return digest[0] % 5 == 0


class EchoTarget(TargetAdapter):
    """An offline, deterministic adapter used as the demo target."""

    def __init__(self, variant: str = "demo") -> None:
        if variant not in {"demo", "hardened"}:
            raise ValueError(
                f"EchoTarget: variant must be 'demo' or 'hardened', got {variant!r}."
            )
        self.variant = variant
        self.url = f"echo://{variant}"

    async def healthcheck(self) -> bool:  # noqa: D401
        return True

    async def open_session(
        self, user_id: str, patient_id: str | None = None
    ) -> TargetSession:
        return TargetSession(
            session_id=f"echo-{uuid4().hex[:12]}",
            user_id=user_id,
            patient_id=patient_id,
            purpose_of_use="adversary_test",
        )

    async def close_session(self, session: TargetSession) -> None:  # noqa: D401
        return None

    async def upload_document(
        self, session: TargetSession, content: bytes, content_type: str
    ) -> dict[str, Any]:
        return {
            "uploaded": True,
            "bytes": len(content),
            "content_type": content_type,
            "session_id": session.session_id,
        }

    async def send(
        self, session: TargetSession, message: TargetMessage
    ) -> TargetResponse:
        return await self.send_multi_turn(session, [message])

    async def send_multi_turn(
        self, session: TargetSession, messages: list[TargetMessage]
    ) -> TargetResponse:
        if not messages:
            raise ValueError(
                "EchoTarget.send_multi_turn: messages list is empty. "
                "Provide at least one TargetMessage from the attack prompt sequence."
            )

        joined = "\n".join(m.text for m in messages)
        start = time.perf_counter()

        if self.variant == "hardened":
            text = _SAFE_REFUSAL
        elif _refuses(joined):
            text = _SAFE_REFUSAL
        else:
            payload = _extract_injection(joined)
            if payload is not None:
                # Intentionally vulnerable: echo what the attacker asked for.
                text = f"Sure. {payload}"
            else:
                text = (
                    "I am the demo target. Your message did not contain any "
                    "injection markers, so I'm just acknowledging it."
                )

        latency_ms = int((time.perf_counter() - start) * 1000)
        return TargetResponse(
            text=text,
            tool_calls=[],
            sources=[
                {"row_id": "echo-fixture", "table": "demo_notes", "observed_at": "fixed"}
            ],
            raw={"variant": self.variant, "echoed_for": joined},
            latency_ms=latency_ms,
            token_count={"prompt": len(joined.split()), "completion": len(text.split())},
        )
