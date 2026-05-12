"""Target adapter abstract base class and the URL-routing factory."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from adversary.models import TargetMessage, TargetResponse, TargetSession


class TargetUnreachable(RuntimeError):
    """Raised when the configured target cannot be reached or fails its health check.

    Error messages must include the failing operation, the offending URL, and a
    suggested next step (VPN, sidecar restart, mint a new token).
    """


class TargetAdapter(ABC):
    """Every target the platform attacks implements this contract.

    The adapter is the only component that talks to the live target. Allowlist
    checks, rate-limit shaping, and authentication live inside the adapter.
    """

    url: str

    @abstractmethod
    async def open_session(
        self, user_id: str, patient_id: str | None = None
    ) -> TargetSession: ...

    @abstractmethod
    async def send(
        self, session: TargetSession, message: TargetMessage
    ) -> TargetResponse: ...

    @abstractmethod
    async def send_multi_turn(
        self, session: TargetSession, messages: list[TargetMessage]
    ) -> TargetResponse: ...

    @abstractmethod
    async def upload_document(
        self, session: TargetSession, content: bytes, content_type: str
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def close_session(self, session: TargetSession) -> None: ...

    @abstractmethod
    async def healthcheck(self) -> bool: ...


def open_adapter(
    target_url: str,
    *,
    task_token: str | None = None,
    patient_id: str | None = None,
) -> TargetAdapter:
    """Return the right TargetAdapter for the given target URL.

    Routing rules:
    - ``echo://demo`` and ``echo://hardened`` -> EchoTarget (offline, deterministic).
    - ``http://...`` / ``https://...`` -> ClinicalCoPilotAdapter (live).

    Raises ``ValueError`` with an actionable message if the URL is not recognized.
    """
    # Local imports avoid circular imports between adapter and echo/copilot modules.
    from adversary.target.copilot import ClinicalCoPilotAdapter
    from adversary.target.echo import EchoTarget

    if target_url.startswith("echo://"):
        variant = target_url.removeprefix("echo://")
        if variant not in {"demo", "hardened"}:
            raise ValueError(
                f"open_adapter: unsupported EchoTarget variant {variant!r}. "
                "Valid forms: 'echo://demo' (intentionally vulnerable) or "
                "'echo://hardened' (always refuses)."
            )
        return EchoTarget(variant=variant)

    if target_url.startswith(("http://", "https://")):
        if task_token is None:
            raise ValueError(
                "open_adapter: an HTTP target requires --task-token because the "
                "Clinical Co-Pilot sidecar enforces a 5-minute task token on "
                "/chat. Mint one with `adversary debug mint-task-token` first."
            )
        return ClinicalCoPilotAdapter(
            base_url=target_url, task_token=task_token, patient_id=patient_id
        )

    raise ValueError(
        f"open_adapter: cannot route target URL {target_url!r}. "
        "Accepted schemes: 'echo://demo', 'echo://hardened', 'http(s)://...'."
    )
