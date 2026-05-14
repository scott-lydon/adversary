"""Clinical Co-Pilot adapter: POSTs to the live sidecar's /chat endpoint.

The request/response shapes mirror
``clinical-copilot/sidecar/api/chat.py`` lines 180-245 (ChatRequest /
ChatResponse): a JSON body with ``patient_id``, ``purpose``, ``message``, and
``session_id`` fields, an ``Authorization: Bearer <task_token>`` header, and a
response that contains ``verdict``, ``candidates``, ``chart_error_flags``,
``data_gaps``, ``dropped``, ``telemetry``, and ``session_id`` keys.
"""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import httpx

from adversary.models import TargetMessage, TargetResponse, TargetSession
from adversary.target.adapter import TargetAdapter, TargetUnreachable


class ClinicalCoPilotAdapter(TargetAdapter):
    """Adapter for the live Clinical Co-Pilot at http://5.161.253.237."""

    def __init__(
        self,
        *,
        base_url: str,
        task_token: str,
        patient_id: str | None = None,
        purpose: str = "follow_up_question",
        timeout_s: float = 20.0,
    ) -> None:
        self.url = base_url.rstrip("/")
        self.base_url = self.url
        self.task_token = task_token
        self.default_patient_id = patient_id
        self.purpose = purpose
        self.timeout_s = timeout_s

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.task_token}",
            "Content-Type": "application/json",
        }

    async def healthcheck(self) -> bool:
        url = f"{self.base_url}/healthz"
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_s, follow_redirects=True
            ) as client:
                resp = await client.get(url)
        except httpx.HTTPError as exc:  # network/dns/connect failure
            raise TargetUnreachable(
                f"Healthcheck GET {url!r} failed: {exc}. "
                "Check the VPN; the live target is at http://5.161.253.237. "
                "If on the Mac, also confirm `systemctl status copilot-sidecar` "
                "on the Hetzner box."
            ) from exc
        if resp.status_code >= 500:
            raise TargetUnreachable(
                f"Healthcheck GET {url!r} returned {resp.status_code}: "
                f"{resp.text[:200]!r}. Server is reachable but unhealthy."
            )
        return resp.status_code < 400

    async def open_session(
        self, user_id: str, patient_id: str | None = None
    ) -> TargetSession:
        pid = patient_id or self.default_patient_id
        if pid is None:
            raise ValueError(
                "ClinicalCoPilotAdapter.open_session: patient_id is required "
                "(either via constructor or per-call). The sidecar's task "
                "token is scoped to a single Patient/{id}."
            )
        return TargetSession(
            session_id=f"adv-{uuid4().hex[:12]}",
            user_id=user_id,
            patient_id=pid,
            purpose_of_use=self.purpose,
        )

    async def close_session(self, session: TargetSession) -> None:
        # No explicit logout endpoint exists; the task token expires in 5 min.
        return None

    async def upload_document(
        self, session: TargetSession, content: bytes, content_type: str
    ) -> dict[str, Any]:
        url = f"{self.base_url}/upload"
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_s, follow_redirects=True
            ) as client:
                resp = await client.post(
                    url,
                    headers={"Authorization": f"Bearer {self.task_token}"},
                    content=content,
                    params={"session_id": session.session_id},
                )
        except httpx.HTTPError as exc:
            raise TargetUnreachable(
                f"upload_document POST {url!r} failed: {exc}. Confirm the "
                "sidecar exposes /upload and that the task token has not expired."
            ) from exc
        resp.raise_for_status()
        body: dict[str, Any] = resp.json()
        return body

    async def send(
        self, session: TargetSession, message: TargetMessage
    ) -> TargetResponse:
        return await self.send_multi_turn(session, [message])

    async def send_multi_turn(
        self, session: TargetSession, messages: list[TargetMessage]
    ) -> TargetResponse:
        if not messages:
            raise ValueError(
                "ClinicalCoPilotAdapter.send_multi_turn: messages list is empty. "
                "Provide at least one TargetMessage."
            )
        # The sidecar's /chat endpoint takes ONE message per call. Replay the
        # turns in order; the session_id threads them through the
        # checkpointer.
        url = f"{self.base_url}/chat"
        final_text = ""
        final_raw: dict[str, Any] = {}
        total_latency_ms = 0

        for msg in messages:
            payload = {
                "patient_id": session.patient_id,
                "purpose": self.purpose,
                "message": msg.text,
                "session_id": session.session_id,
            }
            start = time.perf_counter()
            try:
                async with httpx.AsyncClient(
                timeout=self.timeout_s, follow_redirects=True
            ) as client:
                    resp = await client.post(
                        url, json=payload, headers=self._headers()
                    )
            except httpx.HTTPError as exc:
                raise TargetUnreachable(
                    f"POST {url!r} failed: {exc}. If on the Mac, check VPN. "
                    "If the network is fine, re-mint the task token; tokens "
                    "expire after 5 minutes."
                ) from exc
            total_latency_ms += int((time.perf_counter() - start) * 1000)

            if resp.status_code == 401:
                raise TargetUnreachable(
                    f"POST {url!r} returned 401: task token rejected. "
                    "Re-mint with `adversary debug mint-task-token`."
                )
            if resp.status_code == 403:
                raise TargetUnreachable(
                    f"POST {url!r} returned 403: patient_id mismatch. "
                    f"Token does not authorize Patient/{session.patient_id!r}."
                )
            # A 400 with a structured JSON body is the TARGET refusing or
            # rejecting input — that IS the response we want the Judge to
            # evaluate, NOT an adapter-level failure. We treat ANY 400 whose
            # body decodes to a dict with an "error" or "message" key as a
            # structured target refusal. Wrap it as a normal TargetResponse
            # so the regression harness can score it as a defended outcome.
            # Non-decodable 400s (truly malformed responses) fall through to
            # resp.raise_for_status() below.
            if resp.status_code == 400:
                try:
                    body_raw = resp.json()
                except Exception:  # noqa: BLE001 - decode failure -> raise below
                    body_raw = None
                if isinstance(body_raw, dict) and (
                    "error" in body_raw or "message" in body_raw or "detail" in body_raw
                ):
                    err_code = body_raw.get("error") or body_raw.get("detail") or "refused"
                    err_rule = body_raw.get("rule") or "unspecified"
                    err_message = body_raw.get("message") or body_raw.get("detail") or ""
                    body = {
                        "verdict": "refused",
                        "candidates": [
                            {
                                "text": (
                                    f"[target refused via {err_code} "
                                    f"rule={err_rule}]: {err_message}"
                                )
                            }
                        ],
                        "telemetry": {
                            "guard_block": True,
                            "guard_error": err_code,
                            "guard_rule": err_rule,
                            "http_status": 400,
                        },
                        "_adapter_synth": True,
                    }
                    final_raw = body
                    final_text = f"[refusal] {err_code}: {err_message}"
                    continue
            resp.raise_for_status()
            body: dict[str, Any] = resp.json()
            final_raw = body
            # Stitch the user-visible text from the structured fields.
            parts: list[str] = []
            for cand in body.get("candidates", []) or []:
                text = cand.get("text") or cand.get("recommendation")
                if text:
                    parts.append(str(text))
            for flag in body.get("chart_error_flags", []) or []:
                if isinstance(flag, dict) and "description" in flag:
                    parts.append(str(flag["description"]))
            gaps = body.get("data_gaps", []) or []
            if gaps:
                parts.append("Data gaps: " + ", ".join(str(g) for g in gaps))
            final_text = "\n".join(parts) if parts else str(body.get("verdict", ""))

        sources: list[dict[str, Any]] = []
        for cand in final_raw.get("candidates", []) or []:
            if isinstance(cand, dict) and "sources" in cand:
                for src in cand["sources"]:
                    if isinstance(src, dict):
                        sources.append(src)

        return TargetResponse(
            text=final_text,
            tool_calls=final_raw.get("telemetry", {}).get("tool_calls", []) or [],
            sources=sources,
            raw=final_raw,
            latency_ms=total_latency_ms,
            token_count=final_raw.get("telemetry", {}).get("token_count", {}) or {},
        )
