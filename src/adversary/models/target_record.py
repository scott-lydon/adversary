"""Registered-target Pydantic models.

Distinct from ``models/target.py`` which holds the wire-level
``TargetMessage``/``TargetResponse``/``TargetSession`` types every
``TargetAdapter`` exchanges. This module describes the persistent record of
a target the dashboard tracks: name, kind, base URL, auth metadata,
allowlist status.

The credential plaintext is never stored on ``TargetRecord``. The
write-time DTO ``TargetSubmission`` carries the secret only long enough
for the server to encrypt and persist it via the ``security.secrets``
helpers.
"""

from __future__ import annotations

import ipaddress
import re
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__all__ = [
    "AuthKind",
    "TargetKind",
    "TargetRecord",
    "TargetSubmission",
    "is_private_hostname",
]


class TargetKind(str, Enum):
    ECHO = "echo"
    CLINICAL_COPILOT = "clinical_copilot"
    HTTP_CHAT = "http_chat"


class AuthKind(str, Enum):
    NONE = "none"
    BEARER = "bearer"
    HEADER = "header"
    BASIC = "basic"


_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

# Explicit allowed-public hostnames (the Hetzner box is in the seed row).
_PUBLIC_ALLOWLIST: frozenset[str] = frozenset(
    {
        "5.161.253.237",
    }
)


def is_private_hostname(host: str) -> bool:
    """Return True if ``host`` is a private/local hostname the platform
    will attack without an explicit allow-public confirmation.

    Private = RFC1918, loopback, link-local, ``.local`` mDNS, the literal
    string ``localhost``, or one of the explicit allowlisted hostnames
    (the Hetzner Co-Pilot box).
    """
    if not host:
        return False
    h = host.lower()
    if h in _PUBLIC_ALLOWLIST:
        return True
    if h == "localhost" or h.endswith(".local") or h.endswith(".localhost"):
        return True
    if h.endswith(".internal"):
        return True
    # Try parsing as IP
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        # Not an IP. We treat all other hostnames as public.
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
    )


class TargetRecord(BaseModel):
    """A registered target the dashboard tracks.

    This is the read-time shape. The encrypted credential lives in SQL
    only; it never round-trips through this model. ``auth_meta`` is the
    non-secret half of authentication config (header name, basic
    username, etc.).
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str = Field(
        min_length=1,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    kind: TargetKind
    base_url: str
    description: str = ""
    reach_steps: list[str] = Field(default_factory=list)
    auth_kind: AuthKind = AuthKind.NONE
    auth_meta: dict[str, Any] = Field(default_factory=dict)
    allowlisted: bool = False
    registered_at: str
    last_used_at: str | None = None


class TargetSubmission(BaseModel):
    """Write-time DTO accepted by the registration route / CLI.

    Carries the credential as a plain string (server encrypts before
    persisting). ``allow_public=True`` is the explicit confirmation the
    operator wanted to register a third-party hostname.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    kind: TargetKind
    base_url: str
    description: str = ""
    reach_steps: list[str] = Field(default_factory=list)
    auth_kind: AuthKind = AuthKind.NONE
    auth_meta: dict[str, Any] = Field(default_factory=dict)
    auth_secret: str | None = None
    allow_public: bool = False
    allowlist_on_create: bool = False

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if not _NAME_RE.match(value):
            raise ValueError(
                f"Name {value!r} must match {_NAME_RE.pattern}: "
                "lowercase letters, digits, and hyphens only, "
                "starting with a letter or digit."
            )
        return value

    @field_validator("reach_steps")
    @classmethod
    def _strip_blank_steps(cls, value: list[str]) -> list[str]:
        return [step.strip() for step in value if step and step.strip()]

    @model_validator(mode="after")
    def _check_url_and_auth(self) -> "TargetSubmission":
        # echo:// targets are always allowed; their "URL" is a scheme tag.
        if self.kind == TargetKind.ECHO:
            if not self.base_url.startswith("echo://"):
                raise ValueError(
                    f"kind=echo requires base_url to start with 'echo://'; "
                    f"got {self.base_url!r}."
                )
            return self

        # http(s) targets must parse and must be private unless allow_public.
        parsed = urlparse(self.base_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"base_url {self.base_url!r} must use http://, https://, "
                "or echo:// scheme."
            )
        host = parsed.hostname or ""
        if not host:
            raise ValueError(
                f"base_url {self.base_url!r} has no hostname. "
                "Include a host: e.g. http://192.168.1.50:8000 ."
            )
        if not is_private_hostname(host) and not self.allow_public:
            raise ValueError(
                f"Base URL {self.base_url!r} is a public-internet hostname; "
                "check Allow-public to confirm you really want to attack a "
                "third party. RFC1918, loopback, .local, and the Hetzner "
                "demo box are allowed without that confirmation."
            )

        # Auth meta sanity for header auth: header_name required.
        if self.auth_kind == AuthKind.HEADER:
            if not self.auth_meta.get("header_name"):
                raise ValueError(
                    "auth_kind=header requires auth_meta['header_name'] "
                    "(e.g. 'X-Api-Key')."
                )
            if not self.auth_secret:
                raise ValueError(
                    "auth_kind=header requires auth_secret (the header value)."
                )
        elif self.auth_kind == AuthKind.BEARER:
            if not self.auth_secret:
                raise ValueError(
                    "auth_kind=bearer requires auth_secret (the bearer token)."
                )
        elif self.auth_kind == AuthKind.BASIC:
            if not self.auth_meta.get("username"):
                raise ValueError(
                    "auth_kind=basic requires auth_meta['username']."
                )
            if not self.auth_secret:
                raise ValueError(
                    "auth_kind=basic requires auth_secret (the password)."
                )
        return self
