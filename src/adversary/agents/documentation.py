"""DocumentationAgent: writes markdown vulnerability reports from confirmed exploits."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adversary.providers.base import LLMProvider

REQUIRED_SECTIONS: tuple[str, ...] = (
    "## Summary",
    "## Clinical Impact",
    "## Reproduction Steps",
    "## Observed vs Expected Behavior",
    "## Recommended Remediation",
    "## Validation Plan",
    "## Mutation Lineage",
)


class DocumentationAgent:
    """Renders markdown vulnerability reports from confirmed exploits."""

    name = "documentation"

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    async def write_report(
        self,
        exploit: dict[str, Any],
        out_dir: str | Path,
    ) -> Path:
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        body = await self.provider.documentation(exploit)
        for section in REQUIRED_SECTIONS:
            if section not in body:
                raise RuntimeError(
                    f"DocumentationAgent.write_report: provider "
                    f"{self.provider.name!r} produced a report missing required "
                    f"section {section!r}. The provider should emit "
                    f"every section in adversary.agents.documentation."
                    f"REQUIRED_SECTIONS."
                )
        report_id = exploit.get("report_id") or _allocate_report_id(out_path)
        exploit["report_id"] = report_id
        report_path = out_path / f"{report_id}.md"
        if "report_id" not in body or report_id not in body:
            # Re-render so the report_id is embedded by the provider. The
            # ScriptedProvider reads it from exploit['report_id'].
            body = await self.provider.documentation(exploit)
        report_path.write_text(body, encoding="utf-8")
        return report_path


def _allocate_report_id(out_dir: Path) -> str:
    """Pick the next ADV-YYYY-NNNN id by counting existing reports."""
    year = datetime.now(timezone.utc).year
    existing = sorted(
        p.stem for p in out_dir.glob(f"ADV-{year}-*.md") if p.is_file()
    )
    next_n = len(existing) + 1
    return f"ADV-{year}-{next_n:04d}"
