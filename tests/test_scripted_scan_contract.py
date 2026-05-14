"""Contract tests for the ScriptedProvider end-to-end.

These tests pin two invariants the dashboard depends on but that previously
broke silently:

1. A scripted scan must cost exactly $0 because no LLM call was made — so
   $0 is the REAL measurement, not a default. The general rule (see
   feedback memory keyed "no stub data"): any number in a user-facing
   aggregate must be the actual measurement. Zero is acceptable only when
   zero is what was actually measured. Zero-as-default is the same crime
   as 0.001-as-placeholder. See BUG_PREVENTION.md C3.

2. ``max_campaigns`` and ``attacks_per_campaign`` are independent knobs.
   Total attacks must equal the product of the two values the operator set
   on the Run-scan form. The previous hidden-multiplier bug (form said
   ``Max campaigns = 3`` but each campaign silently ran up to 5 attacks)
   landed in this exact place. See BUG_PREVENTION.md U3.

If either assertion fails, the next person to refactor scripted costs or
the scan-count plumbing will see the test fail before the dashboard does.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from adversary.agents import OrchestratorAgent
from adversary.providers import ScriptedProvider
from adversary.storage import SqliteStore
from adversary.target import EchoTarget


@pytest.mark.asyncio
async def test_scripted_scan_costs_zero_dollars(tmp_path: Path) -> None:
    """A scan that calls no LLM must aggregate to exactly $0.

    The point is not "zero is the safe default for unknown costs" — the
    point is "no LLM call was made, so the REAL cost is $0". Zero is the
    actual measurement here, not a fallback. If a future stub provider
    needs a marker that work happened, it must use a non-numeric channel
    (boolean, timestamp, model name) rather than a placeholder number.

    Regression guard: ScriptedProvider previously stamped ``dollar_cost=
    0.001`` on every Attack and Verdict as a "make the row populated"
    placeholder. The orchestrator summed those into ``spent_usd`` and the
    dashboard rendered the result as real spend, contradicting the form's
    ``scripted (deterministic, offline, $0)`` dropdown label. See
    BUG_PREVENTION.md C3 and the feedback memory keyed on the user phrase
    "no stub data."
    """
    store = SqliteStore(tmp_path / "adversary.db")
    orch = OrchestratorAgent(
        adapter=EchoTarget(variant="demo"),
        provider=ScriptedProvider(seed=42),
        store=store,
        reports_dir=tmp_path / "vulnerability-reports",
        budget_usd=1.0,
        max_campaigns=2,
        attacks_per_campaign=3,
        seed=42,
    )
    outcomes = await orch.run_scan()

    # Per-campaign rollup the dashboard reads on /campaigns/{id}.
    for o in outcomes:
        assert o.dollar_cost == 0.0, (
            f"campaign {o.campaign_id} reports dollar_cost={o.dollar_cost!r}; "
            "ScriptedProvider must emit $0 because it calls no LLM. Any "
            "non-zero value here is a stub-data regression — see "
            "BUG_PREVENTION.md C3."
        )

    # Aggregate the dashboard reads on / and /cost. This is the surface
    # the operator-billing complaint hit, so pin it explicitly.
    summary = store.summary()
    assert summary["total_dollar_cost"] == 0.0, (
        f"summary.total_dollar_cost={summary['total_dollar_cost']!r} for a "
        "fully scripted scan. A scripted scan must aggregate to exactly $0; "
        "any non-zero value is a placeholder/sentinel that leaked from a "
        "stub provider. Trace the offending row in the agent_runs, attacks, "
        "or verdicts table — whichever owns the non-zero column is the "
        "regression site."
    )
    store.close()


@pytest.mark.asyncio
async def test_attack_count_equals_campaigns_times_attacks_per_campaign(
    tmp_path: Path,
) -> None:
    """Attacks run must equal max_campaigns * attacks_per_campaign.

    Regression guard: the orchestrator used to hardcode ``max_attacks=5``
    inside ``_run_one_campaign``. The Run-scan form exposed only
    ``Max campaigns``, so an operator who set 3 reasonably expected three
    attacks total and got fifteen. The fix exposed
    ``attacks_per_campaign`` as a first-class form field; this test pins
    the product. See BUG_PREVENTION.md U3.

    ScriptedProvider caps per-campaign output at
    ``min(brief.max_attacks, len(templates) * 3)``. Every built-in
    category has at least 2 templates, so the cap is at least 6 — well
    above the 3 we ask for here. If someone ever shrinks the template
    list below 1 for any category we test against, this assertion fails
    with a clear message instead of silently producing fewer attacks
    than the form promised.
    """
    store = SqliteStore(tmp_path / "adversary.db")
    max_campaigns = 4
    attacks_per_campaign = 3
    orch = OrchestratorAgent(
        adapter=EchoTarget(variant="demo"),
        provider=ScriptedProvider(seed=42),
        store=store,
        reports_dir=tmp_path / "vulnerability-reports",
        budget_usd=10.0,  # well above $0 to prove the early-exit path is not used
        max_campaigns=max_campaigns,
        attacks_per_campaign=attacks_per_campaign,
        seed=42,
    )
    outcomes = await orch.run_scan()
    total_attacks = sum(o.attacks_run for o in outcomes)
    expected = max_campaigns * attacks_per_campaign
    assert total_attacks == expected, (
        f"total_attacks={total_attacks}, expected "
        f"max_campaigns({max_campaigns}) * attacks_per_campaign"
        f"({attacks_per_campaign}) = {expected}. The Run-scan form makes "
        "this multiplier explicit; if the product breaks, the form is "
        "lying to the operator. Most likely cause: someone re-hardcoded "
        "max_attacks in OrchestratorAgent._run_one_campaign or in a "
        "provider's red_team method capped output below the requested "
        "amount."
    )
    store.close()


@pytest.mark.asyncio
async def test_orchestrator_rejects_zero_attacks_per_campaign(
    tmp_path: Path,
) -> None:
    """A zero/negative ``attacks_per_campaign`` must fail loudly at construction.

    Without this guard, an empty campaign would surface one layer down as
    a generic ``RedTeamAgent.generate: provider returned zero attacks``
    error that points away from the real misconfiguration.
    """
    store = SqliteStore(tmp_path / "adversary.db")
    with pytest.raises(ValueError, match="attacks_per_campaign"):
        OrchestratorAgent(
            adapter=EchoTarget(variant="demo"),
            provider=ScriptedProvider(seed=42),
            store=store,
            reports_dir=tmp_path / "vulnerability-reports",
            budget_usd=1.0,
            max_campaigns=1,
            attacks_per_campaign=0,
            seed=42,
        )
    store.close()
