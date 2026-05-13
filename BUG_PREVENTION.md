# Bug / issue prevention

Running checklist of past incidents and the rules they spawned. Every new
feature should be reviewed against this list before merge so the same bug
class does not re-appear.

## C — Cost / billing

### C1. Dashboard cost must aggregate every cost-bearing table

**Issue (2026-05-13).** The Total Cost card on `/` showed `$0.0000`
even though the platform had spent real money. Root cause: spend lives in
three different tables — `agent_runs.dollar_cost` (orchestrator
placeholder), `attacks.generation_metadata_json.dollar_cost` (red_team),
and `verdicts.dollar_cost` (judge). `store.summary()` only summed the
first one, which never gets updated past its insert-time zero. The /cost
page already aggregated all three, so the two dashboard surfaces silently
disagreed.

**Prevention.** Every cost-bearing surface goes through
`SqliteStore.cost_breakdown()` (and `campaign_breakdown()` for the
per-campaign header). Do not add a new `SUM(dollar_cost)` SQL fragment to
a route. If you add a new agent that bills, add it to `cost_breakdown`
and add a regression test in `tests/test_storage.py::
test_summary_total_dollar_cost_sums_all_three_tables`.

### C2. Orchestrator must update its agent_runs row at campaign end

**Issue (2026-05-13).** Orchestrator inserts an `agent_runs` row at
`campaign_start` with `dollar_cost=0`, `latency_ms=0`, then never updates
it. Per-campaign cost columns and dashboards reading from that row
showed $0 forever.

**Prevention.** `orchestrator.run_campaign` now calls
`store.update_agent_run_totals` at the end. The helper raises if the
placeholder row is missing — silent no-op would hide the regression.

## T — Audit timeline / observability

### T1. Every audited action needs a narrative renderer

**Issue (2026-05-13).** The `red_team` agent generated 5 attacks per
campaign but wrote zero rows to `audit_log`, so the campaign timeline
jumped from `campaign_start` to the first `target_adapter` response with
no indication that anything had happened in between. Cost and tokens
spent by Red Team were invisible to anyone reading the campaign page.

**Prevention.** When an agent does any LLM-billable work it MUST write
an audit row (`store.append_audit`). Every new `(agent, action)` pair
needs a case in `dashboard.app._narrative_for_audit` or the timeline
falls back to a cryptic `agent.action` form. The orchestrator now writes
`red_team / attack_generated` per attack and `orchestrator /
campaign_done` at the end of the run; both have narrative cases.

## D — Data wiring / dashboard

### D1. Page header values must come from the same source of truth as the corresponding card on `/`

**Issue (2026-05-13).** The campaign detail page (`/campaigns/{id}`)
read its Model / Latency / Cost columns from the orchestrator's
placeholder `agent_runs` row, so `Model="live"`, `Latency=0 ms`, and
`Cost=$0.0000` for every campaign, while the `/` summary card and `/cost`
page used totally different (and inconsistent) queries.

**Prevention.** Per-campaign dashboard fields go through
`SqliteStore.campaign_breakdown(campaign_id)` so the campaign header,
the campaigns table row, and the global summary card all share the same
arithmetic. If you need a new field on the campaign page, add it to
`campaign_breakdown` first, then read it in the template.
