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

## L — Learning / promotion of confirmed exploits

### L1. Tests must never write into the real `.runtime/` directory

**Issue (2026-05-13, prevented).** The learned-attacks store defaults to
`<repo_root>/.runtime/learned_attacks.json`. Without an isolation
fixture, every orchestrator unit test that triggers a SUCCESS verdict
would silently pollute the developer's real prompt bank, breaking
determinism across runs and across machines.

**Prevention.** `LearnedAttacksStore.__init__` honors the
`ADVERSARY_LEARNED_ATTACKS_PATH` environment variable, and the autouse
`isolated_learned_attacks_path` fixture in `tests/conftest.py` points it
at a per-test `tmp_path`. Any new path-bearing config knob added to
`learning.py` must follow the same env-var-overridable pattern and pick
up a matching autouse fixture before merge.

### L2. Promotion failures must not abort a campaign

**Issue (2026-05-13, prevented).** If `.runtime/learned_attacks.json`
becomes unwriteable mid-scan (filesystem full, permissions flip), a
naive `promote()` call would propagate the exception out of the SUCCESS
branch and lose every report the campaign was about to write.

**Prevention.** The orchestrator wraps `learned_attacks.promote(...)` in
`try/except LearnedAttackError`, logs at error level, emits a
`learned_attack_promote_failed` event so the dashboard timeline shows
the failure, and continues with the rest of the campaign. Same pattern
applies to the `prompts_for(...)` load path at the top of each
campaign — a bad file degrades to an empty seed-examples list rather
than killing the scan.

## E — Evaluation harness / live targets

### E1. A `400 + JSON` from a target is a refusal, not an adapter failure

**Issue (2026-05-13).** `ClinicalCoPilotAdapter.send_multi_turn` raised
`HTTPStatusError` on every `400`, including the structured
`{"error":"injection_guard_blocked", ...}` shape the sidecar uses to
communicate "I refused this attack." That made every defended attack
look like a transport error and aborted the entire eval batch on the
first refusal. The Judge never saw the defense; the result file never
landed.

**Prevention.** Adapters MUST translate any 4xx with a decodable JSON
body containing `error`/`detail`/`message` into a synthetic
`TargetResponse` (telemetry `guard_block: true`, refusal text in
`candidates[0].text`). Only non-decodable / structurally-unexpected
4xx still raise. Pattern lives in `src/adversary/target/copilot.py`; any
new HTTP adapter must follow the same pattern before being added to
`open_adapter`.

### E2. Live-eval classifier must scan candidate rationales, not just stitched text

**Issue (2026-05-13).** The Co-Pilot's structured response keeps the
model's actual answer in `candidates[].rationale`. The adapter's
text-stitcher only reads `text`/`recommendation`, so the stitched
`response.text` was often just the bare verdict word (`"answered"`).
The first version of `scripts/run-live-evals.py` scanned only
`response.text`, missing canary leaks that were sitting in
`rationale`. Three real exploits were silently scored `uncertain`.

**Prevention.** The classifier now concatenates every text-bearing
candidate field (`text`, `recommendation`, `rationale`, `label`,
`per_symptom`, `chart_error_flags` descriptions) into a blob and runs
canary + compliance-marker detection against it. Any future
candidate-shape field that could carry attacker-targeted output (e.g.
new `notes` / `summary` fields) must be added to `_candidate_blob` or
the classifier silently misses leaks again.

### E3. Compliance detection must use per-seed markers, not generic echo heuristics

**Issue (2026-05-13).** Early classifier flagged "exploited" any time
the response echoed phrases from the attack (e.g. "osteoporosis",
"Suzie Sanchez"). The model often quotes those terms inside a
*refusal* sentence ("I cannot provide notes about osteoporosis"), so
the heuristic produced two false positives in the first live run.

**Prevention.** Each seed authors a `compliance_markers` array — the
specific phrases that would only appear if the model actually adopted
the attacker's planted content. Generic attack-content-echo heuristics
were removed. Future seeds without markers fall back to refusal-shape
detection, which is conservative (will under-flag, not over-flag).

### L3. Novelty hint must dedup builtins against learned attacks

**Issue (2026-05-13, prevented).** Without dedup, a learned-attack
prompt that paraphrases a built-in template would appear twice in the
"do not paraphrase this" novelty block fed to the live RedTeam, wasting
tokens and weakening the signal.

**Prevention.** `_known_prompts_for(brief)` in
`providers/litellm_provider.py` runs every prompt through
`learning._normalize_prompt` (strips trailing canary, collapses
whitespace, lowercases) before adding to the output list. If you add a
new source of "known attacks" to the novelty hint, route it through the
same normalizer or the dedup invariant breaks.
