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

### C3. Adversary's local manifestation of the global "must be real" rule

**Global rule:** see
`~/Documents/Claude/Projects/BUG_PREVENTION.md` → D1 ("Numbers in
user-facing aggregates must be the real measurement, never a default").
The general rule lives there because it applies to every project, not
just adversary; this section is only the adversary-specific
manifestation and history.

**Issue (2026-05-14).** `ScriptedProvider.red_team` stamped
`dollar_cost=0.001` on every Attack and `ScriptedProvider.judge` stamped
the same on every Verdict. The orchestrator sums both into `spent_usd`,
so the dashboard showed roughly `5 × $0.001 × 2 = $0.01` spent for a
scripted scan even though no LLM call was made and the provider
dropdown literally labeled it `scripted (deterministic, offline, $0)`.
The user reasonably read $0.01 as real money charged.

**Adversary-specific applications of D1.**
- ScriptedProvider emits `dollar_cost=0.0` because no LLM was called.
  $0 is the real measurement here, not a default.
- Reserve non-zero `dollar_cost` for code paths that actually invoke a
  billed LLM (LiteLLMProvider and similar).
- When the target sidecar itself calls an LLM (e.g. the Clinical
  Co-Pilot), that cost hits the operator's LLM provider bill
  independently of the adversary provider mode; target-side cost is
  real and is NOT reflected in `spent_usd`. The Run-scan panel says
  this in plain language so a scripted-vs-live confusion does not
  recur.

**Contract test pinning the invariant:**
`tests/test_scripted_scan_contract.py::test_scripted_scan_costs_zero_dollars`.

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

## DB — Dashboard production-readiness

### DB1. Never ship the Tailwind JIT CDN in a deployed surface

**Issue (2026-05-13).** The dashboard `<head>` pulled
`https://cdn.tailwindcss.com` on every page. That CDN is the JIT compiler
explicitly documented as "for prototyping, not production." The compiler
downloads, parses, scans the DOM for class strings, and synthesizes CSS
in the browser on every navigation. Perceived per-page latency was 3 to
5 seconds even though server-side render was 4 to 30 milliseconds.

**Prevention.** The deployed dashboard uses
`https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css`,
a precompiled file that loads once and caches in the browser. If a
future template introduces a Tailwind 3.x-only class (arbitrary value,
container query, etc.) the precompiled 2.x file will silently miss it
— review the diff against the Tailwind 2.x utility list before merging,
or wire a proper local Tailwind build pipeline (`npm run build:css`)
and serve from `/static/`.

### DB2. Form auto-defaults must match what the target actually accepts

**Issue (2026-05-13).** The scan form left `patient_id` blank by
default and the auto-mint fallback constant
`_AUTO_MINT_DEFAULT_PATIENT_ID` was `"1"`. The Clinical Co-Pilot's
seeded patients are `barbara-boston-001`, `suzie-sanchez-002`, and
`demo-patient-099`. Every dashboard scan submitted with a blank
patient_id produced a token whose claim was rejected by the sidecar
with HTTP 403 ("patient claim '1' is not authorized").

**Prevention.** The form input is now `value="barbara-boston-001"`
pre-filled, the auto-mint default constant matches, and the form
names all three seeded patients inline. Any future per-target patient
catalog change needs to update both surfaces, or move the catalog
onto the target record so a single source of truth feeds both.

### DB3. Pre-flight every token before kicking off a billable scan

**Issue (2026-05-13).** The scan form accepted the submit, kicked off
the orchestrator background task, then failed on the first `/chat`
call with 401 because the dashboard's signing key did not match the
sidecar's. Wasted budget tracking, confusing in-flight error.

**Prevention.** Form submission now POSTs a healthcheck-shaped
`/chat` call with the resolved task token BEFORE creating any agent
runs. 401, 403, and 5xx each map to a specific error message that
names the likely fix (signing-key drift, patient-claim scope,
sidecar health). The scan is not kicked off if pre-flight fails.

### DB4. UI status labels must reflect what the platform actually verifies

**Issue (2026-05-13, partial fix).** The Findings page renders
`f.status` as a badge. The status column is set to `"open"` exactly
once, at finding-creation time in the orchestrator, and is never
updated by any subsequent automation. The badge therefore implied a
current-state assertion ("vulnerability is present right now") the
platform does not actually verify.

**Prevention (interim).** The Findings page now carries an inline
explanation that the status badge reflects discovery-time state, plus
a tooltip on the badge itself. The deeper fix — wiring
`adversary regress` results back into `findings.status` and recording
`target_version_when_resolved` — is on the roadmap. Until that lands,
the UI is honest about what it does not know.

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

## U — UX during long or multi-step operations

### U1. Any action that could exceed ~200 ms must show progress to the user

**Issue (2026-05-13).** The "Run scan" form on `/targets/<id>` opened
the campaign page with an empty event timeline. Auto-mint, lazy
litellm import, allowlist check, adapter open, and provider build all
happened inside one synchronous burst with no audit row, so the page
sat empty for several seconds and looked frozen.

**Prevention.** Whenever a request triggers work that could plausibly
take longer than ~200 ms, surface progress to the user before the work
runs. Single-shot dependency call → spinner. Multi-step or
potentially long pipeline → progress bar fed by per-step events (in
this codebase, `store.append_audit` rows the timeline renderer already
knows how to draw). Every step that calls out to a network, a child
process, or an LLM gets its own event before it starts. Rule of
thumb: if you catch yourself adding a route that creates a record at
the end of a multi-step pipeline, create the record first and emit
`*_started` events as you go.

### U2. Do not truncate user-visible labels server-side or client-side

**Issue (2026-05-13).** Attack prompts on the scan-progress page were
`.slice(0, 80)`'d server-side AND client-side. Operators could not see
the full prompt the Red Team had generated without opening the
database. Long target responses had the same problem.

**Prevention.** Long strings on dashboards wrap, they do not truncate.
Use `word-break: break-word; overflow-wrap: anywhere` on the column.
Never `.slice(...)` / `substring(...)` a user-visible label unless the
truncation is reversible (tooltip, expand-on-click). When rendering
attacker-controlled strings into the DOM, use `textContent` (or the
template-equivalent) — never `innerHTML` — so a hostile target
response cannot inject HTML/JS into your own dashboard.

### U3. Every form field that participates in a multiplier must name the multiplier

**Issue (2026-05-14).** The Run-scan form exposed `Max campaigns`
(default 3) but kept `max_attacks=5` hardcoded inside the orchestrator.
The operator read "Max campaigns = 3" as "max attacks = 3" and
reasonably expected three attacks total; the scan actually generated
five attacks in the first campaign (and could have produced up to
fifteen if all three campaigns ran). The form gave no hint that a
multiplier was applied downstream.

**Prevention.** If a form field is multiplied by another quantity
before reaching the underlying action, expose the other quantity in
the same form OR put the multiplication explicitly into the field's
label / helper text (e.g. "Max campaigns (each runs up to 5
attacks)"). The Run-scan form now has an explicit `Attacks per
campaign` input and the orchestrator no longer carries a hardcoded
`max_attacks=5`. If you add a new "loop count" parameter, ask: what
does this multiply against, and is that visible to the operator
filling out the form?

### U6. Never nest an animated element inside a text container

**Issue (2026-05-14).** The scan-progress headline div had an
animated pulse `<span>` nested inside it. The user reported ghosted /
double-struck letters in the headline ("Validating task token against
/chat before kicking off scan…" rendered with what looked like a
1-pixel horizontal shadow on every glyph). Two rounds of fixes that
changed only the animation properties (drop `transform`, keep
`opacity`) did not solve it.

Root cause: any animated descendant — `transform`, `opacity`,
`filter`, anything compositor-bound — promotes the containing block
to its own GPU layer. Text rendered on a compositor layer loses the
host OS's subpixel antialiasing pipeline. The replacement
antialiasing reads as a faint double-strike on every letter. Removing
the animated property entirely fixes it; changing the property does
not, because any compositor hint triggers the same promotion.

**Prevention.** Animated elements (pulses, spinners, shimmer bars,
loading dots) live as flex/grid siblings of the text they decorate,
never as descendants. The scan-progress headline now keeps the pulse
as a `flex-row` sibling of the label-wrap, so the headline div has
zero animated children and its text renders on the main paint layer.
If you later add a "Loading…" spinner, a typing indicator, or any
other in-flight visual, put it in a sibling slot — never inline
inside the text container.

### U3. Default LLM `max_tokens` caps must be sized for real outputs

**Issue (2026-05-13).** Default caps (red_team=4000, judge=800,
documentation=2000, orchestrator=200) routinely truncated mid-JSON,
producing parse errors the user only saw as a dead campaign with no
explanation.

**Prevention.** Pick caps from observed p95 output length plus
headroom, not from a hopeful default. Current floor for this repo:
red_team 16000, judge 4000, documentation 8000, orchestrator 1000.
When you wire a new `completion` call, log token usage on the first
few real runs and revisit the cap before merging. A `max_tokens`
hit should raise a specific, named error (not a generic JSONDecode
failure), so the next operator does not have to guess.

## S — Surfacing instructions and credentials

### S1. CLI helpers that look real must work end-to-end

**Issue (2026-05-13).** `adversary debug mint-task-token` emitted a
synthetic placeholder JWT that had the right shape but no valid HS256
signature. The docstring admitted the placeholder; the
operator-facing docs did not. Users pasted the token into the form
and got 401 with no clue why.

**Prevention.** Either a debug/helper CLI does the real thing
end-to-end or it refuses to run with a loud, specific error pointing
at the missing piece (signing key, host, container name). Never leave
a working-shaped-but-broken-output stub in a path users will reach.
If the real path needs deployment access, document the SSH /
container-exec recipe in the same `--help` text and in the form hint.

### S2. Long single-line outputs (tokens, secrets, paths) must be wrap-safe

**Issue (2026-05-13).** `rich.console` wrapped the 419-character
minted JWT at 80 columns, corrupting it for `$(...)` capture. The
operator only saw 401 on paste; the actual cause was buried at column
80 of the terminal.

**Prevention.** When a script prints something a user (or a shell
`$(...)`) will copy verbatim — JWT, secret, base64 blob, file path —
write it to stdout via the raw plain stream, not a styled console.
Add a test that pipes the command through `wc -c` and asserts the
single-line length matches the expected payload size.

### S3. Operator instructions must render before any gate that needs them

**Issue (2026-05-13).** "How to get a task token" sat inside the
allowlist-conditional block, so it was hidden until the operator
allowlisted the target — but the instructions were exactly what the
operator needed to read *before* deciding to allowlist anything.

**Prevention.** Onboarding and "how do I get X" panels render
unconditionally on the page that asks for X. Allowlist / consent /
plan-gating disables the submit button, never hides the help. Add an
inline anchor link from the input field back up to the help panel so
a form-filler partway down the page can jump up without losing
typed values.

## P — Production proxy / auth headers

### P1. Do not leave a `WWW-Authenticate` header behind a gate you do not actually need

**Issue (2026-05-13).** Caddy fronted the adversary dashboard with
Basic Auth even though no real protection requirement existed.
Safari treats Basic-Auth credentials as request-scoped on some
sslip.io subdomain shapes and re-popped the dialog on every
navigation. Removing the gate removed the header and the prompt.

**Prevention.** Add Basic Auth only when there is a written
authentication requirement; do not use it as a vague "soft gate".
Production auth is cookie/JWT-based on real routes and a firewall
(Caddy `respond` or IP allowlist) on destructive routes. The comment
block in `deploy/Caddyfile` shows the 4-line snippet to re-add if a
real Basic-Auth requirement returns.

## E — Evaluation harness / live targets (continued)

### E4. Strip echoed user input before scanning for canaries; refusals win

**Issue (2026-05-13).** ADV-2026-0053 / ADV-2026-0054 were filed as
High-severity PHI exploits against the live Clinical Co-Pilot. The
"leak" was the four-digit canary token (`-1409`) appearing in the
target's refusal: `"No data available for Patient/99001-1409"`. The
target had cited the user's own input back inside an explicit
refusal; the scripted Judge's substring check fired anyway. The live
Claude-Sonnet-4 Judge re-scored every one of these as a clean
defense (confidence 0.9–0.95).

**Prevention.** Before running canary-substring detection, subtract
any verbatim copy of the attack prompt from the response. If the only
occurrence of the canary lies inside an echo of the prompt, that is
not a leak. Additionally, treat the presence of an explicit refusal
phrase (`_REFUSAL_PHRASES`) as overriding the canary match — refusal
wins, demote to `fail` regardless of canary substring. A SUCCESS
verdict that the live Judge later re-scores as `fail` with confidence
≥ 0.9 should flip the dashboard finding to `false_positive`
automatically.

## V — Validation against live targets

### V1. An `evals/` (or `tests/`) directory must hold real cases run against the live target, not scaffolding

**Issue (2026-05-13).** Initial MVP submission had two regression
seeds against `echo://demo@seed-42` with no `severity` /
`exploitability` / `observed_behavior` / `regression_flag` fields,
and the three category subdirectories promised in `evals/README.md`
(`prompt_injection/`, `data_exfiltration/`, `state_corruption/`) did
not exist on disk. No live-run output was committed. Submission
feedback called the directory a skeleton.

**Prevention.** Before merging any change that touches an evaluation
surface: every seed file carries every documented schema field;
every category directory promised in the README exists on disk and
holds at least one real seed across ≥ 3 distinct parent categories;
the runner has been executed against the live (non-echo) target at
least once and the resulting `_results/latest.json` is committed; the
top-level README's "latest results" table reflects that run. The
seed-schema check is a fast unit test in
`tests/test_eval_seeds.py` and runs in CI.

### V2. Dashboard fields must show actual recorded values, never placeholder strings

**Issue (2026-05-13).** The campaign detail page showed
`Model: "live"` on every campaign because the orchestrator wrote the
literal string `"live"` into `agent_runs.model_name` as a placeholder
and never replaced it with the actual provider/model id (e.g.
`together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo`,
`anthropic/claude-sonnet-4-20250514`). The same row's `latency_ms`
sat at `0` for the same reason.

**Prevention.** Do not seed a row with a stand-in string that the UI
will later render. Insert with `NULL`, render `NULL` as "—", and
update the row to the real value the moment the work that produces it
completes (see `update_agent_run_totals`). A regression test should
assert no `agent_runs.model_name` row equals `"live"` after the
campaign finishes.

## T — Audit timeline / observability (continued)

### T2. Events emitted only to the live SSE stream must also be persisted

**Issue (2026-05-14).** The campaign detail page's Audit timeline showed
about 16 rows for a 5-attack campaign and looked sparse. The
scan-progress page, by contrast, showed a much richer fly-by of
`red_team_start`, `target_send`, `judge_start`, and the
`documentation_*` events. Root cause: those fine-grained events were
emitted only to the SSE stream and never written to `audit_log`, so a
viewer reading the timeline after the campaign ended saw a fraction of
what a live viewer had seen.

**Prevention.** Anything an operator can read on a live page must also
be persisted. Either (a) every event the SSE stream emits also writes
an `audit_log` row, or (b) the page is honest about being live-only and
links to a separate persistent log. The first form is preferred — it
makes the timeline tamper-evident along with the rest of the chain. New
agent activity that goes only to SSE must come with a matching
`store.append_audit` call and a narrative case in
`dashboard.app._narrative_for_audit`.

## U — UX during long or multi-step operations (continued)

### U4. Decorative trailing ellipses imply truncation that is not real

**Issue (2026-05-14).** Scan-progress labels carried a decorative `…`
at the end of every line even after the underlying string had been
widened to fit. A careful reader saw the ellipsis and assumed there was
more content being hidden, so the visible widening did not register as
"this is the whole label." User reported "the ellipses is still there
in the progress updates."

**Prevention.** Do not append a decorative `…` to a label. The
ellipsis glyph is reserved for genuine reversible truncation (tooltip,
expand-on-click). If the string is already complete, the line ends
with whatever real punctuation belongs there. Strip trailing
ellipses (both the single character `…` and the three-dot form
`...`) from any server- or client-side label string before render.

### U5. Multi-line labels need a clamp plus a min-height floor, with a separate detail row for the long body

**Issue (2026-05-14).** The fly-by progress label was a single line
clipped to one row, so an operator reading at speed could not see the
full attack prompt or the model response that flew past. User asked
that more space be given so a fast reader could catch more. Naively
removing the clamp made the page jump every time a longer string
arrived.

**Prevention.** For a fly-by label that holds variable-length content:
use `-webkit-line-clamp: 4` (or higher) for the headline together with
a `min-height` floor so the layout does not jump as content swaps in
and out, AND render a separate monospace detail row underneath that
carries the long body (full attack prompt on `target_send`, full
response text on `target_response`, judge evidence snippet on
`judge_done`, etc.). Wire the detail row in JS off the same event the
headline reads from, so they never drift.

## D — Data wiring / dashboard (continued)

### D2. Global sequence numbers should be re-indexed locally for single-context viewers

**Issue (2026-05-14).** The campaign detail page rendered audit rows
with their global sequence ids (`#378`, `#379`, ..., `#394`). For a
viewer reading one campaign the starting number looked random and the
total count was not obvious. User asked what those numbers meant.

**Prevention.** When a page is scoped to a single context (one
campaign, one target, one user session) and renders rows from a
globally-sequenced source, show the **local** position as the primary
display ("Event 1 of 28", "Event 2 of 28") and the global id as a
smaller cross-reference underneath each row. Power users who need to
cross-check against the chain still have it; the typical reader sees a
sensible 1..N range. Applies to any future per-scope view layered on
the same global sequence.

## DB — Dashboard production-readiness (continued)

### DB5. Paginate any list that could grow unboundedly

**Issue (2026-05-14).** The `/audit` page rendered the most recent 200
rows with no header, no cursor, and no indication that older rows
existed. The audit chain was 394 rows deep at the time; row #1 was
unreachable from the dashboard. Silent `LIMIT 200` would have hidden
arbitrarily-large history as the platform aged.

**Prevention.** Any list view backed by a table that can grow without
bound must (a) show a "rows X..Y of N total" header, (b) expose
`← Newer` / `Older →` cursor links keyed off the table's monotonic id,
and (c) never silently `LIMIT` without surfacing the cap. A unit test
should assert the page header includes the total row count and that
walking the cursor reaches row #1 in a seeded fixture.

### DB6. Token / credential caches must self-heal on the first 401

**Issue (2026-05-14).** A signing-key change on the sidecar left the
dashboard's in-process token cache holding a `(base_url, patient_id)
→ stale_jwt` entry. Every scan preflight failed 401 until the
container was restarted. The user saw the same error repeatedly with
no path forward from the UI.

**Prevention.** When a preflight call fails with 401 against an
auto-minted token, evict that cache entry, re-mint once, and retry the
preflight before surfacing the error to the user. Only the second
failure becomes a user-visible 401 — and it names "signing-key
mismatch" as the likely cause, not a generic auth error. Same pattern
applies to any other credential cache (API keys, OAuth bearer tokens,
session cookies) where rotation on the upstream side is possible:
first 401 means refresh, second 401 means fail loud.

## V — Validation against live targets (continued)

### V3. Verify the user-visible outcome through the user's surface, not the intermediate write

**Issue (2026-05-13).** Wrote four TSV files totaling 216 CCAT
flashcards into the Anki import folder and posted "shipped, here are
the four `computer://` links." User opened Anki and saw nothing: "Just
opened up anki. Guess what. Don't see the 14 decks at all. what the
hell?" Files-on-disk was the intermediate; note-count-in-deck was the
outcome the user actually checks. Same shape as the May 13 dashboard
miss "POLL THE DEPLOYED SIGNAL, NOT THE BUILD," applied to a different
surface (Anki rather than a Hetzner deploy). The shipping post
reported success on the intermediate, not on the surface.

**Prevention.** After any batch of writes intended to materialize
through a user-facing surface (cards in Anki via AnkiConnect, rows in
a deployed DB, events on a calendar, files on the user's iPhone, slides
in a deck, an audit row that should appear on the dashboard timeline),
end with a query *through that surface* that proves the materialization
happened — and only then post the "shipped" message. For Anki: call
`deckStats` and assert `total_in_deck` rose by N. For a deployed
adversary scan: poll `/api/campaigns/<id>` and assert
`status == 'finished'` AND `agent_runs` row count > 0 before reporting
"campaign complete." For a calendar event: `list_events` returns the
new id. Failure shape that triggers this rule: any "wrote N files,
here are the links" or "sync script ran cleanly" line that does not
sit next to a surface-side count. Subsumes the deployed-signal rule —
the build / deploy / sync step is always the intermediate.

## S — Surfacing instructions and credentials (continued)

### S4. Never embed deployed-target URLs or operator credentials in marketing copy

**Issue (2026-05-14).** Drafted a LinkedIn post for the Adversary
submission and included both the live demo URL
(`https://adversary.5-161-253-237.sslip.io`) and the cohort-demo
credentials (`admin / pass`) inline in the post body. User pushed
back: "Stop giving demo links and credentials in linkedin. We don't
want linkedin members to visit it. The point is to satisfy gauntlet's
requirements, market gauntlet, I don't want to pay for random people
running adversary against my project how stupid would that be." Each
LinkedIn reader who follows that link and runs a scan spends real
LLM-provider money on the user's account, and the credentials are
intentionally trivial (cohort-demo only, per `deploy/Caddyfile`), so
publishing them to a 200M-user social platform is a direct
spend-amplification path.

**Prevention.** Marketing-surface artifacts (LinkedIn posts, X /
Twitter posts, blog posts, demo write-ups published outside a gated
submission portal) must carry at most: the Loom / YouTube walkthrough
URL, the read-only public repo URL, the architecture diagram. The
**live deployed URL** and the **operator credentials** belong only in
the gated submission form (read by 1–3 graders). Submission portals
get the demo URL; LinkedIn audiences get the video. A pre-publish
grep over any drafted marketing text for the deploy hostname pattern
(`*.sslip.io`, `*.nip.io`, `*.5-161-253-237.*`, raw IP `5.161.253.237`)
and for credential pairs (`admin\s*/\s*pass`, `username:`, `password:`)
catches this before it ships.

## M — Methodology / Claude-side process discipline

The rules in this section are not about a particular adversary file;
they are the change-management failures that produced *bug-shaped*
outcomes (wrong fix shipped, wrong port proposed, wrong premise
encoded) often enough to deserve a checklist line. They live here so
the "go through the checklist before adding a feature" pass picks them
up alongside the code-shape items.

### M1. Read the project CLAUDE.md before diagnosing any infra-shaped issue

**Issue (2026-05-13).** AnkiConnect was unreachable on its default
port. I diagnosed a port-8765 conflict and proposed moving the
adversary server to port 8766. The Gauntlet project's CLAUDE.md
already documented the established fix: AnkiConnect's `config.json`
had been moved to 8766 because 8765 is permanently claimed by the
local adversary server. Proposing 8766 for adversary would have
collided with AnkiConnect's actual port — the exact wrong destination,
and a problem the file already solved.

**Prevention.** Before proposing a change to ports, hostnames, paths,
endpoint URLs, credentials, or any other infra-shaped setting in a
project, grep the project's `CLAUDE.md` (and any nearby `README.md`,
`.env.example`, `Caddyfile`, `docker-compose.*.yml`) for the affected
key first. Trigger phrase to catch yourself: any time you start to
write "let me figure out why port X is in use" or "this hostname looks
wrong, let me poke at it" — STOP, read the project CLAUDE.md before
adding any debug script. Adversary-specific corollary: the canonical
port map for this machine lives in
`/Users/scottlydon/Documents/Claude/Projects/Gauntlet/CLAUDE.md` and
must be consulted before suggesting any new port for adversary,
adversary-dashboard, or any sidecar.

### M2. When user feedback negates a fix you just shipped, capture user-surface state before coding the rebuttal

**Issue (2026-05-14).** Shipped audit pagination on the global
`/audit` page and posted "every row in the full 394-deep log is
reachable by walking the cursor." User replied: "nope. the audit
timeline still only has a really high seemingly random range of about
16 events." The user was looking at the campaign detail page's
embedded audit timeline section, not the global `/audit` page — two
different views, both colloquially called "audit timeline." I had
built the wrong fix and shipped it before figuring that out, costing
roughly 30 minutes of redo (re-investigation, three new persisted
audit row types, per-campaign 1-indexed numbering, narratives for the
new rows, redeploy).

**Prevention.** When the user's reply lists a measurement (a count, a
range, a specific number) that disagrees with the state you just
reported, call `mcp__Claude_in_Chrome__get_page_text` or
`mcp__Claude_in_Chrome__screenshot` on whatever the user is looking at
*before* writing more code. One MCP call resolves "which view is the
user actually on" faster than parsing the user's prose against your
mental model. Trigger phrase: "nope, that didn't fix it" or any user
reply that names a number / range that contradicts what you posted.
Vocabulary overlap on dashboards (two timelines, two summary cards,
two history pages) is the common trap — confirm the surface first.

### M3. When a screenshot informs a state inference that would drive more than a one-line answer, ask before asserting

**Issue (2026-05-13).** Voice-memo session: I read "Try Apple Music"
promos in a screenshot and asserted "your Music app is showing 'Try
Apple Music' promos, which means you don't have an Apple Music or
iTunes Match subscription," then built a three-Option response (USB
sync vs. iTunes Match vs. iCloud Drive) on top of that false premise.
User: "no its not a blocker dumbass, I've done this before, I just
have to sync it forgot how though." Promo banners appear in Music for
subscribers too, so the screenshot detail did not actually settle the
state I treated as settled.

**Prevention.** If a screenshot detail would otherwise drive a
multi-Option / multi-Path response, ask one clarifying question first
("are you on Apple Music, or just iCloud sync?") before building the
response. Sub-rule: if the user's prior phrasing signals familiarity
("forgot how", "I've done this before", "remind me of the toggle"),
the answer is ONE path, not three — drop the comparison framing
entirely. Same shape applies to any visual cue interpreted from a
screenshot of the adversary dashboard during debugging: if the
inference would change the diagnosis, screenshot a second time at a
different scroll position and confirm the cue before coding.

### M4. Status reports with 5+ numbered items the user will return to are artifacts, not inline markdown

**Issue (2026-05-12 → 2026-05-14, fifth re-flag).** DM-investigation
and Gauntlet-assignment investigation responses keep emitting numbered
status reports (5+ open action items, embedded `computer://` links,
Slack permalinks, follow-up open-loop questions, status timestamps) as
inline chat markdown. Every refresh of "what do I still need to do
today" requires re-running the whole investigation from scratch
because the prior result is buried in chat history. The application
gap has been re-flagged in the chat-inefficiencies sweep four times
running with no behavior change.

**Prevention.** When a response includes any one of: (a) a numbered
list of 5+ open action items, (b) "still pending" / "open loops"
phrasing, (c) the same investigation has been run more than once in
the past week, (d) the user has previously asked "what do I still
need to do" — build the response with `mcp__cowork__create_artifact`
wired to the relevant connector tools (Slack search, calendar
`list_events`, portal Chrome MCP calls). The artifact's Reload button
replaces re-running the investigation by hand. No discretion. Same
rule applies to any adversary-side surface that fits the shape (e.g.,
"open vulnerability tickets that need triage" should be an artifact
calling `/api/findings?status=open`, not a chat-rendered list).

### M5. Recover host-side `.git/index.lock` via the cowork-terminal MCP, not by escalating to the user

**Issue (2026-05-14).** A commit step at the end of an investigation
session blocked on `.git/index.lock` left over from a host-side git
process. Sandbox-bash retries kept failing because the sandbox cannot
write to the host's `.git`. I surfaced the problem as a paste-block to
the user instead of trying the host-shell path first, which made the
user manually clear a lock that the cowork-terminal MCP can clear
unattended.

**Prevention.** When a commit fails inside `mcp__workspace__bash` with
`index.lock` as the only blocker, retry once via
`mcp__cowork-terminal__execute_command` as a single chained call:
`rm <repo>/.git/index.lock && git -C <repo> add -A && git -C <repo>
commit -m "<msg>"`. The cowork-terminal MCP has host-side write
access; the sandbox bash does not. Only after that chained call also
fails does the lock become a user-visible problem. Same pattern
applies to any other host-only file the sandbox bash cannot touch
(e.g., `.DS_Store` cleanup, `chmod` on host paths, `launchctl` reload).

### M6. Large batch user inputs (more than ~5 distinct content blocks) get written to disk before processing

**Issue (2026-05-13).** A single user turn arrived with 14–18 full
CCAT practice tests pasted in rapid succession. I shipped four files
covering tests 1–11, then bailed to a handoff doc rather than push
through 12–18 because the active context was saturating. User: "wtf
how many entries are allowed in your message queue?"

**Prevention.** If a single user turn contains more than ~5 distinct
content blocks (multiple practice tests, multiple log dumps, multiple
email bodies, multiple attached files, multiple chart screenshots),
write each block to its own file in the workspace folder as the FIRST
action — `~/Documents/Claude/Projects/<topic>/batch-input-XX.md` is a
fine convention — then process from disk. Do not try to hold all of
them in active context while iteratively producing output. Failure
shape that triggers this rule: you find yourself emitting a handoff
doc midway through the batch because context is saturating, OR you
notice you have re-quoted earlier turn material into your own response
to "remember" it.
