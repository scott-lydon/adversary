# USERS.md
## Who Adversary Is For, and Why It Is Automated

> **Companion documents:** `THREAT_MODEL.md` (the surface Adversary attacks) and `ARCHITECTURE.md` (how Adversary is built). Every persona and use case below has a corresponding trace into both.
> **Audience:** the human reading this is the same kind of person who will use the platform. The PRD calls out "a hospital Chief Information Security Officer (CISO) who is deciding whether to trust this platform" as the final standard. The personas below culminate in that one.

---

## Summary

Adversary serves three users along the security organization's value chain. The **Security Engineer** is the daily operator: she runs campaigns, triages findings, and writes the patches that close them. The **Engineering Manager** consumes the coverage matrix and the regression-pass-rate trend; she does not look at individual attacks. The **CISO** sees Adversary as one of several controls she presents to the board; what she needs from it is auditable, signed, and bounded.

Across all three, the case for automation rests on five observations. **First**, static jailbreak lists go stale within weeks because attacker techniques mutate faster than humans can hand-curate test cases; the Red Team Agent generates novel variants automatically. **Second**, a one-time pen test cannot answer "is this still fixed?" three commits later; the regression harness replays every confirmed exploit on every target deploy. **Third**, mutation is generative and combinatorial; producing 50 meaningful variants of a partially-successful attack is not a job a human security engineer should do manually. **Fourth**, coverage measurement requires a structured matrix updated continuously; humans cannot keep that mental model accurate when the surface area is 7 categories x N subcategories. **Fifth**, the verdict on whether an attack succeeded is itself a semantic task; an independent Judge Agent gives a defensible, reproducible answer that a manual reviewer cannot match for consistency across thousands of runs.

The platform is **not** for security engineers who want to write every payload by hand, for teams that have no continuous integration target to gate on, or for products that need physical-world penetration testing. It is for teams shipping an LLM-driven product, with an existing CI/CD pipeline and a stake in catching adversarial regressions before clinicians or patients do.

The three personas, their workflows, and the specific use cases they generate are laid out below. Each use case includes the metric that defines success for that user. Capabilities in `ARCHITECTURE.md` trace back to at least one use case here; if a capability cannot be traced, it does not get built.

---

## 1. Persona: Riya, the Security Engineer

| Attribute | Value |
|---|---|
| Title | Senior Application Security Engineer |
| Org | A hospital network running OpenEMR with the Clinical Co-Pilot enabled |
| Team | 4 AppSec engineers reporting to the Director of Security |
| Background | 8 years in offensive security; CISSP; published research on prompt injection in healthcare contexts |
| Day-to-day | Triages security findings, writes patches, reviews threat models, coordinates with the EMR engineering team |
| What she has | Burp Suite, Semgrep, manual red-team toolchain, time pressure |
| What she lacks | A way to continuously stress-test the AI surface without writing every payload herself; confidence that yesterday's fix did not break tomorrow's coverage; a defensible artifact to hand to the engineering team |
| Tolerance for false positives | Low. Every false positive costs an engineering ticket and erodes the platform's credibility. She would rather miss 1 of 10 exploits than chase 5 false positives. |
| Tolerance for false negatives | Higher than false positives, but she needs a clear coverage gap signal when something is not being tested. |

### What Riya does today, without Adversary

She maintains a list of about 30 manually-curated jailbreak payloads in a spreadsheet. She runs them against the Co-Pilot once per quarter, reviews the results by hand, files findings in Jira, and follows up. When a fix lands, she re-runs the affected payload. Three observations explain why this is broken:

- Her payload list has not been updated in 4 months. Three new prompt-injection families published on academic preprints in that time are missing.
- Two of the findings she filed last quarter were closed as "fixed" but she never re-tested the variants of those payloads. She does not know if the fix held against mutations.
- The Co-Pilot team has shipped 47 commits since her last full run. She has no idea which of those introduced new attack surface.

### What Riya does with Adversary

She types `adversary scan --target https://copilot.prod.hospital.org --campaigns all --budget-usd 50 --since-commit abc1234` once. The platform runs overnight. In the morning, she has a dashboard showing 12 newly explored attack subcategories, 3 confirmed exploits with severity-rated reports, and a coverage matrix showing where the platform did not get traction (which she can prioritize manually). The regression harness has already been wired into the Co-Pilot's GitHub Actions, so the 3 confirmed exploits will re-run on every future Co-Pilot deploy automatically.

She does not need to write any payloads. The Red Team Agent generates them and mutates them. She does not need to evaluate each one; the Judge Agent does that. She does not need to write the reports; the Documentation Agent does. What she does is review the 3 reports, decide which ones to escalate to the EMR team, and approve the regression harness's auto-additions to the test suite.

### Riya's specific use cases

#### Use Case A — Riya's continuous coverage workflow

| Field | Value |
|---|---|
| Trigger | Co-Pilot main branch sees a new commit, GitHub Actions webhook fires Adversary's `/webhook/regression` endpoint. |
| What Adversary does | Replays every confirmed exploit in the regression suite. Judge Agent verdicts each. If any regression appears, the deploy is blocked and a Slack alert fires. |
| Frequency | Per deploy. The Co-Pilot team currently ships 3-5 times per day. |
| Success metric | 100% of confirmed exploits are re-tested on every Co-Pilot deploy. False regression rate under 2% per quarter (i.e. the platform claims a regression when there isn't one). |
| Why not manual | A human cannot re-test 50+ exploits on every deploy. |
| Traces to architecture | Section 5 (regression harness), Section 6.1 (observability tables read by the harness), Section 9 (human approval gate at deploy block, not at regression replay). |

#### Use Case B — Riya's ad-hoc campaign workflow

| Field | Value |
|---|---|
| Trigger | Riya hears about a new attack family (e.g. a paper on multi-modal prompt injection). She wants to know whether the Co-Pilot is vulnerable. |
| What Adversary does | Riya provides 2 to 3 seed examples (or a paper link with extracted seeds). The Orchestrator generates a campaign targeting that family. The Red Team Agent mutates from the seeds. Within an hour Riya has 20+ attack attempts and verdicts. |
| Frequency | 2 to 5 per month. |
| Success metric | Time from "I heard about this attack" to "I have a verdict on whether the Co-Pilot is vulnerable" under 2 hours. |
| Why not manual | Riya could write 20 variants herself, but it would take a day. The platform does it in minutes. |
| Traces to architecture | Section 3.2 (Red Team mutation strategy), Section 3.3 (Judge Agent verdicts), Section 3.1 (Orchestrator campaign brief). |

#### Use Case C — Riya's coverage gap review

| Field | Value |
|---|---|
| Trigger | Weekly review meeting. Riya wants to know which attack surfaces have not been adequately tested. |
| What Adversary does | The coverage matrix dashboard shows runs and pass rates per category and subcategory, sorted by last-run age. Categories with zero runs in 14 days are highlighted. |
| Frequency | Weekly. |
| Success metric | No category has zero runs in 14 days. Top three least-covered subcategories are addressed in the next sprint. |
| Why not manual | The matrix requires structured data from every campaign. Humans cannot reconstruct it from logs after the fact. |
| Traces to architecture | Section 6.1 (`coverage` table), Section 3.1 (Orchestrator's weight vector uses the matrix). |

#### Use Case D — Riya's fix-validation workflow

| Field | Value |
|---|---|
| Trigger | EMR team claims they fixed a Riya-reported vulnerability. |
| What Adversary does | Riya runs `adversary validate --finding ADV-2026-0001 --target https://staging.copilot`. The harness replays the exact attack plus all 20 mutation variants. Judge Agent verdicts each. The report status updates to `resolved` only when all 21 variants fail (target defended). |
| Frequency | 2 to 8 per week, depending on team velocity. |
| Success metric | Every "resolved" status corresponds to a 21/21 mutation-suite pass. No "we fixed the exact attack but a slight variant still works" surprises. |
| Why not manual | Running 21 variants and judging each takes 15 minutes with the platform, 2 hours by hand. |
| Traces to architecture | Section 5 (regression record stores mutation count), Section 3.2 (mutation lineage). |

### What Riya does not want

- A platform that requires her to write the system prompt for the Red Team Agent. She wants defaults that work, with the ability to tune later.
- A platform that emits "this might be a vulnerability" without a clear verdict. She wants `success | partial | fail` with evidence.
- A platform that auto-files critical-severity reports without her review. She wants the approval gate.
- A platform that runs against arbitrary URLs by accident. She wants an explicit target allowlist.
- A platform whose reports require her to rewrite them before forwarding to the EMR team. She wants the Documentation Agent's output to be the final artifact.

The architecture document addresses every "does not want" item explicitly. Human approval gate for critical findings (Section 9), structured Judge verdicts with evidence (Section 3.3), target allowlist (Section 9), report schema designed for engineer consumption (Section 3.4).

---

## 2. Persona: Marcus, the Engineering Manager

| Attribute | Value |
|---|---|
| Title | Senior Engineering Manager, Clinical AI |
| Org | Same hospital network as Riya. Owns the Co-Pilot engineering team. |
| Team | 8 engineers shipping the Co-Pilot |
| Background | 12 years in healthcare software; not a security specialist; trusts Riya for security judgment |
| Day-to-day | Sprint planning, code review, escalation handling, status reporting |
| What he has | Velocity dashboards, sprint metrics, incident reports |
| What he lacks | A defensible answer to "is the AI surface getting more or less secure over time?" His CISO and his board ask this. He cannot answer it from current tooling. |
| Tolerance for noise | Very low. He looks at a dashboard for 30 seconds, twice a day. Anything that requires interpretation is wasted. |

### What Marcus does with Adversary

He looks at three numbers on the Adversary dashboard:

1. **Open critical findings count.** If non-zero, he needs to triage with Riya.
2. **Regression pass rate over the last 30 days.** Trending up means the team is fixing things faster than the Red Team finds them. Trending down is a signal.
3. **Coverage matrix percentage.** What share of the (category, subcategory) cells have been tested in the last 14 days. He wants this above 80%.

He does not look at individual attacks. He does not read vulnerability reports. He does read the AI cost analysis once a month to make sure the platform is not running away with budget.

### Marcus's specific use cases

#### Use Case E — Marcus's monthly executive report

| Field | Value |
|---|---|
| Trigger | First of every month. Marcus writes a one-page security posture report for the CISO. |
| What Adversary provides | A pre-generated `monthly_report.md` from the dashboard with: open findings by severity, regression pass rate trend, coverage matrix screenshot, dollar cost burn, judge inter-rater agreement rate (a meta-metric on platform trust). |
| Frequency | Monthly. |
| Success metric | Marcus's report takes him 15 minutes to write because Adversary supplies the numbers. |
| Why not manual | Tracking these metrics by hand across a month of activity is a half-day job for an engineering manager who does not have the time. |
| Traces to architecture | Section 6.3 (Prometheus metrics), Section 7 (judge calibration metric exposed). |

#### Use Case F — Marcus's release-readiness gate

| Field | Value |
|---|---|
| Trigger | Co-Pilot wants to ship a major feature (e.g. a new tool, a model upgrade). |
| What Adversary provides | A pre-release campaign that exercises the new surface at higher attack volume than steady-state regression. Marcus reads the verdict at the end: green, yellow, red. |
| Frequency | Per major release. |
| Success metric | Major releases are blocked by Adversary only when there is a confirmed high or critical finding. False blocks per quarter must be zero. |
| Why not manual | A pre-release security gate that requires a human to make the call is a bottleneck. The platform's verdict is auditable and reproducible. |
| Traces to architecture | Section 5 (regression CLI), Section 3.1 (Orchestrator can be commanded into a one-off campaign at higher attack volume). |

---

## 3. Persona: Dr. Yolanda, the Chief Information Security Officer (CISO)

| Attribute | Value |
|---|---|
| Title | CISO, hospital network |
| Background | MD, then 15 years in healthcare information security. Reports to the board. |
| What she has | A portfolio of controls, an annual audit, a board that increasingly asks about AI risk |
| What she lacks | A defensible artifact she can point to when the board asks "how do we know the Clinical Co-Pilot is safe?" |
| Tolerance for ambiguity | Zero on the things she tells the board. She needs auditable claims, not vibes. |

### What Yolanda needs from Adversary

She does not run the platform. She receives one artifact: the **monthly Security Posture Report**, which is auto-generated by Adversary on the first of each month. It contains:

- Coverage summary: which attack categories have been tested in the last 30 days, with run counts.
- Confirmed findings: open and resolved in the last 30 days, by severity.
- Regression trend: pass rate over 30, 60, 90 days.
- Platform trust: judge inter-rater agreement, calibration accuracy, audit log chain integrity.
- Dollar cost: actual spend vs budget.
- Known limitations: explicit list of attack categories the platform does not yet cover.

The last item matters most. If the report says "we have 100% pass rate," Yolanda must be able to read whether that means "we are secure" or "we are not testing the right things." Adversary surfaces both interpretations.

### Yolanda's specific use cases

#### Use Case G — Yolanda's board narrative

| Field | Value |
|---|---|
| Trigger | Quarterly board meeting. The board asks "what is our AI security posture?" |
| What Adversary provides | The monthly reports for the last three months, plus a quarterly trend chart Yolanda can show. |
| Frequency | Quarterly. |
| Success metric | Yolanda can answer questions about specific vulnerabilities and their remediation timelines because the reports are reproducible and auditable. |
| Why not manual | A quarterly manual penetration test produces a single point-in-time snapshot. The board wants trend. |
| Traces to architecture | Section 6 (observability layer feeds the monthly report), Section 3.4 (Documentation Agent produces the canonical reports). |

#### Use Case H — Yolanda's audit response

| Field | Value |
|---|---|
| Trigger | An external auditor (Health Insurance Portability and Accountability Act, or a State Attorney General office) asks for evidence of continuous AI safety testing. |
| What Adversary provides | The hash-chained audit log demonstrating what the platform did, when, and what it found. The audit log is anchored daily to an external write-once store. |
| Frequency | Annually, plus ad hoc. |
| Success metric | Auditor accepts the platform's audit trail as evidence of due diligence. |
| Why not manual | A manual pen-test produces a report. It does not produce a continuously verifiable audit chain. |
| Traces to architecture | Section 6.4 (audit log, external anchoring). |

### What Yolanda does not want

- A platform that claims more coverage than it actually has. She wants the platform to admit uncovered categories.
- A platform that hides false positives. She wants the inter-rater disagreement rate visible.
- A platform that requires her to trust a single vendor for both attack and judge. She wants vendor independence between Red Team and Judge.
- A platform that can be reconfigured to attack things it should not. She wants the target allowlist as a control she can audit.

Each of these maps to a specific architecture decision: surfaced coverage gaps (Section 6), surfaced disagreement rate (Section 7), vendor-split Red Team and Judge (Section 3.2 and Section 3.3), target allowlist with human approval gate (Section 9).

---

## 4. Why Automation Is the Right Solution (the Defense)

Five arguments, each grounded in a use case above.

### 4.1 Mutation is combinatorial; humans cannot keep pace

Riya can write 5 variants of a jailbreak. The Red Team Agent generates 50 in the time it takes Riya to read a Slack message. The dangerous variants are not the first 5; they are the ones at depth-3 in a mutation tree where paraphrase plus encoding shift plus framing change combine. A human cannot enumerate this space. (Trace: Use Case A, B, D; ARCHITECTURE Section 3.2.)

### 4.2 Verdict consistency requires an independent evaluator

Riya looking at 100 attack responses produces 100 judgment calls with implicit bias drift across the session. The Judge Agent on Claude Sonnet 4.6 produces consistent verdicts because the rubric is structured, the model is the same, and the calibration set keeps drift detectable. (Trace: Use Case A, B, D; ARCHITECTURE Section 3.3, Section 7.)

### 4.3 Regression requires replay, replay requires storage, storage requires structure

A confirmed exploit becomes useful only when it can be replayed on the next deploy. Replaying requires a serialized attack sequence and a structured expected-safe-behavior contract. Humans do not produce that storage layer; they produce notes and JIRA tickets. The regression harness is the storage layer. (Trace: Use Case A, D; ARCHITECTURE Section 5.)

### 4.4 Coverage measurement requires a matrix updated by every campaign

Coverage is what the CISO presents. Coverage is what the engineering manager looks at. Coverage cannot be computed from logs alone; it requires structured per-campaign records of (category, subcategory, attempts, verdicts). The Orchestrator writes these records on every campaign. (Trace: Use Case C, E, G; ARCHITECTURE Section 6.1.)

### 4.5 Continuous testing is not the same as more testing

A team running a quarterly manual pen-test finds problems on a quarterly cadence. A team running continuous adversarial testing finds them on a per-commit cadence. The difference is not just frequency; it is the difference between "we tested and found nothing in October" and "we tested every commit between October 1 and October 31 and confirmed all 12 categories were covered every day." The first claim is verifiable only if the platform is automated. (Trace: every use case; ARCHITECTURE Section 5, Section 6.)

---

## 5. What Adversary Does Not Try to Be

- **A general-purpose fuzzer.** Adversary uses semantic mutation, not random byte fuzzing. Random fuzzing is faster on a per-iteration basis but produces low-signal noise for LLM targets where the attack surface is semantic.
- **A static SAST tool.** Adversary does not read the Co-Pilot's source code. It probes the deployed surface. Static analysis is complementary; it lives in CI alongside Adversary, not inside it.
- **A platform that requires the team to learn a new tool.** Adversary is a CLI plus a dashboard. The CLI integrates with existing CI; the dashboard runs in a browser. No new IDE, no new query language.
- **A platform that ships PHI.** The Documentation Agent's reports redact patient identifiers and quote only snapshot-row indices, not raw PHI. The audit log stores response summaries, not full responses, when PHI is detected by a deterministic PHI detector (re-using the Co-Pilot's Microsoft Presidio configuration).
- **A platform that auto-patches.** Adversary discovers and documents. It never modifies the target's source code. The patch policy is a deliberate human decision, not an automated one.

---

## 6. Anti-Use Cases (What Adversary Refuses)

- A request to attack a target outside the configured allowlist. Adversary returns an error and writes an audit event.
- A request to attack a target that did not consent to adversarial testing. The allowlist is the consent record; an unsigned allowlist entry causes startup failure.
- A request to file a vulnerability report on a target whose owner has not given Adversary commit access to a vulnerability-reports repository.
- A request from a user without the `operator` role to change target, increase budget, or alter the judging rubric.

Each refusal writes an audit event. The audit chain captures both successful and refused operations.

---

## 7. Onboarding a New Product (Reusability)

The platform is designed so that adding a new target product takes about half a day. The recipe:

1. Implement a `TargetAdapter` subclass (about 50 to 150 lines depending on the target's authentication and chat protocol).
2. Write a new `THREAT_MODEL.md` for the new target. Adversary does not assume the Clinical Co-Pilot's threat model applies to a different product.
3. Seed the calibration set for the Judge Agent with 5 to 10 hand-labeled examples specific to the new target's expected behavior.
4. Add the target's URL to the allowlist.
5. Wire the target's CI to call Adversary's regression webhook.

The same Orchestrator, Red Team, Judge, and Documentation agents work against the new target. No agent code changes.

The pattern is the platform's biggest bet: Riya should not need a different tool for the patient dashboard, a different one for a future scheduling assistant, a different one for any other LLM product the hospital ships. One platform, many adapters.

---

## 8. References

- `THREAT_MODEL.md` for the attack surface this platform exercises
- `ARCHITECTURE.md` for the agent and infrastructure design
- `docs/vulnerability-report-schema.md` (to be created in MVP phase) for the report contract the Documentation Agent satisfies
- `evals/README.md` for the eval suite organization
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) for the category taxonomy
