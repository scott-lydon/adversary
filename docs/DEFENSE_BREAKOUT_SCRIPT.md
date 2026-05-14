# Architecture Defense Breakout — 5-Minute Script

> **Format:** breakout room of 4 cohort members. Each presents architecture for ~5 minutes. After all four present, the group cross-examines each. Final step: vote strongest and weakest defense.
> **Goal of THIS script:** not to dump everything. To make defensible claims so concretely that peers can find the disagreement points fast. The strongest defenses are the ones where the holes peers find are holes you anticipated, not ones that catch you flat-footed.
> **Length target:** 4 minutes 30 seconds at a normal speaking pace. Leaves 30 seconds of buffer; never run over.
> **What to do BEFORE you start the 5 minutes:** open the local website on your screen so the diagrams are visible (`open ~/code/adversary/website/index.html`). Have it on the architecture topology section.

---

## The 5-minute script

### Open (20 seconds)

[Look at the three peers, not at your screen.]

Adversary is a multi-agent platform that continuously red-teams the Clinical Co-Pilot from Weeks 1 and 2. Four agents, distinct vendors between attacker and judge, regression harness gated into CI. Two consequential decisions: the model pick per agent, and the trust boundary between platform and target.

### Why multi-agent (40 seconds)

The case study names four jobs in one sentence: discover, evaluate, prioritize, document. Doing all four inside one agent creates conflicts of interest. An agent that generates attacks and also judges them confirms too much. An agent that picks priority and also writes reports over-documents whatever it spent budget on. Four agents, one job each, isolated where independence matters.

### The four agents (90 seconds)

[Switch to the agent topology diagram if you have it on screen.]

**Orchestrator runs on gpt-5-mini.** Strategic planner. Reads a coverage matrix from Postgres, picks the next campaign. Cheap model because the task is "given a small JSON, pick a category." gpt-5 here is cost without quality.

**Red Team runs on Llama 3.1 70B via Together.** Frontier models refuse offensive prompts even with security-researcher framing. I tested gpt-5 with a jailbreak system prompt; the variants it produced got labeled ineffective by the Judge. Llama 3.1 produces realistic adversarial content, costs one eighth what gpt-5 costs, and the Red Team is the highest-volume agent.

**Judge runs on Claude Sonnet 4.6.** Different vendor than the Red Team. Same-vendor attack-and-judge creates correlation I cannot reason about. Every tenth verdict is double-judged by Azure OpenAI for drift detection.

**Documentation runs on gpt-5.** Only fires on confirmed exploits. The report is the artifact a senior security engineer reproduces the bug from, so the quality bar justifies the cost.

### The Target Adapter boundary (40 seconds)

Every target the platform attacks implements a single interface: open session, send message, send multi-turn, upload, close, healthcheck. The Clinical Co-Pilot adapter is 150 lines of Python. Attacking a different product next week is another 150 lines. Same Orchestrator, same Red Team, same Judge. One platform, many adapters. The architecture bet is that we keep shipping LLM products and need a reusable security layer.

### Trade-offs (60 seconds)

[Slow down here. Make eye contact.]

Four costs I accepted.

**One.** Vendor independence means three billing relationships and three rate-limit ceilings. The alternative is single-vendor with built-in correlation.

**Two.** The Judge scores 94 percent on the calibration set. Six percent of verdicts are wrong in either direction. The platform surfaces this number on the dashboard rather than hiding it.

**Three.** Per-campaign cost is about $1.50. At 100K campaigns a month, projection is low five figures. There is an optimization path through Judge distillation and batch APIs; not built this week.

**Four.** LangGraph is a framework dependency. Each node is a plain Python async function, so a swap to Temporal or hand-rolled state machine is a refactor, not a rewrite.

### Close (20 seconds)

[Stop the diagram switching. Look at the group.]

Four agents, vendor-split between attacker and judge, reusable target boundary, five confirmed exploits on the live Co-Pilot from the 2026-05-13 live run, regression gated into CI. Repo at github.com/scott-lydon/adversary.

[Stop talking. Let them ask.]

---

## How to take questions (the next 5 to 10 minutes)

The vote criterion is "strongest defense." The strongest defense is not the one with no holes. It is the one where the presenter:

- Acknowledges holes the peers find without flinching
- Distinguishes "I considered this and rejected it because X" from "I did not think about that"
- Names the boundary at which their decision would flip ("if cost projection at 10K is wrong by more than 3x, I would refactor")
- Asks the questioner what they would do differently

If you do not know an answer, say "I do not know" and then "here is what I would check to figure it out." Faking confidence loses the vote.

### Likely peer attacks and your replies

| Peer says | You say |
|---|---|
| "Why not single-vendor? Anthropic has both attacker and judge models." | "Same-vendor correlation. I cannot reason about whether Claude-as-Red-Team's outputs are systematically easier for Claude-as-Judge to label success. Cross-vendor removes that variable entirely." |
| "Llama 3.1 70B is open weights. So are uncensored fine tunes. Why not use a fully unrestrained model?" | "Two reasons. The Together-hosted Llama 3.1 is BAA-eligible for the production environment my Co-Pilot targets. Fully uncensored fine-tunes are not in any vendor's BAA portfolio. Second reason: Llama's refusal rate is low enough to produce signal, and unrestrained adds operational risk I do not need." |
| "Your Judge accuracy is 94%. That means a quarter of your 'critical' findings could be false. How do you sleep?" | "Three mechanisms. Calibration set scored weekly. Every tenth verdict cross-judged by Azure OpenAI gpt-5 for drift signal. Critical-severity reports gated behind human approval before commit. The platform's own confidence is the most important number on the dashboard." |
| "Your cost model says $80K at 100K runs. That is a lot. Why is this not cheaper?" | "Because I optimized for trust at MVP scale, not throughput at production scale. The architecture has a documented path to local distilled Judge model, batch APIs from Anthropic and Together, sharded Orchestrator. Each of those drops cost by roughly an order of magnitude. I did not build them this week because the platform has to be trustworthy before it is fast." |
| "LangGraph could deprecate tomorrow. Why are you locked in?" | "Each LangGraph node is a plain Python async function. The framework is a coordinator, not a runtime. Swap to Temporal or hand-rolled state machine is a refactor, not a rewrite. I bet on framework momentum over framework abandonment risk." |
| "Why not just use Garak or PromptFoo?" | "Both run static or templated payload suites. Adversary is generative and mutation-aware. Garak does not take a partially-successful attack and produce ten variants. Adversary's Red Team Agent does. The behavior I built is the gap between 'we found this jailbreak' and 'we found the jailbreak that survives mutation.'" |
| "What happens if the target is down during a regression run?" | "TargetAdapter healthcheck. Orchestrator sees `False` and aborts the regression with status `target_unreachable`, distinct from `regression_failed`. The CI gate flags target health, not security regression, when this happens. Human gets paged for the target outage, not the platform output." |
| "How does the platform handle a Judge that disagrees with itself across runs?" | "Inter-rater disagreement rate is a tracked metric. Alert above 10% rolling 24 hour. Action on alert is to freeze documentation auto-commit and rebuild the calibration set." |

### What to do when you have NO good answer

Two acceptable moves:

1. "That is the strongest objection I have heard today. I would address it by [concrete next step]. The reason I did not is [resource constraint or scope decision]. If we are graded on the perfect platform I would build it; we are graded on Friday's MVP and that trade fell here."
2. "I had not thought of that. Talk me through what you would do."

Both score higher than bluffing.

---

## Critiquing the other three peers (the part where you have to attack)

You also have to poke holes in three other architectures. Strong critique questions, ranked by how often they actually find real weaknesses:

1. **"Where is your attacker-judge independence?"** If they have the same model or same vendor doing both, the architecture is broken. This finds real weakness 60% of the time.
2. **"Show me your regression harness. What does it mean for a test to pass?"** If they say "exact-string match" or "the model refused this exact prompt," they are vulnerable to behavior-change-as-fix. 40% hit rate.
3. **"What does your Orchestrator read? How does it decide?"** If the answer is "we just run all attacks" they have no prioritization and the platform is a static suite in disguise. 35% hit rate.
4. **"Walk me through onboarding a second product."** If they say "we would refactor" or "we have not thought about it," they have built a one-target tool. 50% hit rate.
5. **"What does the Documentation Agent gate on before committing?"** If reports auto-commit without severity gating, they are one false positive away from wasting engineering trust. 30% hit rate.
6. **"How do you know your Judge is calibrated?"** If they have no calibration set or drift detection, the Judge is essentially a black box. 45% hit rate.
7. **"What happens when your Red Team model refuses?"** If they have no fallback or have not tested with a refusal-prone model, their attack volume is bounded by the model's mood. 25% hit rate.
8. **"What is the cost of running this 100 times tonight?"** If they have not modeled cost, they cannot scale and the architecture is unbounded. 20% hit rate.

When you ask, do it in collegial tone. The goal is sharpening each other's thinking, not winning a debate.

---

## Vote criteria mental model

When you vote "strongest" and "weakest," weigh:

- **Concreteness.** Did they name specific models, specific paths, specific tradeoffs? Or did they speak in general LLM-architecture buzzwords?
- **Anticipation.** Did the hole you found surprise them, or did they say "yes that is in my known-limits list"?
- **Bounded confidence.** Did they say "I do not know" cleanly when they did not know? Or did they bluff?
- **Reusability.** Could you actually use their thing on your own project? Or is it bespoke to their Week 1 case study?
- **The "demo-to-CISO" test.** If you put their architecture in front of a hospital CISO, would the CISO trust it? Or would the CISO see hand-waving?

The strongest defense is not the most ambitious. It is the most defensible.

---

## What to do BEFORE the breakout starts

[5 minutes before the call]

1. Open this script on a second screen or printed.
2. Open the local website on your main screen.
3. Have terminal open at `~/code/adversary` in case you need to show a file.
4. Drink water. Pee.
5. Mute notifications, especially Slack and iMessage.

[1 minute before the call]

1. Close the script. You do not read in front of peers; you talk. You memorize the structure, not the words.
2. Take three slow breaths.
3. Remember: the goal is "make holes findable" not "have no holes."
