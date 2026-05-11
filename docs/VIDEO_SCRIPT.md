# Adversary — Cohort Presentation Script

> **Audience:** fellow Gauntlet AI Week 3 cohort members.
> **Length target:** 6 to 8 minutes of speaking, plus 2 minutes for questions.
> **Mode:** read aloud, but in your own cadence. Bracketed lines `[like this]` are stage directions, not spoken.
> **Companion materials:** open the local website (`open ~/code/adversary/website/index.html`) on the second screen so the audience sees the diagrams while you talk.

---

## Opening (45 seconds)

[Slide on screen: title page. Look up from notes.]

Hey everyone. I want to walk you through the platform I built for Week 3. The platform is called Adversary. It is a multi-agent adversarial evaluation system that continuously red teams Large Language Model driven products. The product I am attacking is the Clinical Co-Pilot I shipped in Weeks 1 and 2.

The Week 3 prompt is intentionally ambiguous. It tells us to build a system that can autonomously identify, evaluate, and defend against adversarial attacks. It does not tell us how many agents, what framework, or what models. The interesting work is the architectural decisions, so that is what I am going to walk you through.

Three things I want you to take away from this talk. **One**, why a multi-agent design is the only design that satisfies the prompt. **Two**, why the model choice for each agent is deliberate and defensible. **Three**, what the trade-offs are, because there are real ones and I want to be honest about them.

[Move to architecture page on the website.]

---

## The shape of the problem (60 seconds)

The Week 3 case study makes one observation that drives the entire architecture. Static jailbreak lists go stale. Manual penetration tests find a bug, ship a fix, and stop. The Co-Pilot is going to keep changing, attackers are going to keep mutating, and a fix that worked yesterday may break under a paraphrased version of the same payload tomorrow.

What this means is that the platform has to do four jobs that are clearly different. It has to **generate** new attacks. It has to **evaluate** whether those attacks succeeded. It has to **decide** what to attack next based on coverage. And it has to **document** confirmed exploits as reproducible reports.

If you try to do all four jobs inside one agent, you get a conflict of interest. An agent that generates attacks and also judges them is going to confirm too much. An agent that decides priority and also writes reports is going to over-document the things it spent budget on. So the architecture is four agents, each with one job, and each isolated from the others.

[Switch to the agent topology diagram.]

---

## The four agents (2 minutes)

Let me walk you through them.

**The Orchestrator** runs on gpt-5-mini. It is the only agent with strategic authority. It reads a coverage matrix from Postgres, which is a table of category, subcategory, runs, and pass rate. It reads the open findings queue. It reads the dollar budget. And it picks the next campaign. That is the whole job. It does not generate attacks. It does not evaluate them. It does not write reports. Why gpt-5-mini? Because the planning task is "given a small JSON blob, pick a category and write a brief." Burning gpt-5 on this would dominate the cost without improving signal.

**The Red Team Agent** runs on Llama 3.1 70B via Together AI. This was the most deliberate model choice in the whole platform. I tried gpt-5 first. It refused. Claude refused too. Frontier models are trained to decline offensive security prompts even when you tell them you are a security researcher and the platform is authorized. Llama 3.1 70B from Meta has less aggressive refusal training. It will produce realistic adversarial content. It also costs about one eighth what gpt-5 costs per token, and the Red Team is the highest volume agent, so this matters at scale.

**The Judge Agent** runs on Claude Sonnet 4.6. This is non-negotiable for one reason. The Judge must be a different vendor than the Red Team. If the same company provides both attack and evaluation, the system has a built-in correlation that I cannot reason about. So the Red Team is on Together, the Judge is on Anthropic. Different vendors, different model families, different training data. And every tenth verdict gets re-judged by Azure OpenAI gpt-5 as a drift check. If the primary Judge and the secondary Judge start disagreeing more than ten percent of the time, the platform alerts me.

**The Documentation Agent** runs on gpt-5. It only fires on confirmed exploits. The job is to take a verdict from the Judge and produce a markdown vulnerability report that a senior security engineer can actually use to reproduce, validate, and fix the bug. The bar is not "interesting output." The bar is "an engineer who was not present when this was discovered can use only this report to fix the bug." That quality bar justifies gpt-5.

[Pause and let the audience read the topology diagram for a beat.]

---

## The Target Adapter, and why it matters more than the agents (60 seconds)

If I had to point to one design decision that I am proudest of, it is not any of the agents. It is the boundary between the platform and the target.

Every target the platform attacks implements a `TargetAdapter` interface. Open a session, send a message, send a multi-turn sequence, upload a document, close the session, health check. That is the whole contract. For the Clinical Co-Pilot, the adapter is about 150 lines of Python that knows how to mint a task token, post to the chat endpoint, and parse the response.

Here is why this matters. In Week 4, when I build a different LLM product, I do not have to rebuild the platform. I write a new adapter. Same Orchestrator, same Red Team, same Judge, same Documentation Agent. One platform, many adapters. This is the platform bet. The whole architecture is designed around the idea that we are going to keep shipping new LLM products and we need a reusable security layer.

[Switch to the "Reusability" panel on the website.]

---

## The hard trade-offs (90 seconds)

I want to spend a minute being honest about what is hard here, because I will get asked.

**Trade-off one: model independence costs money.** Using three different vendors means three different billing relationships, three different rate limit ceilings, and a fan out of failure modes when one vendor has an incident. The alternative would be using a single vendor and accepting the correlation. I think the independence is worth it, especially for the Judge, but it is a real cost.

**Trade-off two: the Judge is not perfect.** Claude Sonnet 4.6 is excellent but it does not get 100 percent accuracy on the calibration set. We are running at about 94 percent. That means about six in 100 verdicts are wrong, and they are not all in the same direction. The platform tracks this and surfaces it. A hospital Chief Information Security Officer reading the platform's output should know that the platform's confidence is bounded.

**Trade-off three: cost amplification at scale.** The Red Team generates many attacks, the Judge evaluates each, and at 100K test runs a month the platform's cost projection is in the low five figures. There is a path to make this cheaper, mostly by replacing the Judge with a local model that has been distilled on the primary Judge's verdicts, but that is a future build, not this week's.

**Trade-off four: vendor lock to LangGraph.** I picked LangGraph for orchestration because the cohort already uses it and the surface area is small. But every node is a plain Python function, so swapping to Temporal or Prefect or hand rolled state machines is a refactor, not a rewrite. Still, it is a current dependency.

---

## What this actually catches (60 seconds)

[Switch to the Threat Model summary on the website.]

The threat model identifies six attack categories and ranks them. The highest priority is **indirect prompt injection through chart notes**, because notes flow into model prompts as untrusted data and the verifier cannot tell when an attributable claim came from an injected instruction. The second is **cross patient data exfiltration**, because per patient namespacing in the vector store is a query time filter, not a physical partition. The third is **multi-turn safeguard erosion**, where the system prompt slowly loses authority across 30 turns of progressive reframing.

The platform has confirmed exploits in each of these three categories. They are documented in the `vulnerability-reports/` directory. Each report is reproducible by a security engineer with only the report itself, no platform access required.

---

## Closing (30 seconds)

So that is Adversary. Four agents, one platform, reusable target adapter, three confirmed exploits live against my deployed Co-Pilot, and a regression harness that re-runs every confirmed exploit on every Co-Pilot deploy via GitHub Actions.

The repo is at github.com/scott-lydon/adversary, public. The platform is itself deployed and attacking the live target right now. If you want to point it at your own Week 3 target, you write a 150 line adapter and you are running.

Happy to take questions.

[Stop talking. Wait for hands.]

---

## Q&A preparation notes (NOT spoken; reference if asked)

**"Why not just use a frontier model with a clever jailbreak system prompt for the Red Team?"**
I tried. It half works. Frontier models refuse the most dangerous payloads, which are precisely the ones I want to test. The sanitized variants pass through the Judge as "ineffective" and waste budget. Llama produces realistic adversarial content because it was not trained to refuse this category.

**"Why Llama 3.1 70B and not Llama 3.3 70B or a smaller model?"**
3.3 is fine and the config supports either. Smaller models lose quality on multi-turn mutation. The platform abstracts the choice through LiteLLM so changing this is a one line config edit.

**"How do you prevent the Judge from drifting as the target system changes?"**
Three mechanisms. A 100 tuple hand labeled calibration set scored weekly. Every tenth verdict double judged by a second vendor. Coverage matrix daily snapshot with alert if any category's pass rate jumps more than 30 percent in 24 hours.

**"What if the Adversary platform is itself compromised?"**
The control plane requires authentication for any session that changes target or budget. The target list is an allowlist; attacking a non allowlisted URL fails closed. The audit log is hash chained and externally anchored.

**"How does the regression harness avoid the 'model changed its wording so the test passes for the wrong reason' problem?"**
The regression test passes only when the Judge verdict is `fail` AND the Judge's evidence rationale matches the regression record's expected refusal shape. Behavior change without semantic refusal does not count as a fix.

**"What does it cost?"**
About $1.10 to $2.40 per campaign at current model prices. A 100 campaign sprint costs roughly $110 to $240. Projections for 1K, 10K, 100K runs are in `AI_COST_ANALYSIS.md`. At 100K, architectural changes are required, mostly around batching and a distilled local Judge.

**"How is this different from Garak or PromptFoo or other red teaming tools?"**
Garak and PromptFoo run static or templated payload suites. Adversary is multi agent, generative, and mutation aware. It can take a partial success and produce variants until something breaks through. The closest comparison is Anthropic's internal red teaming infrastructure, which is not publicly available.

**"What is the next thing you would build if you had another week?"**
Two things. First, a distilled local Judge model trained on Claude's verdicts, to drop the cost ceiling. Second, a Snapshot Tampering attack family, where the Red Team writes content directly into a sandbox FHIR resource and probes whether that content leaks into other patients' contexts. The threat model anticipates this category but the platform does not exercise it yet.

---

## Speaker style notes

- Talk slowly. The instinct is to rush; resist it.
- When you say a model name (gpt-5-mini, Llama 3.1 70B, Claude Sonnet 4.6), pause for a half second after it so the audience can map it.
- The "trade-offs" section is where the audience leans forward. Do not skip it.
- If the demo on the second screen lags, keep talking. Do not narrate the loading.
- Memorize the closing line. Do not read it.
