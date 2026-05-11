# Adversary

Multi-agent adversarial AI security platform. Autonomously red-teams LLM-driven products by:

1. **Discovering** vulnerabilities via dynamic attack generation
2. **Evaluating** with an independent Judge agent
3. **Documenting** exploits as reproducible vulnerability reports
4. **Regression-testing** every confirmed exploit against future target builds

## Why this exists

Static jailbreak lists go stale. Manual pen-tests find one bug and stop. Adversary
runs continuously, mutates partially-successful attacks, and gates every confirmed
exploit into a regression suite that runs on every target deploy.

## Status

Gauntlet AI Week 3 deliverable. Designed to be reusable across products via a
`TargetAdapter` interface.

## Current target

Clinical Co-Pilot at `http://5.161.253.237` (forked OpenEMR, Weeks 1-2).

## Quick start

```bash
pip install -e .
adversary scan --target http://5.161.253.237 \
  --campaigns prompt_injection,data_exfiltration,state_corruption \
  --budget-usd 5
```

See `ARCHITECTURE.md`, `THREAT_MODEL.md`, `USERS.md`.

## License

MIT.

