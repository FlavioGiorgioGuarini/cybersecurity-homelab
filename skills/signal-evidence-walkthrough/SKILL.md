---
name: signal-evidence-walkthrough
description: Explain evidence and rationale from a Signal Homelab defensive case, whether it uses a built-in sample or approved local JSON or JSONL telemetry.
---

# Walk through defensive evidence

Find the scenario ID in `node tools/run-lab.mjs --list` and read its evaluation rules in the `LABS` export of `docs/labs.mjs`. Reproduce the built-in sample with `node tools/run-lab.mjs <id>`. For local telemetry, use the workspace import and export or generate a report from the CLI with approved evidence.

```sh
node tools/signal.mjs report <id> --input path.json --out report.md
node tools/signal.mjs prompt <id> --budget 650 --mode review --format obsidian
```

- Start with the analyst's question. List the small set of observations that could change the answer and identify the event, field, or value supporting each.
- Explain why the chosen defensive response follows from those observations. Give one plausible alternative and the evidence that would move the decision toward it.
- Check the rationale against `evaluateLab` and `scoreDecision`. Report any mismatch between the written explanation and the runnable case.
- Identify whether the evidence came from a built-in sample or approved local data. Describe confidence and missing context. Keep raw local inputs and reports private and review them for sensitive fields before any authorized sharing.

A concise walkthrough records the case ID, observation, inference, decision, and reproducible command.
