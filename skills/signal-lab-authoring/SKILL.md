---
name: signal-lab-authoring
description: Add or revise a synthetic defensive triage lab in Signal Homelab and verify the expected decision through its shared evaluator and offline runner.
---

# Author a Signal Homelab lab

Work from the project root. Read `docs/labs.mjs`, then choose one existing `LABS` entry whose decision structure fits the new case. Preserve the evaluator contract consumed by both built-in samples and locally imported JSON or JSONL. Ship generated examples that remain safe to distribute.

- Keep the scenario to defensive recognition, triage, containment, or recovery. Create fictional identifiers and sanitized events. Use reserved documentation addresses and domains when examples require them.
- Define the observable task and justified disposition before writing alternatives. Include one useful discriminator between plausible choices. Explain how that observation supports the decision, and avoid treating weak signals as proof of compromise.
- Add the case to `LABS`. Keep its event types and required fields compatible with `parseLabInput`. Reuse `evaluateLab` and `scoreDecision` for shared scoring and feedback. Update `tests/labs.test.mjs` when a new behavior would otherwise lack coverage.
- Exercise both the selected case and the catalog. Run commands from the repository root.

```sh
node tools/run-lab.mjs --list
node tools/run-lab.mjs <id>
node tools/run-lab.mjs --all
node --test tests/labs.test.mjs
```

Report the case ID, observed interpretation, test result, and any unresolved inference. Keep the procedure runnable without a target system or account.
