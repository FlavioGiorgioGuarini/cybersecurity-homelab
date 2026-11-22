# Signal Lab Authoring

Start in `docs/labs.mjs`. Use an existing `LABS` entry as a model. `parseLabInput` checks local inputs. The shared `evaluateLab` and `scoreDecision` functions let the CLI and browser agree. Built-in samples exercise the cases with fictional data. [[Signal Workspace Operations]] explains how to work with local data.

| Field | What to record |
| --- | --- |
| Case ID | Stable identifier used by the lab runner |
| Analyst question | The defensive decision the case asks for |
| Synthetic evidence | A few fictional observations that discriminate between choices |
| Expected decision | Disposition and rationale supported by the evidence |
| Plausible alternative | The observation that would make it appropriate |
| Verification | Result of the selected case, whole catalog and test suite |

Run `node tools/run-lab.mjs --list`, `node tools/run-lab.mjs <id>`, `node tools/run-lab.mjs --all` and `node --test tests/labs.test.mjs` from the project root.

Use [[Signal Evidence Walkthrough]] to record conclusions and [[Signal Workspace QA]] to compare the browser route with the evaluator.
