# Signal Workspace QA

Use the local browser workspace in `docs/index.html`. Record one run per browser and viewport combination. Compare a built-in sample with `node tools/run-lab.mjs <id>`, then exercise a local input and workspace export.

| Check | Evidence |
| --- | --- |
| Narrow and wide layout | Widths, visible controls and readable evidence |
| Keyboard path | Select a case, evaluate evidence, check the decision and review feedback. Test arrow-key orbit and Tab away from the telemetry field. |
| Motion preference | Test Pause rotation and open a fresh page with reduced motion. Record the observed behavior. |
| Graphics fallback | Environment and whether evidence and controls remain reachable |
| Outcome parity | Lab ID and CLI comparison |
| Local import and export | File type, report location and comparison with the same case and input in the CLI |

Mark combinations you could not exercise as unverified. Link [[Signal Evidence Walkthrough]] for the reasoning and [[Signal Workspace Operations]] for the run and export commands.
