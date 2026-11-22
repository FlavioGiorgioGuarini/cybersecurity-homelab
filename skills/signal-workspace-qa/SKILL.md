---
name: signal-workspace-qa
description: Verify Signal Homelab's local browser workspace for accessible defensive triage, JSON or JSONL ingestion and report export at mobile and desktop widths.
---

# Check the Signal Homelab workspace

Use the local entry point in `docs/index.html` and the project’s documented launch method. Start with a built-in synthetic sample to compare the browser result with `node tools/run-lab.mjs <id>`. Then exercise the workspace import and export with an approved local JSON or JSONL input.

1. At a narrow viewport and at desktop size, select a lab, evaluate the evidence, and check a decision. Look for horizontal overflow, clipped text and obscured controls.
2. Repeat without a pointer. Check focus visibility and order, button labels, decision feedback and a usable path back to the catalog. Focus the telemetry field, try its arrow-key orbit, then Tab to leave it.
3. Exercise **Pause rotation** and test the reduced-motion preference on a fresh page. Check that essential evidence remains available. Exercise a graphics-disabled fallback when the browser can simulate it.
4. Compare the workspace report with the local CLI report when both use the same case and input. Verify Markdown output opens and cite offsets or identifiers only when they are present in the processed records.
5. Record browser, viewport, input type and observed results. If a condition could not be exercised, record it as unverified. Limit claims to the combinations actually tested.

Use the project’s local assets and approved inputs. Store any optional personal portrait in private local configuration under `~/.config`. Keep personal assets and reports outside public repository content.

[W3C guidance on keyboard traps](https://www.w3.org/WAI/WCAG21/Understanding/no-keyboard-trap) · [W3C guidance on interaction animation](https://www.w3.org/WAI/WCAG22/Understanding/animation-from-interactions)
