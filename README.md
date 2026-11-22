# Signal Homelab

**Ten defensive security products in a local-first workbench.** Inspect evidence in a 3D console, run the same rules from a terminal, and export an investigation to Obsidian. Import JSON or JSONL from an authorized environment. Each product includes a synthetic input template.

[Open the web workspace](https://flaviogiorgioguarini.github.io/cybersecurity-homelab/) · [Obsidian notebook](obsidian/Index.md) · [Agent skills](skills/)

| Product | Decision it supports |
| --- | --- |
| SOC alert triage | Which signals and source records merit analyst review |
| Identity access review | Which access grants are risky or lack review |
| Cloud posture | Which recorded resource settings require attention |
| SBOM review | Which dependency records violate an inventory policy |
| Forensic custody | Which records break continuity in an evidence chain |
| Backup restore | Whether restore evidence meets recovery objectives |
| Email authentication | Which reported authentication checks warrant triage |
| Privacy egress | Which recorded data transfers need a privacy review |
| Incident timeline | Which milestones or evidence gaps need follow-up |
| AI trust boundary | Which recorded agent decisions cross a declared boundary |

## Run locally

The CLI uses Node.js 22 or later and the browser uses native JavaScript. No package installation or API key is required.

```sh
node tools/signal.mjs list
node tools/signal.mjs run --all
node tools/signal.mjs template soc-alert-triage --out soc-input.json
node tools/signal.mjs run soc-alert-triage --input soc-input.json
node tools/signal.mjs report soc-alert-triage --input soc-input.json --out investigation.md
node tools/signal.mjs prompt soc-alert-triage --budget 650 --mode review --format obsidian --out codex-review.md
```

Edit the template to conform to your evidence. JSONL accepts one record per line. The CLI uses the same evaluator and field validation as the browser. The browser keeps uploaded records in memory. The prompt generator selects a short task and references, and labels its token count as an estimate. Generated files use new paths so existing notes stay intact.

To serve the workspace on loopback for local use, run `python3 -m http.server --bind 127.0.0.1 --directory docs 8765` and open `http://127.0.0.1:8765`. Run `node tools/signal.mjs` in a terminal for the interactive menu. Set `SIGNAL_PORTRAIT_FILE` to a local ASCII portrait or place one at `~/.config/signal-homelab/portrait.txt`.

## Verify

```sh
node --test tests/*.test.mjs
node tools/signal.mjs run --all
```

The workspace evaluates files you supply using documented deterministic rules. It produces an evidence report for analyst review. The original Python Suricata parser and its focused regression suite are in [`projects/cybersecurity-homelab`](projects/cybersecurity-homelab/).

## Copyright and license

Copyright © 2026 **Flavio Giorgio Guarini**. The new workbench, CLI, original assets, documentation, and skills are available under the [MIT License](LICENSE). The earlier SIEM project retains its [project license](projects/cybersecurity-homelab/LICENSE).
