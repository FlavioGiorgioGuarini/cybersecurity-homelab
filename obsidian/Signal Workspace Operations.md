# Signal Workspace Operations

Signal Homelab evaluates evidence for a chosen defensive case. Its built-in synthetic samples provide repeatable inputs. To analyze approved local telemetry, select a case and import JSON or JSONL in the browser workspace. Review the observations and save the report using the workspace export.

Supply a JSON array of events or one event object per non-empty JSONL line. Provide `time` as an ISO 8601 timestamp with timezone, `source` and `message` as text, and `severity` as `info`, `warning` or `critical`. Use the case's sample in `docs/labs.mjs` to identify its event kinds and additional fields accepted by `parseLabInput`.

## Local CLI

From the repository root, obtain the available case IDs.

```sh
node tools/run-lab.mjs --list
node tools/run-lab.mjs <id> --input path.jsonl
```

Generate an evidence report from an approved local file. Replace `<id>`, `path.json` and `report.md` with your case and private paths.

```sh
node tools/signal.mjs report <id> --input path.json --out report.md
```

Generate a bounded review prompt formatted for Obsidian.

```sh
node tools/signal.mjs prompt <id> --budget 650 --mode review --format obsidian
```

Review the prompt before pasting it into an AI service. Keep raw source files, personal assets and imported reports in a private local folder. Configure any personal portrait privately under `~/.config` with an image you have the right to use. The public workspace uses its own default assets.

Use [[Signal Evidence Walkthrough]] to record the result and [[Signal Workspace QA]] to compare browser export and CLI output.
