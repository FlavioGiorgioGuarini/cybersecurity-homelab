# Signal Homelab

A notebook for operating and maintaining Signal Homelab, a local defensive triage workspace. Import approved JSON or JSONL telemetry or start with a built-in synthetic sample. Commands run from the Signal Homelab repository root.

- [[Signal Workspace Operations]] covers local ingestion, workspace export, and the prompt and report commands.
- [[Signal Lab Authoring]] covers case design and automated verification.
- [[Signal Evidence Walkthrough]] records how evidence supports a decision.
- [[Signal Workspace QA]] checks browser interaction, accessibility and local export.
- [[Signal Adoption Review]] tracks public project use and maintainer activity.

## Open in Obsidian

Open this `obsidian` folder as a local vault, or copy the entire folder into an existing vault and open this note. Keep the note filenames together so the links resolve. These plain Markdown notes work locally with Obsidian’s core links. No add-ons or paid services are required.

```sh
node tools/run-lab.mjs --list
node tools/run-lab.mjs --all
node --test tests/labs.test.mjs
```

The reusable agent instructions are under `skills/` in the repository.
