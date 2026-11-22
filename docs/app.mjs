import { LABS, evaluateLab, parseLabInput, scoreDecision } from "./labs.mjs";
import { mountSignalField } from "./scene.mjs";

const MAX_BYTES = 1024 * 1024;
const PROGRESS_KEY = "signal-homelab/practice/v1";
const SEVERITIES = ["info", "warning", "critical"];
const validLabs = new Set(LABS.map((lab) => lab.id));
const $ = (id) => document.getElementById(id);
const signalField = mountSignalField($("signal-canvas"), $("motion-toggle"));

let activeLab;
let report = null;
let importSequence = 0;
const localEvidence = new Map();
const completed = readProgress();

function make(tag, className = "", value = "") {
  const element = document.createElement(tag);
  element.className = className;
  element.textContent = value;
  return element;
}

function readProgress() {
  try {
    const saved = JSON.parse(localStorage.getItem(PROGRESS_KEY) || "[]");
    return new Set(Array.isArray(saved) ? saved.filter((id) => validLabs.has(id)) : []);
  } catch {
    return new Set();
  }
}

function saveProgress() {
  try {
    localStorage.setItem(PROGRESS_KEY, JSON.stringify([...completed]));
  } catch {
    $("workspace-status").textContent = "Practice progress is only available for this tab.";
  }
}

function renderProgress() {
  $("lab-progress").max = LABS.length;
  $("lab-progress").value = completed.size;
  $("progress-text").textContent = `${completed.size} of ${LABS.length} complete`;
  $("reset-progress").disabled = completed.size === 0;
}

function renderLibrary() {
  const query = $("lab-search").value.toLowerCase().trim().split(/\s+/).filter(Boolean);
  const matches = LABS.filter((lab) => {
    const searchable = `${lab.title} ${lab.category} ${lab.summary}`.toLowerCase();
    return query.every((part) => searchable.includes(part));
  });
  $("lab-count").textContent = query.length
    ? `${matches.length} of ${LABS.length} tools`
    : `${LABS.length} tools`;
  const entries = matches.map((lab) => {
    const item = make("li");
    const option = make("button", "lab-option");
    const text = make("span");
    const done = completed.has(lab.id);
    option.type = "button";
    option.dataset.lab = lab.id;
    option.setAttribute("aria-pressed", String(lab.id === activeLab.id));
    option.setAttribute("aria-controls", "lab-workspace");
    text.append(make("span", "option-title", lab.title), make("span", "option-detail", lab.category));
    const mark = make("span", `option-mark${done ? " is-complete" : ""}`, done ? "✓" : "›");
    mark.setAttribute("aria-hidden", "true");
    if (done) text.append(make("span", "sr-only", " Practice complete"));
    option.append(text, mark);
    item.append(option);
    return item;
  });
  if (!entries.length) entries.push(make("li", "lab-list-empty", "No tools match this search."));
  $("lab-list").replaceChildren(...entries);
}

function activeRecords() {
  return localEvidence.get(activeLab.id)?.records ?? activeLab.events;
}

function severityLabel(severity, value = severity) {
  const className = /^[a-z]+$/.test(severity) ? severity : "info";
  return make("span", `severity ${className}`, value);
}

function renderSeverityChart(records) {
  const counts = Object.fromEntries(SEVERITIES.map((key) => [key, 0]));
  for (const record of records) counts[record.severity] += 1;
  const bar = make("div", "chart-bar");
  const key = make("div", "chart-key");
  bar.setAttribute("aria-hidden", "true");
  for (const severity of SEVERITIES) {
    const count = counts[severity];
    if (count) {
      const segment = make("span", `chart-segment ${severity}`);
      segment.style.flexGrow = count;
      bar.append(segment);
    }
    key.append(severityLabel(severity, `${count} ${severity}`));
  }
  $("severity-chart").replaceChildren(bar, key);
  signalField.update(counts);
}

function eventNode(event, index) {
  const row = make("li", "event-row");
  row.id = `event-${index + 1}`;
  row.tabIndex = -1;
  const timing = make("div", "event-time");
  const timestamp = make("time", "", event.time.replace("T", " ").replace(/\.\d+Z$/, "Z"));
  timestamp.dateTime = event.time;
  timing.append(make("span", "event-number", `Event ${index + 1}`), timestamp);
  const content = make("div", "event-content");
  content.append(make("p", "event-source", event.source), make("p", "event-message", event.message));
  row.append(timing, content, severityLabel(event.severity));
  return row;
}

function renderWorkspace() {
  const records = activeRecords();
  const imported = localEvidence.get(activeLab.id);
  $("lab-category").textContent = activeLab.category;
  $("lab-title").textContent = activeLab.title;
  $("lab-summary").textContent = activeLab.summary;
  $("lab-objective").textContent = activeLab.objective;
  $("dataset-summary").textContent = imported
    ? `Local file · ${imported.filename}`
    : "Built-in synthetic records are selected.";
  $("scene-caption").textContent = imported
    ? `${activeLab.category} · Local evidence`
    : `${activeLab.category} · Synthetic records`;
  $("sample-reset").hidden = !imported;
  $("event-summary").textContent = `${records.length} ${records.length === 1 ? "record" : "records"} · ${imported ? "Local file" : "Synthetic sample"}`;
  $("evaluate").disabled = records.length === 0;
  renderSeverityChart(records);
  $("events").replaceChildren(...records.map(eventNode));
  $("events").scrollTop = 0;
  renderDecision(Boolean(imported));
  clearEvaluation();
}

function renderDecision(imported) {
  $("decision-form").hidden = imported;
  $("decision-prompt").textContent = activeLab.decision;
  const options = activeLab.choices.map(({ id, label }) => {
    const option = make("label", "choice");
    const radio = make("input");
    radio.type = "radio";
    radio.name = "decision";
    radio.value = id;
    option.append(radio, make("span", "", label));
    return option;
  });
  $("choices").replaceChildren(...options);
  $("decision-feedback").hidden = true;
  $("check-decision").disabled = true;
}

function clearEvaluation() {
  report = null;
  $("evaluation").hidden = true;
  $("metrics").replaceChildren();
  $("findings").replaceChildren();
}

function chooseLab(id, navigate = false) {
  const selected = LABS.find((lab) => lab.id === id);
  if (!selected) return;
  activeLab = selected;
  importSequence += 1;
  $("dataset-input").value = "";
  showInputError("");
  renderLibrary();
  renderWorkspace();
  renderProgress();
  if (navigate) {
    const url = new URL(window.location.href);
    url.searchParams.set("lab", id);
    history.replaceState(null, "", url);
    if (window.matchMedia("(max-width: 720px)").matches) $("lab-header").scrollIntoView({ block: "start" });
    $("lab-title").focus({ preventScroll: true });
  }
}

function showInputError(message) {
  $("input-error").textContent = message;
  $("input-error").hidden = !message;
}

async function importFile(file) {
  const version = ++importSequence;
  showInputError("");
  if (file.size > MAX_BYTES) {
    showInputError("This file is larger than 1 MB. Choose a smaller JSON or JSONL file.");
    return;
  }
  try {
    const text = await file.text();
    if (version !== importSequence) return;
    const records = parseLabInput(activeLab.id, text);
    localEvidence.set(activeLab.id, { filename: file.name, records });
    renderWorkspace();
  } catch (error) {
    if (version === importSequence) showInputError(error instanceof Error ? error.message : "The local file could not be read.");
  }
}

function highlightEvent(index) {
  const row = $(`event-${index + 1}`);
  if (!row) return;
  $("events").querySelector(".is-cited")?.classList.remove("is-cited");
  row.classList.add("is-cited");
  row.focus({ preventScroll: true });
  row.scrollIntoView({ block: "nearest" });
}

function evaluate() {
  const records = activeRecords();
  showInputError("");
  try {
    const evaluation = evaluateLab(activeLab.id, records);
    renderEvaluation(evaluation, records);
  } catch (error) {
    showInputError(error instanceof Error ? error.message : "This dataset could not be evaluated.");
  }
}

function renderEvaluation({ metrics, findings }, records) {
  const metricsMarkup = metrics.map(({ label, value }) => {
    const metric = make("div", "metric");
    metric.append(make("dt", "", label), make("dd", "", String(value)));
    return metric;
  });
  const sources = new Set();
  const findingsMarkup = findings.map(({ severity, title, detail, eventIndexes }) => {
    const finding = make("li", "finding");
    finding.append(severityLabel(severity), make("h5", "finding-title", title), make("p", "finding-detail", detail));
    const links = make("div", "finding-events");
    for (const index of eventIndexes) {
      if (!Number.isInteger(index) || !records[index]) continue;
      sources.add(index);
      const link = make("button", "event-link", `Event ${index + 1}`);
      link.type = "button";
      link.addEventListener("click", () => highlightEvent(index));
      links.append(link);
    }
    if (links.children.length) finding.append(links);
    return finding;
  });
  if (!findingsMarkup.length) findingsMarkup.push(make("li", "finding", "No findings matched this dataset."));
  $("metrics").replaceChildren(...metricsMarkup);
  $("findings").replaceChildren(...findingsMarkup);
  $("evaluation").hidden = false;
  $("results-title").focus({ preventScroll: true });
  $("evaluation").scrollIntoView({ block: "nearest" });
  const imported = localEvidence.get(activeLab.id);
  report = {
    tool: { id: activeLab.id, title: activeLab.title },
    dataset: { type: imported ? "local" : "synthetic", records: records.length, ...(imported && { filename: imported.filename }) },
    evaluatedAt: new Date().toISOString(),
    metrics,
    findings,
    evidence: [...sources].sort((a, b) => a - b).map((index) => ({ eventIndex: index, record: records[index] })),
  };
}

function download(filename, type, text) {
  const objectUrl = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(objectUrl), 4000);
}

function markdownValue(value) {
  return String(value).replace(/[\r\n]+/g, " ").replace(/[&<>"']/g, (character) => `&#${character.charCodeAt(0)};`).replace(/[\\*_[\]`#|]/g, "\\$&");
}

function reportMarkdown(data) {
  const lines = [
    `# ${markdownValue(data.tool.title)}`, "",
    `Dataset: ${data.dataset.type} · ${data.dataset.records} records`,
    `Evaluated: ${data.evaluatedAt}`, "",
    "## Metrics", "",
    ...data.metrics.map(({ label, value }) => `- **${markdownValue(label)}** — ${markdownValue(value)}`),
    "", "## Findings", "",
  ];
  for (const finding of data.findings) {
    lines.push(
      `### ${markdownValue(finding.title)}`, "",
      `${markdownValue(finding.severity)} — ${markdownValue(finding.detail)}`,
      `Evidence: ${finding.eventIndexes.map((index) => `Event ${index + 1}`).join(", ") || "none"}`, "",
    );
  }
  if (!data.findings.length) lines.push("No findings matched this dataset.", "");
  if (data.evidence.length) lines.push("## Cited events", "");
  for (const { eventIndex, record } of data.evidence) {
    lines.push(`- **Event ${eventIndex + 1}** — ${markdownValue(record.time)} · ${markdownValue(record.source)} · ${markdownValue(record.message)}`);
  }
  return lines.join("\n") + "\n";
}

$("lab-search").addEventListener("input", renderLibrary);
$("lab-list").addEventListener("click", (event) => {
  const option = event.target.closest("button[data-lab]");
  if (option) chooseLab(option.dataset.lab, true);
});
$("import-trigger").addEventListener("click", () => $("dataset-input").click());
$("dataset-input").addEventListener("change", (event) => {
  const file = event.target.files?.[0];
  event.target.value = "";
  if (file) importFile(file);
});
$("sample-reset").addEventListener("click", () => {
  importSequence += 1;
  showInputError("");
  localEvidence.delete(activeLab.id);
  renderWorkspace();
  $("import-trigger").focus();
});
$("download-sample").addEventListener("click", () => {
  download(`${activeLab.id}-sample.json`, "application/json", JSON.stringify(activeLab.events, null, 2) + "\n");
});
$("evaluate").addEventListener("click", evaluate);
$("export-json").addEventListener("click", () => {
  if (report) download(`${activeLab.id}-report.json`, "application/json", JSON.stringify(report, null, 2) + "\n");
});
$("export-markdown").addEventListener("click", () => {
  if (report) download(`${activeLab.id}-report.md`, "text/markdown", reportMarkdown(report));
});
$("choices").addEventListener("change", () => {
  $("check-decision").disabled = false;
  $("decision-feedback").hidden = true;
});
$("decision-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (localEvidence.has(activeLab.id)) return;
  const choiceId = new FormData(event.target).get("decision");
  if (!choiceId) return;
  const { correct, explanation } = scoreDecision(activeLab.id, choiceId);
  const feedback = $("decision-feedback");
  feedback.hidden = false;
  feedback.classList.toggle("retry", !correct);
  feedback.textContent = `${correct ? "Correct." : "Review the evidence and try again."} ${explanation}`;
  if (correct) {
    completed.add(activeLab.id);
    saveProgress();
    renderProgress();
    renderLibrary();
  }
});
$("reset-progress").addEventListener("click", () => {
  completed.clear();
  saveProgress();
  renderProgress();
  renderLibrary();
  renderDecision(localEvidence.has(activeLab.id));
  $("workspace-status").textContent = "Practice progress reset.";
  $("lab-search").focus();
});

const requestedLab = new URLSearchParams(window.location.search).get("lab");
chooseLab(validLabs.has(requestedLab) ? requestedLab : LABS[0].id);
