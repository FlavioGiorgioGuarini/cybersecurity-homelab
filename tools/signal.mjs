#!/usr/bin/env node
import { readFile, stat, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { parseArgs } from 'node:util';
import { LABS, evaluateLab, parseLabInput, scoreDecision } from '../docs/labs.mjs';
import { buildPrompt, obsidianPrompt } from './prompt.mjs';

const MAX_INPUT = 1_048_576;
const DEFAULT_LOGO = [' ╭───────────────────╮', ' │  S I G N A L   ◈  │', ' │  H O M E L A B    │', ' ╰───────────────────╯'];
const help = `Usage: node tools/signal.mjs <command> [product] [options]

  list                                   List all products
  template <product>                      Export an editable JSON input template
  run <product> [--input FILE]            Evaluate an example or local JSON/JSONL
  run --all                              Evaluate the ten included examples
  report <product> [--input FILE]        Create a Markdown investigation report
  prompt <product> [--mode review]       Create a small Codex task prompt

  --input FILE           Read local JSON/JSONL, up to 1 MiB
  --out FILE             Save to a new file
  --budget N             Estimated prompt budget (240–5000, default 900)
  --format obsidian      Add Obsidian frontmatter to the prompt
  --mode review|coach|extend

Run without arguments in a terminal to open the investigation menu.
Set SIGNAL_PORTRAIT_FILE to an optional local ASCII portrait file.`;

function getLab(id) {
  const lab = LABS.find(item => item.id === id);
  if (!lab) throw new Error(`Unknown product ${JSON.stringify(id ?? '')}. Run list for valid IDs.`);
  return lab;
}

async function readInput(lab, file) {
  const info = await stat(file);
  if (!info.isFile() || info.size > MAX_INPUT) throw new Error('Input must be a file of at most 1 MiB.');
  const payload = await readFile(file, 'utf8');
  if (Buffer.byteLength(payload, 'utf8') > MAX_INPUT) throw new Error('Input exceeds the 1 MiB limit.');
  return parseLabInput(lab.id, payload);
}

function safeText(value) {
  return String(value).replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '');
}

function markdown(value) {
  return safeText(value).replace(/\s+/g, ' ').replace(/[&<>]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[ch])
    .replace(/[\\`*_\[\]#]/g, '\\$&');
}

function report(lab, result, custom) {
  const lines = [
    '---', 'type: security-investigation', `product: ${JSON.stringify(lab.id)}`,
    `evidence: ${custom ? 'local-input' : 'synthetic-example'}`, '---', '',
    `# ${markdown(lab.title)}`, '', '## Metrics', '',
    ...result.metrics.map(({ label, value }) => `- ${markdown(label)} — ${markdown(value)}`),
    '', '## Findings', '',
  ];
  if (result.findings.length === 0) lines.push('No findings matched the current rules.');
  for (const item of result.findings) {
    lines.push(`- **${markdown(item.title)}** (${markdown(item.severity)}) — ${markdown(item.detail)}`);
    if (item.eventIndexes.length) lines.push(`  - Evidence rows ${item.eventIndexes.map(i => i + 1).join(', ')}`);
  }
  return [...lines, '', '## Review', '', '- Confirm findings against the original evidence before taking action.', ''].join('\n');
}

async function deliver(text, path) {
  if (path) {
    await writeFile(resolve(path), text, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    console.log(`Saved ${resolve(path)}`);
  } else {
    process.stdout.write(text.endsWith('\n') ? text : `${text}\n`);
  }
}

async function showLogo() {
  const local = process.env.SIGNAL_PORTRAIT_FILE || resolve(process.env.XDG_CONFIG_HOME || resolve(homedir(), '.config'), 'signal-homelab/portrait.txt');
  let logo = DEFAULT_LOGO;
  try {
    const info = await stat(local);
    if (info.isFile() && info.size <= 8192) {
      const lines = (await readFile(local, 'utf8')).split(/\r?\n/).slice(0, 28)
        .map(line => line.replace(/[^ -~]/g, ' ').slice(0, 72));
      if (lines.some(line => line.trim())) logo = lines;
    }
  } catch (error) {
    if (process.env.SIGNAL_PORTRAIT_FILE) console.error(`Portrait unavailable: ${error.code || 'read error'}`);
  }
  console.log(`\x1b[38;5;49m${logo.join('\n')}\x1b[0m\nSignal Homelab · Investigation console\n`);
}

async function menu() {
  await showLogo();
  for (const [index, lab] of LABS.entries()) console.log(`${String(index + 1).padStart(2)}  ${lab.title}`);
  const reader = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const selection = (await reader.question('\nProduct number (Enter to exit) › ')).trim();
    if (!selection) return;
    const lab = LABS[Number(selection) - 1];
    if (!lab) throw new Error('Choose a product number from the menu.');
    const input = (await reader.question('Local JSON/JSONL path (Enter for example) › ')).trim();
    const events = input ? await readInput(lab, input) : lab.events;
    const result = evaluateLab(lab.id, events);
    process.stdout.write(`\n${report(lab, result, Boolean(input))}\n`);
    if (input) return;
    console.log(lab.decision);
    for (const [index, choice] of lab.choices.entries()) console.log(`${index + 1}. ${choice.label}`);
    const answer = (await reader.question('Decision number (Enter to skip) › ')).trim();
    if (answer) {
      const choice = lab.choices[Number(answer) - 1];
      if (!choice) throw new Error('Choose one of the displayed decisions.');
      const feedback = scoreDecision(lab.id, choice.id);
      console.log(`${feedback.correct ? 'Correct' : 'Review the evidence'}: ${feedback.explanation}`);
    }
  } finally {
    reader.close();
  }
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      all: { type: 'boolean' }, input: { type: 'string' }, out: { type: 'string' },
      budget: { type: 'string' }, mode: { type: 'string' }, format: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  const [command, id] = positionals;
  if (values.help || (!command && !process.stdin.isTTY)) return console.log(help);
  if (!command) return menu();
  if (positionals.length > 2) throw new Error('Too many positional arguments.');
  if (command === 'list') return deliver(LABS.map(lab => `${lab.id}\t${lab.title}`).join('\n'), values.out);
  if (command === 'template') return deliver(JSON.stringify(getLab(id).events, null, 2), values.out);
  if (command === 'run' && values.all) {
    if (id || values.input) throw new Error('--all runs the included examples and cannot take a product or input file.');
    return deliver(JSON.stringify(LABS.map(lab => ({ id: lab.id, ...evaluateLab(lab.id) })), null, 2), values.out);
  }
  if (!['run', 'report', 'prompt'].includes(command)) throw new Error(`Unknown command ${JSON.stringify(command)}.`);

  const lab = getLab(id);
  if (command === 'prompt') {
    if (values.input) throw new Error('Prompts reference product files and do not import private logs.');
    const result = buildPrompt(lab, { budget: Number(values.budget ?? 900), mode: values.mode ?? 'review' });
    if (values.format && !['text', 'obsidian'].includes(values.format)) throw new Error('Format must be text or obsidian.');
    await deliver(values.format === 'obsidian' ? obsidianPrompt(lab, result) : result.prompt, values.out);
    return console.error(`Estimated ${result.tokens}/${result.budget} tokens · ${result.mode}`);
  }

  const custom = Boolean(values.input);
  const events = custom ? await readInput(lab, values.input) : lab.events;
  const result = evaluateLab(lab.id, events);
  const body = command === 'report' ? report(lab, result, custom) : JSON.stringify({ id: lab.id, ...result }, null, 2);
  return deliver(body, values.out);
}

await main().catch(error => {
  console.error(`Signal: ${safeText(error.message)}`);
  process.exitCode = 1;
});
