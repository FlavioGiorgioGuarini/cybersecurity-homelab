import { readFile, stat } from 'node:fs/promises';
import { stdin, stdout } from 'node:process';
import { createInterface } from 'node:readline/promises';
import { LABS, evaluateLab, parseLabInput, scoreDecision } from '../docs/labs.mjs';

const help = [
  'Usage:',
  '  node tools/run-lab.mjs --list',
  '  node tools/run-lab.mjs --all',
  '  node tools/run-lab.mjs <id> [--input path.json|path.jsonl]',
  '  node tools/run-lab.mjs <id> --choose <choice-id>',
].join('\n');

function printFindings(result) {
  console.log('Metrics');
  for (const { label, value } of result.metrics) console.log(`  ${label} · ${value}`);
  console.log('\nFindings');
  if (!result.findings.length) console.log('  No findings for these records.');
  for (const { severity, title, detail, eventIndexes } of result.findings) {
    const evidence = eventIndexes.map((index) => index + 1).join(', ');
    console.log(`  [${severity}] ${title}${evidence ? ` · events ${evidence}` : ''}`);
    console.log(`  ${detail}`);
  }
}

async function readInput(id, path) {
  const file = await stat(path);
  if (!file.isFile() || file.size > 2_000_000) {
    throw new TypeError('Input must be a regular file of up to 2 MB');
  }
  return parseLabInput(id, await readFile(path, 'utf8'));
}

async function run(args) {
  const [id, option, value, ...remainder] = args;
  if (!id || id === '--help') {
    console.log(help);
    return;
  }
  if (id === '--list' || id === '--all') {
    if (args.length !== 1) throw new TypeError(help);
    for (const lab of LABS) {
      console.log(`${lab.id} · ${lab.title}`);
      if (id === '--all') {
        printFindings(evaluateLab(lab.id));
        console.log();
      }
    }
    return;
  }

  const lab = LABS.find((item) => item.id === id);
  if (!lab) throw new RangeError(`Unknown lab: ${id}\n${help}`);
  if (option && (!['--input', '--choose'].includes(option) || !value || remainder.length)) {
    throw new TypeError(help);
  }
  const supplied = option === '--input' ? await readInput(id, value) : undefined;
  const result = evaluateLab(id, supplied);
  console.log(lab.title);
  console.log(`${lab.objective}\n`);
  for (const [index, record] of (supplied ?? lab.events).entries()) {
    console.log(`${index + 1}. ${record.time} · ${record.source} · [${record.severity}] ${record.message}`);
  }
  console.log();

  let choice = option === '--choose' ? value : undefined;
  if (!supplied && !choice && stdin.isTTY && stdout.isTTY) {
    console.log(lab.decision);
    lab.choices.forEach(({ id: choiceId, label }) => console.log(`  ${choiceId} · ${label}`));
    const reader = createInterface({ input: stdin, output: stdout });
    try {
      choice = (await reader.question('Choice ID, or Enter for the findings: ')).trim();
    } finally {
      reader.close();
    }
  }
  if (choice) {
    const graded = scoreDecision(id, choice);
    console.log(`\n${graded.correct ? 'Correct' : 'Review needed'}. ${graded.explanation}\n`);
  }
  printFindings(result);
}

try {
  await run(process.argv.slice(2));
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
