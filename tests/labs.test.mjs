import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { LABS, evaluateLab, parseLabInput, scoreDecision } from '../docs/labs.mjs';

const examples = {
  'soc-alert-triage': { findings: 1, changeIndex: 8, change: { count: 10 }, updatedFindings: 0, badField: 'count' },
  'identity-access-review': { findings: 2, changeIndex: 2, change: { enabled: false }, updatedFindings: 1, badField: 'enabled' },
  'cloud-posture': { findings: 2, changeIndex: 2, change: { public: false }, updatedFindings: 1, badField: 'public' },
  'sbom-review': { findings: 2, changeIndex: 0, change: { version: '1.4.1' }, updatedFindings: 1, badField: 'version' },
  'forensic-custody': { findings: 2, changeIndex: 3, change: { digest: 'fixture-a1', from: 'examiner-a' }, updatedFindings: 0, badField: 'from' },
  'backup-restore': { findings: 2, changeIndex: 1, change: { verified: true, restoreMinutes: 100 }, updatedFindings: 1, badField: 'verified' },
  'email-authentication': { findings: 2, changeIndex: 1, change: { dkimDomain: 'LEDGER.EXAMPLE.' }, updatedFindings: 1, badField: 'dkim' },
  'privacy-egress': { findings: 1, changeIndex: 2, change: { purpose: 'capacity', fields: ['region'], retentionDays: 1 }, updatedFindings: 0, badField: 'fields' },
  'incident-timeline': { findings: 1, changeIndex: 3, change: { time: '2026-01-15T16:03:00Z' }, updatedFindings: 0, badField: 'ingested' },
  'ai-trust-boundary': { findings: 1, changeIndex: 3, change: { action: 'summarize', provenance: 'verified-operator' }, updatedFindings: 0, badField: 'provenance' },
};

test('the catalog contains ten unique labs with separate findings and playable decisions', () => {
  assert.equal(LABS.length, 10);
  assert.deepEqual(new Set(LABS.map(({ id }) => id)), new Set(Object.keys(examples)));
  for (const lab of LABS) {
    assert.equal(new Set(lab.choices.map(({ id }) => id)).size, 3);
    for (const choice of lab.choices) {
      assert.deepEqual(scoreDecision(lab.id, choice.id), {
        correct: choice.id === lab.answer,
        explanation: lab.explanation,
      });
    }
    const report = evaluateLab(lab.id);
    assert.ok(report.metrics.length >= 2);
    assert.equal(report.findings.length, examples[lab.id].findings);
    for (const { eventIndexes } of report.findings) {
      assert.ok(eventIndexes.length > 0);
      assert.ok(eventIndexes.every((index) => Number.isInteger(index) && index >= 0 && index < lab.events.length));
    }
  }
});

for (const lab of LABS) {
  test(`${lab.id}: JSON and JSONL give the same analyzable local data`, () => {
    const { changeIndex, change, updatedFindings } = examples[lab.id];
    const events = structuredClone(lab.events);
    Object.assign(events[changeIndex], change);
    const json = parseLabInput(lab.id, JSON.stringify(events));
    const jsonl = parseLabInput(lab.id, events.map((item) => JSON.stringify(item)).join('\n\n'));
    assert.deepEqual(jsonl, json);
    assert.equal(evaluateLab(lab.id, json).findings.length, updatedFindings);
    assert.notDeepEqual(evaluateLab(lab.id, json), evaluateLab(lab.id));
  });

  test(`${lab.id}: required event fields are checked with record context`, () => {
    const { changeIndex, badField } = examples[lab.id];
    const events = structuredClone(lab.events);
    delete events[changeIndex][badField];
    assert.throws(() => parseLabInput(lab.id, JSON.stringify(events)),
      new RegExp(`Event ${changeIndex + 1}: missing or invalid ${badField}`));
  });
}

test('timestamps normalize, invalid dates fail, and partial incident evidence does not imply containment', () => {
  const lab = LABS.find(({ id }) => id === 'incident-timeline');
  const input = [{ ...lab.events[0], time: '2026-01-15T17:02:00+01:00', ingested: '2026-01-15T16:10:00Z' }];
  const [record] = parseLabInput(lab.id, JSON.stringify(input));
  assert.equal(record.time, '2026-01-15T16:02:00.000Z');
  assert.equal(evaluateLab(lab.id, [record]).metrics[0].value, 'Not observed');
  assert.match(evaluateLab(lab.id, [record]).findings[0].title, /not verified/);
  assert.throws(() => evaluateLab(lab.id, [{ ...record, time: '2026-02-30T10:00:00Z' }]), /ISO 8601/);
});

test('invalid modes, oversized inputs, incomplete policies and malformed JSON fail clearly', () => {
  assert.throws(() => evaluateLab('unknown'), /Unknown lab/);
  assert.throws(() => scoreDecision('backup-restore', 'unknown'), /Unknown choice/);
  assert.throws(() => parseLabInput('cloud-posture', '[]'), /Expected 1 to/);
  assert.throws(() => parseLabInput('cloud-posture', ' '.repeat(2_000_001)), /up to/);
  assert.throws(() => parseLabInput('cloud-posture', '{}\nnot-json'), /record line 2/);
  const cloud = LABS.find(({ id }) => id === 'cloud-posture');
  assert.throws(() => evaluateLab(cloud.id, cloud.events.slice(1)), /exactly one policy/);
});

test('CLI evaluates the catalog, graders and user-provided files', async () => {
  const cli = fileURLToPath(new URL('../tools/run-lab.mjs', import.meta.url));
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  const list = run('--list');
  assert.equal(list.status, 0, list.stderr);
  assert.equal(list.stdout.trim().split('\n').length, 10);
  const all = run('--all');
  assert.equal(all.status, 0, all.stderr);
  assert.match(all.stdout, /Action proposal blocked/);
  const grade = run('backup-restore', '--choose', 'verified');
  assert.equal(grade.status, 0, grade.stderr);
  assert.match(grade.stdout, /Correct\./);

  const directory = await mkdtemp(join(tmpdir(), 'signal-lab-test-'));
  try {
    const path = join(directory, 'mail.jsonl');
    const mail = LABS.find(({ id }) => id === 'email-authentication');
    await writeFile(path, JSON.stringify(mail.events[0]));
    const custom = run(mail.id, '--input', path);
    assert.equal(custom.status, 0, custom.stderr);
    assert.match(custom.stdout, /Messages evaluated · 1/);
    assert.match(custom.stdout, /No findings/);
    assert.equal(run(mail.id, '--input').status, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
