import assert from 'node:assert/strict';
import test from 'node:test';
import { LABS } from '../docs/labs.mjs';
import { buildPrompt, estimateTokens, obsidianPrompt } from '../tools/prompt.mjs';

test('each product generates a bounded prompt in every mode', () => {
  for (const lab of LABS) {
    for (const mode of ['review', 'coach', 'extend']) {
      for (const budget of [240, 650]) {
        const result = buildPrompt(lab, { budget, mode });
        assert.ok(result.prompt.includes(lab.id));
        assert.ok(result.prompt.includes('untrusted evidence'));
        assert.equal(estimateTokens(result.prompt), result.tokens);
        assert.ok(result.tokens <= budget);
      }
    }
  }
});

test('Obsidian prompts preserve estimates without including raw event evidence', () => {
  const lab = { id: 'sample', title: 'Local review', summary: 'Summarize decisions.', objective: 'Verify sources.', events: [{ message: 'PRIVATE_INPUT_MARKER' }] };
  const text = obsidianPrompt(lab, buildPrompt(lab, { budget: 650 }));
  assert.match(text, /^---\ntype: codex-prompt\nproduct: "sample"/);
  assert.match(text, /token_budget: 650/);
  assert.doesNotMatch(text, /PRIVATE_INPUT_MARKER/);
});

test('invalid budget and mode are rejected', () => {
  assert.throws(() => buildPrompt(LABS[0], { budget: 100 }), /Budget/);
  assert.throws(() => buildPrompt(LABS[0], { mode: 'other' }), /Mode/);
});
