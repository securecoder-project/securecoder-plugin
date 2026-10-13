'use strict';

// The CWE knowledge base: the catalog's shape, the keyword selector, and the
// two places a selection is surfaced (the user-prompt hook and
// securecoder_enrich_prompt).

const test = require('node:test');
const assert = require('node:assert/strict');
const catalog = require('../mcp-server/lib/security-knowledge-base.json');
const kb = require('../mcp-server/lib/knowledge-base');
const { enrichPrompt } = require('../mcp-server/lib/enricher');
const { userPrompt } = require('../mcp-server/lib/hooks');
const { SECURITY_CONSTRAINTS, MAX_PROMPT_CONTEXT_CHARS } = require('../mcp-server/lib/constraints');
const { cleanEnv, makeProject } = require('./helpers');

const CONTENT_FIELDS = ['detect', 'repair', 'false_positives', 'preserve'];
const ids = (text, options) => kb.selectEntries(text, options).map((entry) => entry.id);
// Mentions a keyword of every entry in the catalog.
const EVERYTHING = catalog.entries.map((entry) => entry.keywords[0]).join(', ');

test('catalog entries are structurally uniform and carry the four checklist fields', () => {
  assert.ok(catalog.entries.length >= 10 && catalog.entries.length <= 18, `${catalog.entries.length} entries`);
  const keys = Object.keys(catalog.entries[0]).sort();
  for (const entry of catalog.entries) {
    assert.deepEqual(Object.keys(entry).sort(), keys, entry.id);
    assert.match(entry.id, /^CWE-\d+$/);
    for (const field of ['name', 'summary', ...CONTENT_FIELDS]) {
      assert.equal(typeof entry[field], 'string', `${entry.id} ${field}`);
      assert.ok(entry[field].trim().length > 0, `${entry.id} ${field}`);
      assert.equal(entry[field], entry[field].trim(), `${entry.id} ${field}`);
    }
    assert.match(entry.false_positives, /^Do not flag if /, entry.id);
    assert.ok(Array.isArray(entry.keywords) && entry.keywords.length > 0, entry.id);
    for (const keyword of entry.keywords) {
      assert.equal(typeof keyword, 'string', entry.id);
      assert.ok(keyword.length > 0 && keyword === keyword.toLowerCase().trim(), `${entry.id} keyword "${keyword}"`);
    }
    assert.ok(Array.isArray(entry.languages), entry.id);
  }
  assert.equal(new Set(catalog.entries.map((entry) => entry.id)).size, catalog.entries.length, 'ids are unique');
  assert.deepEqual(kb.entries().map((entry) => entry.id), catalog.entries.map((entry) => entry.id));
});

test('selection is deterministic and capped at six', () => {
  assert.equal(kb.MAX_SELECTED, 6);
  const first = ids(EVERYTHING);
  assert.equal(first.length, 6);
  assert.deepEqual(ids(EVERYTHING), first);
  assert.deepEqual(ids(EVERYTHING.toUpperCase()), first, 'matching ignores case');

  // Equal scores keep catalog order; a better match moves ahead of it.
  assert.deepEqual(ids('validate the xpath expression and the ldap filter'), ['CWE-90', 'CWE-643']);
  assert.deepEqual(ids('ldap lookup, then an xpath expression for the xml query with selectnodes'), ['CWE-643', 'CWE-90']);
});

test('an unrecognised task yields an empty selection and no error', () => {
  for (const input of ['rename this variable', 'make the README nicer', 'why is the build failing?', '', '   ', null, undefined, 42, {}, ['sql']]) {
    assert.deepEqual(kb.selectEntries(input), [], JSON.stringify(input));
  }
  // Everyday debugging phrasing is not a security task.
  assert.deepEqual(ids('fix this error message I get when running npm test'), []);
  assert.deepEqual(ids('here is the stack trace, why does it crash?'), []);
  // Words that mean something else in everyday prompts are not triggers.
  for (const prompt of [
    'Upload the build artifacts to S3',
    'Update the HTML of the landing page',
    'Run the eval suite',
    'Add a dashboard of crypto prices',
    'Add a pinch of salt to the recipe text',
    'Build a Secret Santa picker',
    'A Boeing 777 landing in Washington D.C.',
    'Summarize the U.S.C. section, e.g. the first part',
  ]) assert.deepEqual(ids(prompt), [], prompt);
  // A keyword that ends in punctuation still matches inside code.
  assert.deepEqual(ids('it calls eval(x) on the reply'), ['CWE-94']);
  assert.deepEqual(ids('a medieval(x) theme'), []);
  // Runs of trailing punctuation are scanned once, not once per position.
  const started = Date.now();
  kb.selectEntries(`a${'.'.repeat(19998)}a`);
  kb.selectEntries(`a.${'!?:.'.repeat(4999)}a`);
  assert.ok(Date.now() - started < 250, `${Date.now() - started} ms`);
  // Keywords match whole words, not fragments of other words.
  assert.deepEqual(ids('evaluate the results and the mysqldump schedule'), []);
  assert.deepEqual(kb.selectEntries('sql '.repeat(500000)).map((entry) => entry.id), ['CWE-89'], 'a huge prompt is bounded, not an error');
  assert.equal(kb.renderCompact([]), '');
  assert.equal(kb.renderChecklist([]), '');
});

test('representative tasks select the weakness classes they touch', () => {
  assert.deepEqual(ids('add an endpoint that runs a SQL query built from the search box'), ['CWE-89']);
  assert.deepEqual(ids('run git via subprocess with the branch name from the request'), ['CWE-78']);
  assert.deepEqual(ids('let users upload a file and save it under the given filename'), ['CWE-22']);
  assert.deepEqual(ids('fetch the URL the user pastes and show a link preview'), ['CWE-918']);
  assert.deepEqual(ids('load the session with pickle'), ['CWE-502']);
  assert.deepEqual(ids('store the API key for the billing client'), ['CWE-798']);
  assert.ok(ids('hash passwords with md5 before storing them in postgres').includes('CWE-327'));
  assert.ok(ids('hash passwords with md5 before storing them in postgres').includes('CWE-89'));
});

test('language limits a language-specific entry and can select it on its own', () => {
  const memory = catalog.entries.find((entry) => entry.languages.length > 0);
  assert.equal(memory.id, 'CWE-119');
  // Keywords alone select it when no language is known.
  assert.deepEqual(ids('copy the string with strcpy'), ['CWE-119']);
  // Its language alone selects it, from a path in the text or from a caller.
  assert.deepEqual(ids('refactor utils.c'), ['CWE-119']);
  assert.deepEqual(ids('tidy this up', { files: ['src/parser.cpp'] }), ['CWE-119']);
  assert.deepEqual(ids('rewrite the tokenizer in C++'), ['CWE-119']);
  // A task clearly in another language never gets it, whatever its keywords say.
  assert.deepEqual(ids('write parser.py that reads a buffer overflow report'), []);
  assert.deepEqual(ids('use memcpy semantics', { files: ['src/Main.java'] }), []);
  // Language-neutral entries are unaffected by the detected language.
  assert.deepEqual(ids('build the SQL query', { files: ['db.c'] }), ['CWE-89', 'CWE-119']);
  assert.deepEqual(ids('build the SQL query in app.py'), ['CWE-89']);
});

test('the compact rendering is one line per entry and the checklist carries all four fields', () => {
  const selection = kb.selectEntries('build the SQL query and call subprocess');
  assert.deepEqual(selection.map((entry) => entry.id), ['CWE-89', 'CWE-78']);

  const compact = kb.renderCompact(selection).split('\n');
  assert.equal(compact.length, 3);
  assert.match(compact[0], /guidance, not findings/);
  assert.equal(compact[1], `- CWE-89 SQL injection: ${selection[0].summary}`);

  const checklist = kb.renderChecklist(selection);
  assert.match(checklist, /^Secure-coding checklist/);
  assert.match(checklist, /guidance, not a list of findings/);
  for (const entry of selection) {
    for (const field of CONTENT_FIELDS) assert.ok(checklist.includes(entry[field]), `${entry.id} ${field}`);
  }
  assert.match(checklist, /\n1\. CWE-89 SQL injection\n/);
  assert.match(checklist, /\n2\. CWE-78 OS command injection\n/);
});

test('user-prompt hook adds compact lines for a matching prompt and stays under the ceiling', () => {
  const root = makeProject();
  const env = cleanEnv();

  const plain = userPrompt({ cwd: root, prompt: 'rename this variable' }, { env });
  assert.equal(plain.context, SECURITY_CONSTRAINTS);
  assert.deepEqual(plain.cwes, []);

  const sql = userPrompt({ cwd: root, prompt: 'add an endpoint that runs a SQL query built from the search box' }, { env });
  assert.deepEqual(sql.cwes, ['CWE-89']);
  assert.ok(sql.context.startsWith(`${SECURITY_CONSTRAINTS}\n\n`));
  assert.match(sql.context, /\n- CWE-89 SQL injection: bind every untrusted value/);
  assert.equal(sql.response.hookSpecificOutput.additionalContext, sql.context);

  const most = userPrompt({ cwd: root, prompt: EVERYTHING }, { env });
  assert.equal(most.cwes.length, kb.MAX_SELECTED);
  assert.ok(most.context.length <= MAX_PROMPT_CONTEXT_CHARS, `${most.context.length} characters`);

  // The ceiling holds for the six longest lines the catalog can produce.
  const longest = [...catalog.entries]
    .sort((a, b) => (b.id.length + b.name.length + b.summary.length) - (a.id.length + a.name.length + a.summary.length))
    .slice(0, kb.MAX_SELECTED);
  assert.ok(`${SECURITY_CONSTRAINTS}\n\n${kb.renderCompact(longest)}`.length <= MAX_PROMPT_CONTEXT_CHARS);
});

test('enrichPrompt appends the checklist for a matching task and nothing for any other', () => {
  const matching = enrichPrompt('Write a function that builds a SQL query from the search box');
  assert.deepEqual(matching.cwes, [{ id: 'CWE-89', name: 'SQL injection' }]);
  assert.match(matching.checklist, /^Secure-coding checklist/);
  assert.ok(matching.enriched.endsWith(matching.checklist));
  assert.match(matching.enriched, /Additional constraints:\n- Preserve the exact externally visible contract/);

  const other = enrichPrompt('Write a function that reverses a list');
  assert.deepEqual(other.cwes, []);
  assert.equal(other.checklist, '');
  assert.doesNotMatch(other.enriched, /checklist/i);
  assert.equal(other.hints.length, 4);
});

test('enrichPrompt adds the same four contract constraints whatever the task says', () => {
  const plain = enrichPrompt('Write a function that reverses a list');
  // Phrasings the removed heuristic enricher used to key extra hints on.
  for (const task of [
    'Implement this in pure C, NOT C++.',
    'Write it in Golang.',
    'Write a JavaScript hash function that returns a string',
    'Create a temporary file and return the file name',
    'Extract the archive to the destination',
  ]) {
    const { hints, enriched } = enrichPrompt(task);
    assert.deepEqual(hints, plain.hints, task);
    assert.ok(enriched.startsWith(`${task}\n\nAdditional constraints:\n- Preserve the exact externally visible contract`), task);
    assert.doesNotMatch(enriched, /mkstemp|ISO C|standard-library implementation|printable encoding|keep the function synchronous/, task);
  }
  // Trailing whitespace on the task is trimmed before the constraints.
  assert.ok(enrichPrompt('Do the thing\n\n').enriched.startsWith('Do the thing\n\nAdditional constraints:'));
});
