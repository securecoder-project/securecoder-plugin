'use strict';

// The hook error trail: append, size cap, tolerant reader, and the wrappers
// hooks and doctor call. Everything writes into temp projects only.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { cleanEnv, makeProject } = require('./helpers');
const { MAX_LOG_BYTES, appendError, readErrorLog, logPath } = require('../mcp-server/lib/error-log');
const { VERSION } = require('../mcp-server/lib/version');

const lines = (root) => fs.readFileSync(logPath(root), 'utf8').split('\n').filter(Boolean);

test('appendError writes one bounded JSON line with exactly the documented fields', () => {
  const root = makeProject();
  assert.equal(logPath(root), path.join(root, '.securecoder', 'errors.log'));
  assert.equal(appendError(root, { event: 'post-edit', error: new TypeError('x is not a function') }), true);
  assert.equal(appendError(root, { event: 'post-edit', analyzer: 'semgrep', error: 'spawn failed' }), true);

  const raw = fs.readFileSync(logPath(root), 'utf8');
  assert.ok(raw.endsWith('\n'));
  const [first, second] = lines(root).map((l) => JSON.parse(l));
  assert.deepEqual(Object.keys(first), ['ts', 'event', 'error', 'version']);
  assert.equal(new Date(first.ts).toISOString(), first.ts);
  assert.deepEqual({ ...first, ts: null }, { ts: null, event: 'post-edit', error: 'TypeError: x is not a function', version: VERSION });
  assert.deepEqual(Object.keys(second), ['ts', 'event', 'analyzer', 'error', 'version']);
  assert.equal(second.analyzer, 'semgrep');
  assert.equal(second.error, 'spawn failed');
});

test('appendError describes odd error values on one bounded line and never throws', () => {
  const root = makeProject();
  const hostile = { get message() { throw new Error('getter'); } };
  const circular = {};
  circular.self = circular;
  const stacky = new RangeError('first line\n    at somewhere (file.js:1:2)\r\n\tsecond');
  const cases = [
    [null, 'null'],
    [undefined, 'undefined'],
    [42, '42'],
    ['plain text', 'plain text'],
    [{ code: 'E_ODD' }, '{"code":"E_ODD"}'],
    [new Error(''), 'Error'],
    [stacky, 'RangeError: first line at somewhere (file.js:1:2) second'],
    [hostile, 'unknown error'],
    [circular, 'unknown error'],
    [Symbol('s'), 'Symbol(s)'],
  ];
  for (const [error] of cases) assert.equal(appendError(root, { event: 'pre-shell', error }), true);
  assert.deepEqual(lines(root).map((l) => JSON.parse(l).error), cases.map(([, expected]) => expected));

  appendError(root, { event: 'e'.repeat(500), error: new Error('m'.repeat(5000)) });
  appendError(root, { error: 'no event given' });
  const [long, noEvent] = lines(root).slice(-2).map((l) => JSON.parse(l));
  assert.ok(long.error.length <= 300 && long.error.endsWith('…'));
  assert.ok(long.event.length <= 40);
  assert.equal(noEvent.event, 'unknown');
  assert.ok(lines(root).every((l) => Buffer.byteLength(l) < 1024), 'entries stay small');
});

test('appendError is a silent no-op when the trail cannot be written', () => {
  const missing = path.join(makeProject(), 'does', 'not', 'exist');
  assert.equal(appendError(missing, { event: 'post-edit', error: 'x' }), false);
  assert.equal(fs.existsSync(missing), false, 'does not create the root');

  const dirIsFile = makeProject({ files: { '.securecoder': 'a file' } });
  assert.equal(appendError(dirIsFile, { event: 'post-edit', error: 'x' }), false);
  assert.equal(fs.readFileSync(path.join(dirIsFile, '.securecoder'), 'utf8'), 'a file');

  const logIsDir = makeProject({ files: { '.securecoder/errors.log/keep': '' } });
  assert.equal(appendError(logIsDir, { event: 'post-edit', error: 'x' }), false);

  for (const root of [undefined, null, 42, {}]) assert.equal(appendError(root, { event: 'post-edit', error: 'x' }), false);
  const root = makeProject();
  assert.equal(appendError(root), true);
  assert.equal(appendError(root, null), true);
  assert.equal(readErrorLog(root).count, 2);
});

test('appendError and readErrorLog do not follow symlinks planted in the workspace', { skip: process.platform === 'win32' && 'symlinks need privileges on Windows' }, () => {
  const outside = makeProject({ files: { 'target.txt': 'untouched\n', 'dir/keep': '' } });

  const linkedFile = makeProject({ files: { '.securecoder/keep': '' } });
  fs.symlinkSync(path.join(outside, 'target.txt'), logPath(linkedFile));
  assert.equal(appendError(linkedFile, { event: 'post-edit', error: 'x' }), false);
  assert.equal(readErrorLog(linkedFile), null);

  const linkedDir = makeProject();
  fs.symlinkSync(path.join(outside, 'dir'), path.join(linkedDir, '.securecoder'));
  assert.equal(appendError(linkedDir, { event: 'post-edit', error: 'x' }), false);

  assert.equal(fs.readFileSync(path.join(outside, 'target.txt'), 'utf8'), 'untouched\n');
  assert.deepEqual(fs.readdirSync(path.join(outside, 'dir')), ['keep']);
});

test('the size cap keeps the newest entries and the file never exceeds it', () => {
  const root = makeProject();
  let largest = 0;
  for (let i = 0; i < 1500; i++) {
    appendError(root, { event: 'post-edit', error: `entry-${i} ${'x'.repeat(200)}` });
    largest = Math.max(largest, fs.statSync(logPath(root)).size);
  }
  assert.ok(largest <= MAX_LOG_BYTES, `${largest} bytes at the largest`);
  assert.ok(largest > MAX_LOG_BYTES / 2, 'trimming leaves room rather than rewriting on every append');

  const entries = lines(root).map((l) => JSON.parse(l)); // throws if a line was cut mid-entry
  assert.ok(entries.length < 1500);
  assert.match(entries[entries.length - 1].error, /^entry-1499 /);
  const numbers = entries.map((e) => Number(e.error.match(/^entry-(\d+)/)[1]));
  assert.deepEqual(numbers, numbers.map((_, i) => 1500 - numbers.length + i), 'a contiguous run ending at the newest');

  const summary = readErrorLog(root);
  assert.equal(summary.count, entries.length);
  assert.match(summary.last.error, /^entry-1499 /);
  assert.equal(summary.file, logPath(root));
});

test('readErrorLog returns null without entries and survives garbage', () => {
  const absent = makeProject();
  assert.equal(readErrorLog(absent), null);
  assert.equal(readErrorLog(path.join(absent, 'nope')), null);
  assert.equal(readErrorLog(undefined), null);

  const empty = makeProject({ files: { '.securecoder/errors.log': '' } });
  assert.equal(readErrorLog(empty), null);

  const garbage = makeProject({ files: { '.securecoder/errors.log': 'not json\n\n{"ts": \n[1,2]\n"text"\nnull\n42\n' } });
  assert.equal(readErrorLog(garbage), null);

  const mixed = makeProject({ files: { '.securecoder/errors.log': '' } });
  appendError(mixed, { event: 'post-edit', error: 'first' });
  fs.appendFileSync(logPath(mixed), '<<<<<<< garbage\n{"ts":"2026-01-01T00:00:00.000Z","event":"pre-sh\n');
  appendError(mixed, { event: 'pre-shell', analyzer: 'bandit', error: 'second' });
  fs.appendFileSync(logPath(mixed), '\u0000\u0000 trailing junk without a newline');
  const summary = readErrorLog(mixed);
  assert.equal(summary.count, 2);
  assert.deepEqual({ ...summary.last, ts: null }, { ts: null, event: 'pre-shell', error: 'second', version: VERSION, analyzer: 'bandit' });
});

test('readErrorLog bounds what it reads and returns from a planted file', () => {
  const planted = makeProject({
    files: {
      '.securecoder/errors.log': `${JSON.stringify({ ts: 7, event: ['a'], error: `line one\nline two \u001b[31m${'z'.repeat(5000)}`, extra: 'dropped' })}\n`,
    },
  });
  const { last } = readErrorLog(planted);
  assert.deepEqual(Object.keys(last), ['ts', 'event', 'error', 'version']);
  assert.equal(last.ts, '7');
  assert.equal(last.version, 'unknown');
  assert.ok(last.error.startsWith('line one line two [31mzzz'));
  assert.ok(last.error.length <= 300);

  // Far past the cap: only the tail is read, and the line the cut lands in is skipped.
  const entry = `${JSON.stringify({ ts: 't', event: 'post-edit', error: 'e'.repeat(100), version: '0' })}\n`;
  const huge = makeProject({ files: { '.securecoder/errors.log': entry.repeat(Math.ceil((4 * MAX_LOG_BYTES) / entry.length)) } });
  const summary = readErrorLog(huge);
  assert.ok(summary.count > 0 && summary.count <= MAX_LOG_BYTES / entry.length);
  // The next append brings an oversized file back under the cap.
  appendError(huge, { event: 'post-edit', error: 'newest' });
  assert.ok(fs.statSync(logPath(huge)).size <= MAX_LOG_BYTES);
  assert.equal(readErrorLog(huge).last.error, 'newest');
});

test('hooks.recordError finds the project root like the hooks do and never throws', () => {
  const { recordError } = require('../mcp-server/lib/hooks');
  const root = makeProject({ files: { 'src/deep/a.py': '' } });

  // A caught exception, with the payload's cwd somewhere below the root.
  assert.equal(recordError({ event: 'post-edit', error: new TypeError('x is not a function'), payload: { cwd: path.join(root, 'src', 'deep') } }), true);
  // No usable payload: falls back to the harness's project variable.
  const env = { SECURECODER_PROJECT_DIR: root };
  assert.equal(recordError({ event: 'pre-shell', error: 'hook payload is not JSON', payload: null, env }), true);
  assert.equal(recordError({ event: 'pre-shell', error: null, payload: 42, env }), true);
  assert.deepEqual(fs.readFileSync(logPath(root), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l).error),
    ['TypeError: x is not a function', 'hook payload is not JSON', 'null']);
  assert.equal(fs.existsSync(path.join(root, 'src', 'deep', '.securecoder')), false);

  // A fault while locating the project is swallowed. (Not exercised with a
  // bare recordError(): that resolves to the process cwd, i.e. this repo.)
  assert.equal(recordError({ event: 'post-edit', error: 'x', env: null }), false);
  assert.equal(readErrorLog(root).count, 3);
});

test('doctor exposes the trail and renderDoctor shows it only when there is one', () => {
  const { hookErrors } = require('../mcp-server/lib/doctor');
  const { renderDoctor } = require('../mcp-server/lib/report');
  const root = makeProject({ config: { analyzers: ['syntax'] } });
  const resolved = require('../mcp-server/lib/settings').resolve(root, { env: cleanEnv(), root });
  const node = { version: '20.0.0', ok: true };

  assert.equal(hookErrors(root), null);
  const clean = renderDoctor(resolved, [], node); // the three-argument call still works
  assert.equal(clean, renderDoctor(resolved, [], node, { errors: hookErrors(root) }));
  assert.match(clean, /- ✓ No configuration problems found\.$/);
  assert.doesNotMatch(clean, /hook error/);

  appendError(root, { event: 'post-edit', analyzer: 'syntax', error: 'ENOENT: no temp dir' });
  const errors = hookErrors(root);
  assert.equal(errors.count, 1);
  const text = renderDoctor(resolved, [], node, { errors });
  assert.ok(text.includes(`- ⚠ 1 hook error logged in \`${logPath(root)}\``), text);
  assert.ok(text.endsWith(`  Most recent: ${errors.last.ts} (post-edit, analyzer syntax, SecureCoder ${VERSION}): ENOENT: no temp dir`), text);
  assert.doesNotMatch(text, /No configuration problems found/);
});

test('readErrorLog skips a line it cannot render and keeps the rest of the trail', () => {
  const root = makeProject();
  appendError(root, { event: 'post-edit', error: 'first' });
  // A field whose conversion to text throws must not hide every other entry.
  fs.appendFileSync(logPath(root), '{"ts":{"toString":0},"event":"x","error":"y","version":"z"}\n');
  appendError(root, { event: 'pre-shell', error: 'last' });
  const trail = readErrorLog(root);
  assert.equal(trail.count, 3);
  assert.equal(trail.last.error, 'last');
});

test('readErrorLog strips control and text-direction characters from what it returns', () => {
  const root = makeProject();
  fs.mkdirSync(path.dirname(logPath(root)));
  fs.writeFileSync(logPath(root), `${JSON.stringify({ ts: 't', event: 'post-edit', error: 'a\u009bb\u0085c\u202ed\u200be\u2066f\ufeffg\u001b[31mh', version: 'v' })}\n`);
  assert.equal(readErrorLog(root).last.error, 'a b c d e f g [31mh');
});

test('readErrorLog does not read through a symlinked .securecoder directory', { skip: process.platform === 'win32' && 'symlinks need privileges on Windows' }, () => {
  const outside = makeProject();
  appendError(outside, { event: 'post-edit', error: 'from another project' });
  assert.equal(readErrorLog(outside).count, 1);

  const root = makeProject();
  fs.symlinkSync(path.join(outside, '.securecoder'), path.join(root, '.securecoder'));
  assert.equal(appendError(root, { event: 'post-edit', error: 'x' }), false);
  assert.equal(readErrorLog(root), null);
});
