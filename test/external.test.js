'use strict';

// semgrep and bandit adapters, against stub binaries: a run that produced no
// report is that analyzer's failure, never "no findings".

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ROOT, cleanEnv, makeProject, runNode } = require('./helpers');
const { runBandit, runSemgrep } = require('../mcp-server/lib/external');
const { analyze } = require('../mcp-server/lib/analyze');
const settings = require('../mcp-server/lib/settings');
const { readErrorLog } = require('../mcp-server/lib/error-log');

const NO_STUB = process.platform === 'win32' && 'needs a POSIX shell for the stub binaries';
const HOOK = path.join(ROOT, 'hooks', 'securecoder-hook.js');
const CLI = path.join(ROOT, 'bin', 'securecoder');

function stub(body) {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-stub-')), 'analyzer');
  fs.writeFileSync(file, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  return file;
}

const CRASH = stub('echo "Traceback (most recent call last):" >&2; echo "  boom" >&2; exit 2');
const EMPTY_REPORT = stub('echo \'{"results": []}\'');
const FILES = (root) => [{ abs: path.join(root, 'app.py'), rel: 'app.py', content: 'x = 1\n' }];

test('a crash, a timeout, or anything but a JSON report is a failure', { skip: NO_STUB }, async () => {
  const files = FILES(makeProject({ files: { 'app.py': 'x = 1\n' } }));
  await assert.rejects(runSemgrep(files, { binary: CRASH }), /^Error: semgrep exited with code 2 without a JSON report: Traceback \(most recent call last\):$/);
  await assert.rejects(runBandit(files, { binary: CRASH }), /^Error: bandit exited with code 2 without a JSON report: Traceback/);
  await assert.rejects(runSemgrep(files, { binary: stub('exit 0') }), /without a JSON report: no output$/);
  const slow = stub('sleep 5');
  await assert.rejects(runSemgrep(files, { binary: slow, timeoutMs: 200 }), /^Error: semgrep timed out after 200ms$/);
  await assert.rejects(runBandit(files, { binary: slow, timeoutMs: 200 }), /^Error: bandit timed out after 200ms$/);
});

test('a semgrep report that carries a fatal error and no results is a failure', { skip: NO_STUB }, async () => {
  const files = FILES(makeProject({ files: { 'app.py': 'x = 1\n' } }));
  // What semgrep prints when the ruleset cannot be fetched (exit 7).
  const report = JSON.stringify({ results: [], errors: [{ code: 2, level: 'error', type: 'SemgrepError', message: 'Failed to download configuration from https://semgrep.dev/c/p/x HTTP 404.' }] });
  await assert.rejects(runSemgrep(files, { binary: stub(`echo '${report}'; exit 7`) }), /^Error: semgrep exited with code 7: Failed to download configuration from https:\/\/semgrep\.dev\/c\/p\/x HTTP 404\.$/);
  // The same report with exit 0, or errors next to real results, is not fatal.
  assert.deepEqual(await runSemgrep(files, { binary: stub(`echo '${report}'`) }), []);
  const partial = JSON.stringify({ results: [{ check_id: 'r', path: files[0].abs, start: { line: 1 }, end: { line: 1 }, extra: { message: 'm', severity: 'ERROR' } }], errors: [{ message: 'one rule timed out' }] });
  assert.deepEqual((await runSemgrep(files, { binary: stub(`echo '${partial}'; exit 2`) })).map((v) => v.rule.id), ['r']);
});

test('an empty report is clean, and a binary that is not installed disables the analyzer quietly', { skip: NO_STUB }, async () => {
  const files = FILES(makeProject({ files: { 'app.py': 'x = 1\n' } }));
  assert.deepEqual(await runSemgrep(files, { binary: EMPTY_REPORT }), []);
  assert.deepEqual(await runBandit(files, { binary: EMPTY_REPORT }), []);
  assert.deepEqual(await runSemgrep(files, { binary: 'securecoder-missing-semgrep' }), []);
  assert.deepEqual(await runBandit(files, { binary: 'securecoder-missing-bandit' }), []);
  // bandit is only run on Python files.
  assert.deepEqual(await runBandit([{ abs: '/x/a.js', rel: 'a.js', content: '' }], { binary: CRASH }), []);
});

test('a crashing analyzer is reported by the scan, the hook trail and doctor instead of reading as clean', { skip: NO_STUB }, async () => {
  const root = makeProject({ files: { 'app.py': 'x = 1\n' }, config: { analyzers: ['semgrep', 'bandit'] } });
  const env = cleanEnv({ SEMGREP_BIN: CRASH, BANDIT_BIN: CRASH });

  const config = settings.resolve(root, { env, root }).effective;
  const result = await analyze({ filePaths: ['app.py'], projectRoot: root, config });
  assert.deepEqual(result.violations, []);
  assert.deepEqual(result.failures.map((f) => f.guardian).sort(), ['bandit', 'semgrep']);

  const scan = runNode(CLI, ['scan', 'app.py'], { env, cwd: root });
  assert.equal(scan.status, 0, scan.stderr);
  assert.match(scan.stdout, /\(Analyzer semgrep failed: semgrep exited with code 2 without a JSON report: Traceback/);
  assert.match(scan.stdout, /\(Analyzer bandit failed: bandit exited with code 2/);

  // The post-edit hook still fails open, and now leaves a trail.
  const hook = runNode(HOOK, ['post-edit'], { input: JSON.stringify({ cwd: root, tool_input: { file_path: path.join(root, 'app.py') } }), env, cwd: root });
  assert.equal(hook.status, 0, hook.stderr);
  assert.equal(hook.stdout, '');
  const trail = readErrorLog(root);
  assert.equal(trail.count, 2);
  assert.deepEqual([trail.last.event, ['bandit', 'semgrep'].includes(trail.last.analyzer)], ['post-edit', true]);
  assert.match(runNode(CLI, ['doctor'], { env, cwd: root }).stdout, /2 hook errors logged in/);

  // Not installed is not a fault: nothing is logged for it.
  const quiet = makeProject({ files: { 'app.py': 'x = 1\n' }, config: { analyzers: ['semgrep', 'bandit'] } });
  const missing = cleanEnv({ SEMGREP_BIN: 'securecoder-missing-semgrep', BANDIT_BIN: 'securecoder-missing-bandit' });
  const silent = runNode(HOOK, ['post-edit'], { input: JSON.stringify({ cwd: quiet, tool_input: { file_path: path.join(quiet, 'app.py') } }), env: missing, cwd: quiet });
  assert.equal(silent.status, 0);
  assert.equal(readErrorLog(quiet), null);
});
