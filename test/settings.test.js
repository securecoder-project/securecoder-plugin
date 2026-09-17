'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const settings = require('../mcp-server/lib/settings');
const { loadConfig, isExcluded, DEFAULTS } = require('../mcp-server/lib/config');
const { cleanEnv, makeProject } = require('./helpers');

const readJson = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));

test('defaults resolve with source "default" and no warnings', () => {
  const env = cleanEnv();
  const root = makeProject();
  const r = settings.resolve(root, { env });
  assert.equal(r.root, root);
  assert.equal(r.values.enabled.value, true);
  assert.equal(r.values.mode.value, 'advisory');
  assert.equal(r.values.severity_threshold.value, 'LOW');
  assert.deepEqual(r.values.analyzers.value, ['syntax', 'semgrep', 'bandit']);
  assert.ok(Object.values(r.values).every((v) => v.source === 'default'));
  assert.deepEqual(r.warnings, []);
  assert.equal(r.effective.retry.soft_limit, 7);
  assert.equal(r.effective.bins.semgrep, 'semgrep');
});

test('precedence is default < user < project < local < env', () => {
  const env = cleanEnv();
  fs.mkdirSync(env.SECURECODER_HOME, { recursive: true });
  fs.writeFileSync(path.join(env.SECURECODER_HOME, 'config.json'), JSON.stringify({ mode: 'enforce', severity_threshold: 'MEDIUM', semgrep_config: 'p/ci' }));
  const root = makeProject({ config: { severity_threshold: 'HIGH', semgrep_config: 'p/security-audit' }, local: { semgrep_config: 'auto' } });

  let r = settings.resolve(root, { env });
  assert.deepEqual(r.values.mode, { value: 'enforce', source: 'user' });
  assert.deepEqual(r.values.severity_threshold, { value: 'HIGH', source: 'project' });
  assert.deepEqual(r.values.semgrep_config, { value: 'auto', source: 'local' });

  r = settings.resolve(root, { env: { ...env, SECURECODER_MODE: 'advisory', SECURECODER_SEVERITY: 'low' } });
  assert.deepEqual(r.values.mode, { value: 'advisory', source: 'env' });
  assert.deepEqual(r.values.severity_threshold, { value: 'LOW', source: 'env' });
});

test('trusted keys from project or local config are ignored with a warning', () => {
  const env = cleanEnv();
  const root = makeProject({
    config: { bins: { semgrep: '/tmp/evil' }, codeql: { binary: '/tmp/evil', threads: 4 }, trace_log: '/tmp/x.jsonl' },
    local: { bins: { bandit: '/tmp/evil' } },
  });
  const r = settings.resolve(root, { env });
  assert.equal(r.values['bins.semgrep'].value, 'semgrep');
  assert.equal(r.values['bins.bandit'].value, 'bandit');
  assert.equal(r.values['codeql.binary'].value, 'codeql');
  assert.equal(r.values.trace_log.value, null);
  assert.deepEqual(r.values['codeql.threads'], { value: 4, source: 'project' });
  assert.equal(r.warnings.filter((w) => w.includes('only honored from user config')).length, 4);
});

test('trusted keys are honored from user config and env', () => {
  const env = cleanEnv({ CODEQL_BIN: '/opt/codeql/codeql' });
  fs.writeFileSync(path.join(env.SECURECODER_HOME, 'config.json'), JSON.stringify({ bins: { semgrep: '/opt/semgrep' } }));
  const r = settings.resolve(makeProject(), { env });
  assert.deepEqual(r.values['bins.semgrep'], { value: '/opt/semgrep', source: 'user' });
  assert.deepEqual(r.values['codeql.binary'], { value: '/opt/codeql/codeql', source: 'env' });
});

test('invalid values, unknown keys, and malformed files become warnings, not failures', () => {
  const env = cleanEnv({ SECURECODER_ENABLED: 'maybe' });
  const root = makeProject({ config: { mode: 'strict', analyzers: ['semgrep', 'eslint'], retry: { soft_limit: 20, hard_limit: 5 }, colour: 'red' } });
  fs.writeFileSync(path.join(root, '.securecoder.local.json'), '{ not json');
  const r = settings.resolve(root, { env });
  assert.equal(r.values.mode.value, 'advisory');
  assert.deepEqual(r.values.analyzers.value, ['syntax', 'semgrep', 'bandit']);
  assert.equal(r.values.enabled.value, true);
  assert.equal(r.files.local.exists, true);
  assert.ok(r.files.local.error);
  const joined = r.warnings.join('\n');
  assert.match(joined, /Invalid value for mode/);
  assert.match(joined, /unknown entry "eslint"/);
  assert.match(joined, /Unknown key "colour"/);
  assert.match(joined, /SECURECODER_ENABLED/);
  assert.match(joined, /soft_limit \(20\) is above retry.hard_limit \(5\)/);
  assert.match(joined, /Ignoring local config/);
});

test('set writes atomically to the chosen scope, keeps unknown keys, and reports precedence', () => {
  const env = cleanEnv();
  const root = makeProject({ config: { _comment: 'team', futureKey: { x: 1 } }, local: { mode: 'advisory' } });
  const result = settings.setFromText('mode', 'ENFORCE', { scope: 'project', cwd: root, env });
  assert.equal(result.value, 'enforce');
  assert.equal(result.effective.source, 'local');
  assert.ok(result.notices.some((n) => n.includes('local scope takes precedence')));
  const written = readJson(path.join(root, '.securecoder.json'));
  assert.deepEqual(written, { _comment: 'team', futureKey: { x: 1 }, mode: 'enforce' });
  assert.deepEqual(fs.readdirSync(root).filter((f) => f.endsWith('.tmp')), []);
});

test('weakening changes are flagged', () => {
  const env = cleanEnv();
  const root = makeProject();
  assert.ok(settings.setFromText('enabled', 'off', { scope: 'local', cwd: root, env }).notices.some((n) => n.startsWith('⚠')));
  assert.ok(settings.setFromText('severity', 'high', { scope: 'local', cwd: root, env }).notices.some((n) => n.includes('reduces protection')));
  assert.equal(settings.setFromText('severity', 'medium', { scope: 'local', cwd: root, env }).notices.length, 0);
  const removed = settings.modifyList('analyzers', { remove: ['bandit'] }, { scope: 'local', cwd: root, env });
  assert.ok(removed.notices.some((n) => n.includes('-bandit')));
});

test('parseValue accepts friendly spellings and rejects out-of-range input', () => {
  assert.equal(settings.parseValue('enabled', 'yes'), true);
  assert.equal(settings.parseValue('hooks.post_edit', 'OFF'), false);
  assert.equal(settings.parseValue('retry.soft_limit', '12'), 12);
  assert.deepEqual(settings.parseValue('analyzers', 'Bandit, syntax'), ['syntax', 'bandit']);
  assert.deepEqual(settings.parseValue('exclude_patterns', '["a/","*.gen.ts"]'), ['a/', '*.gen.ts']);
  assert.equal(settings.parseValue('codeql.languages', 'all'), null);
  assert.throws(() => settings.parseValue('retry.hard_limit', '500'), /out of range/);
  assert.throws(() => settings.parseValue('mode', 'strict'), /Allowed: advisory \| enforce/);
  assert.throws(() => settings.parseValue('analyzers', 'eslint'), /unknown entry/);
});

test('aliases and typo suggestions', () => {
  assert.equal(settings.canonicalKey('severity'), 'severity_threshold');
  assert.equal(settings.canonicalKey('shell-guard'), 'hooks.shell_guard');
  assert.equal(settings.canonicalKey('ruleset'), 'semgrep_config');
  assert.throws(() => settings.requireKey('severty_threshold'), /Did you mean "severity_threshold"/);
});

test('trusted keys cannot be written outside user scope', () => {
  const env = cleanEnv();
  const root = makeProject();
  assert.throws(() => settings.setFromText('bins.semgrep', '/x', { scope: 'project', cwd: root, env }), (err) => err.code === 'trusted_key');
  const ok = settings.setFromText('bins.semgrep', '/opt/semgrep', { scope: 'user', cwd: root, env });
  assert.equal(ok.effective.value, '/opt/semgrep');
});

test('modifyList extends the effective value when the scope has no entry yet', () => {
  const env = cleanEnv();
  const root = makeProject();
  const r = settings.modifyList('exclude', { add: ['build/'] }, { scope: 'local', cwd: root, env });
  assert.deepEqual(r.value, [...DEFAULTS.exclude_patterns, 'build/']);
  const again = settings.modifyList('exclude', { add: ['build/'], remove: ['nope/'] }, { scope: 'local', cwd: root, env });
  assert.deepEqual(again.value, [...DEFAULTS.exclude_patterns, 'build/']);
  assert.ok(again.notices[0].includes('nope/'));
});

test('unset prunes empty parents; reset keeps comments and unknown keys', () => {
  const env = cleanEnv();
  const root = makeProject({ local: { _comment: 'mine', retry: { soft_limit: 3 }, mode: 'enforce', extra: true } });
  const u = settings.unset('retry.soft_limit', { scope: 'local', cwd: root, env });
  assert.equal(u.removed, true);
  assert.deepEqual(readJson(path.join(root, '.securecoder.local.json')), { _comment: 'mine', mode: 'enforce', extra: true });
  const r = settings.reset({ scope: 'local', cwd: root, env });
  assert.deepEqual(r.removed, ['mode']);
  assert.ok(r.notices.some((n) => n.includes('mode is now advisory')));
  assert.deepEqual(readJson(path.join(root, '.securecoder.local.json')), { _comment: 'mine', extra: true });
});

test('writes refuse to clobber a malformed config file', () => {
  const env = cleanEnv();
  const root = makeProject();
  fs.writeFileSync(path.join(root, '.securecoder.json'), '{ broken');
  assert.throws(() => settings.setFromText('mode', 'enforce', { scope: 'project', cwd: root, env }), (err) => err.code === 'malformed_file');
  assert.equal(fs.readFileSync(path.join(root, '.securecoder.json'), 'utf8'), '{ broken');
});

test('init refuses to overwrite; gitignore helper is idempotent', () => {
  const env = cleanEnv();
  const root = makeProject();
  settings.init({ scope: 'project', cwd: root, env });
  assert.equal(readJson(path.join(root, '.securecoder.json')).mode, 'advisory');
  assert.throws(() => settings.init({ scope: 'project', cwd: root, env }), (err) => err.code === 'exists');
  assert.equal(settings.ensureLocalGitignored(root).changed, true);
  assert.equal(settings.ensureLocalGitignored(root).changed, false);
  assert.equal(fs.readFileSync(path.join(root, '.gitignore'), 'utf8'), '.securecoder.local.json\n');
});

test('project root is found from a subdirectory; default scope follows it', () => {
  const root = makeProject({ files: { 'src/deep/a.py': 'x = 1\n' } });
  assert.equal(settings.findProjectRoot(path.join(root, 'src', 'deep')), root);
  assert.equal(settings.defaultScope(path.join(root, 'src')), 'local');
});

test('loadConfig and isExcluded keep the pipeline contract', () => {
  const env = cleanEnv();
  const root = makeProject({ config: { exclude_patterns: ['vendor/', '*.min.js'] } });
  const saved = process.env.SECURECODER_HOME;
  process.env.SECURECODER_HOME = env.SECURECODER_HOME;
  try {
    const config = loadConfig(root);
    assert.deepEqual(config.exclude_patterns, ['vendor/', '*.min.js']);
    assert.equal(isExcluded('vendor/lib.py', config), true);
    assert.equal(isExcluded(path.join('src', 'vendor', 'lib.py'), config), true);
    assert.equal(isExcluded('src/app.min.js', config), true);
    assert.equal(isExcluded('src/myvendor/lib.py', config), false);
    assert.equal(isExcluded('src/app.js', config), false);
  } finally {
    if (saved === undefined) delete process.env.SECURECODER_HOME;
    else process.env.SECURECODER_HOME = saved;
  }
});
