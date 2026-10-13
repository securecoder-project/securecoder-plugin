'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const settings = require('../mcp-server/lib/settings');
const { loadConfig, isExcluded, DEFAULTS } = require('../mcp-server/lib/config');
const { ROOT, cleanEnv, makeProject, runNode } = require('./helpers');

const readJson = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
const writeUserConfig = (env, data) => fs.writeFileSync(path.join(env.SECURECODER_HOME, 'config.json'), JSON.stringify(data));
const floorWarnings = (r) => r.warnings.filter((w) => w.includes('never weaken it'));

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
    config: { bins: { semgrep: '/tmp/evil' }, codeql: { binary: '/tmp/evil', timeout_seconds: 120 }, trace_log: '/tmp/x.jsonl' },
    local: { bins: { bandit: '/tmp/evil' } },
  });
  const r = settings.resolve(root, { env });
  assert.equal(r.values['bins.semgrep'].value, 'semgrep');
  assert.equal(r.values['bins.bandit'].value, 'bandit');
  assert.equal(r.values['codeql.binary'].value, 'codeql');
  assert.equal(r.values.trace_log.value, null);
  assert.deepEqual(r.values['codeql.timeout_seconds'], { value: 120, source: 'project' });
  assert.equal(r.warnings.filter((w) => w.includes('only honored from user config')).length, 4);
});

test('trusted keys are honored from user config and env', () => {
  const env = cleanEnv({ CODEQL_BIN: '/opt/codeql/codeql' });
  fs.writeFileSync(path.join(env.SECURECODER_HOME, 'config.json'), JSON.stringify({ bins: { semgrep: '/opt/semgrep' }, codeql: { binary: '/usr/local/bin/codeql' } }));
  const r = settings.resolve(makeProject(), { env });
  assert.deepEqual(r.values['bins.semgrep'], { value: '/opt/semgrep', source: 'user' });
  assert.deepEqual(r.values['codeql.binary'], { value: '/opt/codeql/codeql', source: 'env' });
  const { CODEQL_BIN, ...withoutEnv } = env;
  assert.deepEqual(settings.resolve(makeProject(), { env: withoutEnv }).values['codeql.binary'], { value: '/usr/local/bin/codeql', source: 'user' });
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

test('a repository file cannot turn enabled off', () => {
  const env = cleanEnv();
  for (const scope of ['project', 'local']) {
    const root = makeProject(scope === 'project' ? { config: { enabled: false } } : { local: { enabled: false } });
    const r = settings.resolve(root, { env });
    assert.deepEqual(r.values.enabled, { value: true, source: 'default' });
    assert.equal(r.effective.enabled, true);
    assert.deepEqual(r.warnings, [
      `Ignoring "enabled" = off from ${scope} config: a file inside the repository may strengthen this setting but never weaken it. Set it in user config or $SECURECODER_ENABLED instead.`,
    ]);
  }
});

test('a repository file cannot lower mode from a user-level enforce', () => {
  const env = cleanEnv();
  writeUserConfig(env, { mode: 'enforce' });
  for (const scope of ['project', 'local']) {
    const root = makeProject(scope === 'project' ? { config: { mode: 'advisory' } } : { local: { mode: 'advisory' } });
    const r = settings.resolve(root, { env });
    assert.deepEqual(r.values.mode, { value: 'enforce', source: 'user' });
    assert.deepEqual(r.warnings, [
      `Ignoring "mode" = advisory from ${scope} config: a file inside the repository may strengthen this setting but never weaken it. Set it in user config or $SECURECODER_MODE instead.`,
    ]);
  }
});

test('a repository file may strengthen enabled and mode', () => {
  const env = cleanEnv();
  let r = settings.resolve(makeProject({ config: { enabled: true, mode: 'enforce' } }), { env });
  assert.deepEqual(r.values.enabled, { value: true, source: 'project' });
  assert.deepEqual(r.values.mode, { value: 'enforce', source: 'project' });
  assert.deepEqual(r.warnings, []);

  writeUserConfig(env, { enabled: false });
  r = settings.resolve(makeProject({ config: { enabled: true } }), { env });
  assert.deepEqual(r.values.enabled, { value: true, source: 'project' });
  // Restating a user-level "off" weakens nothing, so it is honored as before.
  r = settings.resolve(makeProject({ local: { enabled: false } }), { env });
  assert.deepEqual(r.values.enabled, { value: false, source: 'local' });
  assert.deepEqual(r.warnings, []);
});

test('the floor is default < user: local may undo what the project strengthened', () => {
  const env = cleanEnv();
  const root = makeProject({ config: { mode: 'enforce' }, local: { mode: 'advisory' } });
  let r = settings.resolve(root, { env });
  assert.deepEqual(r.values.mode, { value: 'advisory', source: 'local' });
  assert.deepEqual(r.warnings, []);

  // With a user-level enforce the same local value is below the floor, and the
  // project value stays the reported source.
  writeUserConfig(env, { mode: 'enforce' });
  r = settings.resolve(root, { env });
  assert.deepEqual(r.values.mode, { value: 'enforce', source: 'project' });
  assert.equal(floorWarnings(r).length, 1);
  assert.match(floorWarnings(r)[0], /"mode" = advisory from local config/);
});

test('an invalid kill-switch value gets the invalid-value warning, not the floor warning', () => {
  const r = settings.resolve(makeProject({ config: { enabled: 'off', mode: 'off' } }), { env: cleanEnv() });
  assert.deepEqual(r.values.enabled, { value: true, source: 'default' });
  assert.equal(r.warnings.length, 2);
  assert.ok(r.warnings.every((w) => /^Invalid value for (enabled|mode)/.test(w) && w.endsWith('(in project config; ignored)')));
});

test('the shipped example config resolves without warnings', () => {
  const example = readJson(path.join(ROOT, 'examples', 'securecoder.json'));
  assert.equal(example.enabled, true);
  assert.equal(example.mode, 'advisory');
  assert.deepEqual(example.codeql, { timeout_seconds: 600 });
  const r = settings.resolve(makeProject({ config: example }), { env: cleanEnv() });
  assert.deepEqual(r.warnings, []);
  assert.deepEqual(r.values.enabled, { value: true, source: 'project' });
  assert.deepEqual(r.values.mode, { value: 'advisory', source: 'project' });
});

test('severity_threshold, analyzers and exclude_patterns can still be weakened from project config', () => {
  const env = cleanEnv();
  writeUserConfig(env, { severity_threshold: 'LOW', analyzers: ['syntax', 'semgrep', 'bandit'], exclude_patterns: ['tests/'] });
  const r = settings.resolve(makeProject({ config: { severity_threshold: 'HIGH', analyzers: ['syntax'], exclude_patterns: ['tests/', 'src/'] } }), { env });
  assert.deepEqual(r.values.severity_threshold, { value: 'HIGH', source: 'project' });
  assert.deepEqual(r.values.analyzers, { value: ['syntax'], source: 'project' });
  assert.deepEqual(r.values.exclude_patterns, { value: ['tests/', 'src/'], source: 'project' });
  assert.deepEqual(r.warnings, []);
});

test('environment variables still override enabled and mode in both directions', () => {
  const env = cleanEnv();
  writeUserConfig(env, { mode: 'enforce' });
  const root = makeProject({ config: { enabled: true } });
  const r = settings.resolve(root, { env: { ...env, SECURECODER_ENABLED: 'off', SECURECODER_MODE: 'advisory' } });
  assert.deepEqual(r.values.enabled, { value: false, source: 'env' });
  assert.deepEqual(r.values.mode, { value: 'advisory', source: 'env' });
  assert.deepEqual(r.warnings, []);
});

test('set refuses a repository-scope write that the floor rule would ignore', () => {
  const env = cleanEnv();
  const root = makeProject();
  const refused = (key, value, scope) => {
    let caught;
    try { settings.setFromText(key, value, { scope, cwd: root, env }); } catch (err) { caught = err; }
    assert.ok(caught instanceof settings.SettingsError, `${key} ${value} in ${scope} scope was not refused`);
    assert.equal(caught.code, 'weakens_floor');
    return caught.message;
  };

  assert.equal(refused('enabled', 'off', 'local'),
    '"enabled" cannot be turned off from local config: a file inside the repository may strengthen this setting but never weaken it. Use --scope user (applies to all your projects) or the $SECURECODER_ENABLED environment variable.');
  assert.match(refused('enabled', 'off', 'project'), /cannot be turned off from project config/);
  assert.equal(fs.existsSync(path.join(root, '.securecoder.local.json')), false);
  assert.equal(fs.existsSync(path.join(root, '.securecoder.json')), false);

  // Allowed: strengthening, and advisory while the floor is advisory.
  assert.deepEqual(settings.setFromText('enabled', 'on', { scope: 'local', cwd: root, env }).effective, { value: true, source: 'local' });
  assert.deepEqual(settings.setFromText('mode', 'enforce', { scope: 'project', cwd: root, env }).effective, { value: 'enforce', source: 'project' });
  const undo = settings.setFromText('mode', 'advisory', { scope: 'local', cwd: root, env });
  assert.deepEqual(undo.effective, { value: 'advisory', source: 'local' });
  assert.ok(undo.notices.some((n) => n.includes('reduces protection')));

  // Once the user-level mode is enforce, the same local write is refused and
  // the file keeps what it had.
  settings.setFromText('mode', 'enforce', { scope: 'user', cwd: root, env });
  const localFile = path.join(root, '.securecoder.local.json');
  fs.writeFileSync(localFile, JSON.stringify({ enabled: true }));
  assert.equal(refused('mode', 'advisory', 'local'),
    '"mode" cannot be lowered to advisory from local config: a file inside the repository may strengthen this setting but never weaken it. Use --scope user (applies to all your projects) or the $SECURECODER_MODE environment variable.');
  assert.deepEqual(readJson(localFile), { enabled: true });
});

test('user-scope writes are never refused and keep the reduces-protection notice', () => {
  const env = cleanEnv();
  const root = makeProject();
  const off = settings.setFromText('enabled', 'off', { scope: 'user', cwd: root, env });
  assert.equal(readJson(off.file).enabled, false);
  assert.deepEqual(off.effective, { value: false, source: 'user' });
  assert.deepEqual(off.notices, ['⚠ This reduces protection: enabled changed from on to off.']);
  // With the floor now off, repeating it in the repository weakens nothing.
  assert.deepEqual(settings.setFromText('enabled', 'off', { scope: 'local', cwd: root, env }).effective, { value: false, source: 'local' });

  // A project that strengthens the setting still wins over the user-level off, and the note says so.
  const strengthened = makeProject({ config: { enabled: true } });
  const again = settings.setFromText('enabled', 'off', { scope: 'user', cwd: strengthened, env });
  assert.deepEqual(again.effective, { value: true, source: 'project' });
  assert.deepEqual(again.notices, ['Note: enabled is still on because the project scope takes precedence over user.']);
});

test('cli: a refused write exits 2 with the reason and writes nothing', () => {
  const env = cleanEnv();
  const root = makeProject();
  const r = runNode(path.join(ROOT, 'bin', 'securecoder'), ['config', 'set', 'enabled', 'off'], { env, cwd: root });
  assert.equal(r.status, 2);
  assert.equal(r.stdout, '');
  assert.match(r.stderr, /^securecoder: "enabled" cannot be turned off from local config: .*--scope user .*\$SECURECODER_ENABLED environment variable\.\n$/);
  assert.equal(fs.existsSync(path.join(root, '.securecoder.local.json')), false);
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
  // enabled can only be turned off from user scope; the ⚠ notice still applies there.
  assert.ok(settings.setFromText('enabled', 'off', { scope: 'user', cwd: root, env }).notices.some((n) => n.startsWith('⚠')));
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
  // No kill switch in the starter file: a `mode` there would be ignored, with
  // a warning on every run, for anyone whose user config says enforce.
  const starter = readJson(path.join(root, '.securecoder.json'));
  assert.equal(starter.severity_threshold, 'LOW');
  assert.equal('mode' in starter, false);
  assert.equal('enabled' in starter, false);
  writeUserConfig(env, { mode: 'enforce' });
  assert.deepEqual(settings.resolve(root, { env }).warnings, []);
  fs.rmSync(path.join(env.SECURECODER_HOME, 'config.json'));
  assert.throws(() => settings.init({ scope: 'project', cwd: root, env }), (err) => err.code === 'exists');
  const gitignore = path.join(root, '.gitignore');
  assert.deepEqual(settings.ensureLocalGitignored(root), { file: gitignore, changed: true, added: ['.securecoder.local.json', '.securecoder/'], present: [] });
  assert.deepEqual(settings.ensureLocalGitignored(root), { file: gitignore, changed: false, added: [], present: ['.securecoder.local.json', '.securecoder/'] });
  assert.equal(fs.readFileSync(gitignore, 'utf8'), '.securecoder.local.json\n.securecoder/\n');
});

test('gitignore helper adds only the missing entry and keeps existing content', () => {
  const gitignore = (root) => path.join(root, '.gitignore');

  // Only the personal config is ignored so far, and the file lacks a final newline.
  let root = makeProject();
  fs.writeFileSync(gitignore(root), 'node_modules/\n/.securecoder.local.json');
  let r = settings.ensureLocalGitignored(root);
  assert.deepEqual([r.changed, r.added, r.present], [true, ['.securecoder/'], ['.securecoder.local.json']]);
  assert.equal(fs.readFileSync(gitignore(root), 'utf8'), 'node_modules/\n/.securecoder.local.json\n.securecoder/\n');

  // Every spelling of the directory entry counts as present.
  for (const spelling of ['.securecoder', '.securecoder/', '/.securecoder', '/.securecoder/']) {
    root = makeProject();
    fs.writeFileSync(gitignore(root), `# local state\r\n${spelling}\r\n`);
    r = settings.ensureLocalGitignored(root);
    assert.deepEqual([r.changed, r.added, r.present], [true, ['.securecoder.local.json'], ['.securecoder/']], spelling);
    assert.equal(fs.readFileSync(gitignore(root), 'utf8'), `# local state\r\n${spelling}\r\n.securecoder.local.json\n`);
    assert.equal(settings.ensureLocalGitignored(root).changed, false);
  }

  // A different path that merely starts the same way is not a match.
  root = makeProject();
  fs.writeFileSync(gitignore(root), '.securecoder.json\n.securecoder/errors.log\n');
  assert.deepEqual(settings.ensureLocalGitignored(root).added, ['.securecoder.local.json', '.securecoder/']);
});

test('cli: config gitignore says which entries it added', () => {
  const env = cleanEnv();
  const root = makeProject();
  fs.writeFileSync(path.join(root, '.gitignore'), '.securecoder.local.json\n');
  const cli = () => runNode(path.join(ROOT, 'bin', 'securecoder'), ['config', 'gitignore'], { env, cwd: root });
  let r = cli();
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, `✓ Added .securecoder/ to ${path.join(root, '.gitignore')}\n`);
  r = cli();
  assert.equal(r.stdout, `.securecoder.local.json and .securecoder/ are already ignored in ${path.join(root, '.gitignore')}\n`);
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

// ── settings removed in 0.3.0 ────────────────────────────────────────────────
// The warn-and-ignore tests below go when REMOVED_KEYS leaves settings.js.

const REMOVED = ['codeql.languages', 'codeql.query_packs', 'codeql.threads', 'codeql.ram_mb'];
const removedWarning = (key, scope) => `"${key}" in ${scope} config was removed in SecureCoder 0.3.0 and is ignored. Delete it from the file to silence this warning.`;

test('a config file that still sets a removed CodeQL key gets one warning per key and resolves normally', () => {
  const env = cleanEnv();
  writeUserConfig(env, { codeql: { threads: 8, binary: '/opt/codeql/codeql' } });
  const root = makeProject({
    config: { mode: 'enforce', codeql: { languages: null, query_packs: { python: ['my/pack'], go: [] }, threads: 4, ram_mb: 4096, timeout_seconds: 120 } },
    local: { codeql: { query_packs: {}, languages: ['python'] } },
  });
  const r = settings.resolve(root, { env });
  assert.deepEqual(r.warnings, [
    removedWarning('codeql.threads', 'user'),
    removedWarning('codeql.languages', 'project'),
    removedWarning('codeql.query_packs', 'project'),
    removedWarning('codeql.threads', 'project'),
    removedWarning('codeql.ram_mb', 'project'),
    removedWarning('codeql.query_packs', 'local'),
    removedWarning('codeql.languages', 'local'),
  ]);

  // Everything else in those files still applies, and nothing of the removed keys survives.
  assert.deepEqual(r.values.mode, { value: 'enforce', source: 'project' });
  assert.deepEqual(r.values['codeql.timeout_seconds'], { value: 120, source: 'project' });
  assert.deepEqual(r.values['codeql.binary'], { value: '/opt/codeql/codeql', source: 'user' });
  assert.deepEqual(r.effective.codeql, { timeout_seconds: 120, binary: '/opt/codeql/codeql' });
  assert.deepEqual(DEFAULTS.codeql, { timeout_seconds: 600, binary: 'codeql' });
  for (const key of REMOVED) assert.equal(key in r.values, false, key);
});

test('a key that only looks like a removed one is still an ordinary unknown key', () => {
  const r = settings.resolve(makeProject({ config: { threads: 4, codeql: { thread: 4, query_pack: { python: ['x'] } } } }), { env: cleanEnv() });
  assert.deepEqual(r.warnings, [
    'Unknown key "threads" in project config (ignored).',
    'Unknown key "codeql.thread" in project config (ignored).',
    'Unknown key "codeql.query_pack.python" in project config (ignored).',
  ]);
});

test('the removed CodeQL keys are gone from the schema, config keys, and the object type with them', () => {
  const { renderKeys } = require('../mcp-server/lib/report');
  const keys = renderKeys();
  for (const key of REMOVED) {
    assert.equal(key in settings.SCHEMA, false, key);
    assert.equal(keys.includes(key), false, key);
  }
  assert.deepEqual(Object.keys(settings.SCHEMA).filter((k) => k.startsWith('codeql.')), ['codeql.timeout_seconds', 'codeql.binary']);
  assert.match(keys, /\| `codeql\.timeout_seconds` \| integer 30–14400 \| 600 \|/);
  assert.match(keys, /\| `codeql\.binary` \| text \| codeql \|/);
  assert.deepEqual([...new Set(Object.values(settings.SCHEMA).map((spec) => spec.type))].sort(), ['boolean', 'enum', 'integer', 'list', 'set', 'string']);
  assert.equal(keys.includes('JSON object'), false);
  assert.equal(keys.includes('(or "all")'), false);
  assert.equal(fs.readFileSync(path.join(ROOT, 'mcp-server', 'lib', 'settings.js'), 'utf8').includes("type: 'object'"), false);
});

test('trace_log is still the one setting that can be cleared to null', () => {
  assert.equal(settings.describeAllowed(settings.SCHEMA.trace_log), 'text (or "null")');
  for (const word of ['null', 'none', 'default', 'NONE', ' Null ']) assert.equal(settings.parseValue('trace_log', word), null, word);
  assert.equal(settings.parseValue('trace_log', '/tmp/trace.jsonl'), '/tmp/trace.jsonl');
  // "all" meant "every language" for the removed codeql.languages; here it is a file name.
  assert.equal(settings.parseValue('trace_log', 'all'), 'all');
  assert.equal(settings.validate('trace_log', null), null);
  assert.equal(settings.validate('trace_log', '/tmp/trace.jsonl'), '/tmp/trace.jsonl');
  assert.throws(() => settings.validate('trace_log', ''), /expected non-empty text\. Allowed: text \(or "null"\)\./);
  // No other setting accepts null, from a file or from typed text.
  assert.throws(() => settings.validate('analyzers', null), /expected an array\. Allowed: comma-separated subset of: syntax, semgrep, bandit\.$/);
  assert.equal(settings.parseValue('semgrep_config', 'none'), 'none');

  const env = cleanEnv();
  const root = makeProject();
  settings.setFromText('trace_log', '/tmp/trace.jsonl', { scope: 'user', cwd: root, env });
  assert.deepEqual(settings.resolve(root, { env }).values.trace_log, { value: '/tmp/trace.jsonl', source: 'user' });
  assert.equal(settings.setFromText('trace_log', 'none', { scope: 'user', cwd: root, env }).value, null);
  assert.equal(settings.resolve(root, { env }).effective.trace_log, null);
  assert.deepEqual(settings.resolve(root, { env: { ...env, SECURECODER_TRACE_LOG: 'null' } }).values.trace_log, { value: null, source: 'env' });
});

test('a removed key cannot be written, read, or unset, and says why', () => {
  const env = cleanEnv();
  const stale = { codeql: { threads: 4 } };
  const root = makeProject({ local: stale });
  const refused = (fn) => {
    let caught;
    try { fn(); } catch (err) { caught = err; }
    assert.ok(caught instanceof settings.SettingsError);
    assert.equal(caught.code, 'unknown_key');
    return caught.message;
  };
  const message = (key) => `Unknown setting "${key}": it was removed in SecureCoder 0.3.0 and no longer has any effect. Run "securecoder config keys" to list settings.`;

  assert.equal(refused(() => settings.setFromText('codeql.threads', '4', { scope: 'local', cwd: root, env })), message('codeql.threads'));
  assert.equal(refused(() => settings.set('codeql.query_packs', {}, { scope: 'user', cwd: root, env })), message('codeql.query_packs'));
  assert.equal(refused(() => settings.modifyList('codeql.languages', { add: ['python'] }, { scope: 'local', cwd: root, env })), message('codeql.languages'));
  assert.equal(refused(() => settings.unset('codeql.threads', { scope: 'local', cwd: root, env })), message('codeql.threads'));
  assert.equal(refused(() => settings.requireKey('codeql.ram-mb')), message('codeql.ram-mb'));
  // A near miss gets the ordinary message, and no suggestion that points somewhere unrelated.
  for (const key of ['threads', 'ram_mb', 'languages', 'query_packs', 'codeql.thread']) {
    assert.equal(refused(() => settings.requireKey(key)), `Unknown setting "${key}". Run "securecoder config keys" to list settings.`);
  }
  assert.deepEqual(readJson(path.join(root, '.securecoder.local.json')), stale);
  assert.equal(fs.existsSync(path.join(env.SECURECODER_HOME, 'config.json')), false);

  const cli = runNode(path.join(ROOT, 'bin', 'securecoder'), ['config', 'set', 'codeql.threads', '4'], { env, cwd: root });
  assert.equal(cli.status, 2);
  assert.equal(cli.stdout, '');
  assert.equal(cli.stderr, `securecoder: ${message('codeql.threads')}\n`);
  assert.deepEqual(readJson(path.join(root, '.securecoder.local.json')), stale);
});

test('reset treats a removed key like any other key it does not know: kept, and still warned about', () => {
  const env = cleanEnv();
  const root = makeProject({ config: { mode: 'enforce', codeql: { threads: 4, query_packs: { go: ['x'] }, timeout_seconds: 60 } } });
  const r = settings.reset({ scope: 'project', cwd: root, env });
  assert.deepEqual(r.removed, ['mode', 'codeql.timeout_seconds']);
  assert.deepEqual(readJson(path.join(root, '.securecoder.json')), { codeql: { threads: 4, query_packs: { go: ['x'] } } });
  assert.deepEqual(settings.resolve(root, { env }).warnings, [removedWarning('codeql.threads', 'project'), removedWarning('codeql.query_packs', 'project')]);
});

test('SECURECODER_CONFIG replaces the project file and stays project scope', () => {
  const root = makeProject({
    config: { severity_threshold: 'HIGH' },
    files: { 'ci/securecoder.json': JSON.stringify({ severity_threshold: 'MEDIUM', enabled: false, bins: { semgrep: '/tmp/evil' } }) },
  });
  const env = cleanEnv({ SECURECODER_CONFIG: 'ci/securecoder.json' });
  const r = settings.resolve(root, { env });
  // A relative path is resolved against the project root, and .securecoder.json is not read.
  assert.equal(r.files.project.path, path.join(root, 'ci', 'securecoder.json'));
  assert.deepEqual(r.values.severity_threshold, { value: 'MEDIUM', source: 'project' });
  // Still a repository file: no trusted keys, and the kill switches keep their floor.
  assert.deepEqual(r.values['bins.semgrep'], { value: 'semgrep', source: 'default' });
  assert.deepEqual(r.values.enabled, { value: true, source: 'default' });
  assert.equal(r.warnings.filter((w) => /"bins\.semgrep" from project config/.test(w)).length, 1);
  assert.equal(r.warnings.filter((w) => /Ignoring "enabled" = off from project config/.test(w)).length, 1);
});

test('a config path that is not a small regular file is reported, never read', { skip: process.platform === 'win32' && 'needs mkfifo' }, () => {
  const { execFileSync } = require('child_process');
  const env = cleanEnv();
  const root = makeProject({ config: { mode: 'enforce' } });
  // A FIFO would block a synchronous read for good, and with it every hook.
  execFileSync('mkfifo', [path.join(root, '.securecoder.local.json')]);
  const r = settings.resolve(root, { env });
  assert.equal(r.files.local.error, 'not a regular file');
  assert.equal(r.warnings.filter((w) => w.includes('.securecoder.local.json: not a regular file')).length, 1);
  assert.deepEqual(r.values.mode, { value: 'enforce', source: 'project' });

  // The hook answers at once with the FIFO in place.
  const started = Date.now();
  const hook = runNode(path.join(ROOT, 'hooks', 'securecoder-hook.js'), ['user-prompt'], { input: JSON.stringify({ cwd: root, prompt: 'hi' }), env, cwd: root });
  assert.equal(hook.status, 0, hook.stderr);
  assert.match(hook.stdout, /"hookEventName":"UserPromptSubmit"/);
  assert.ok(Date.now() - started < 5000);
  assert.throws(() => settings.set('mode', 'enforce', { scope: 'local', cwd: root, env }), (err) => err.code === 'malformed_file');

  // So would a file far larger than any config.
  const big = makeProject();
  fs.writeFileSync(path.join(big, '.securecoder.json'), `{"mode":"enforce"}${' '.repeat(1024 * 1024)}`);
  const rb = settings.resolve(big, { env });
  assert.match(rb.files.project.error, /^larger than 1024 KiB$/);
  assert.deepEqual(rb.values.mode, { value: 'advisory', source: 'default' });
});
