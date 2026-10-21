'use strict';

// The per-prompt constraint injection: the `user-prompt` hook event run as a
// real process, and everything that has to agree with it (the skill's copy of
// the text, the settings toggle, the hook entries each harness is given).

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { pathToFileURL } = require('url');
const { ROOT, cleanEnv, makeProject, runNode } = require('./helpers');
const { SECURITY_CONSTRAINTS, MAX_PROMPT_CONTEXT_CHARS } = require('../mcp-server/lib/constraints');
const io = require('../mcp-server/lib/hook-io');
const settings = require('../mcp-server/lib/settings');
const harnessHooks = require('../mcp-server/lib/harness-hooks');

const HOOK = path.join(ROOT, 'hooks', 'securecoder-hook.js');
const CLI = path.join(ROOT, 'bin', 'securecoder');
const SKILL = path.join(ROOT, 'skills', 'secure-codegen', 'SKILL.md');
// A prompt that selects no knowledge-base entry, so the context is the
// constraint block and nothing else.
const PLAIN_PROMPT = 'rename this variable';

// What Claude Code sends for UserPromptSubmit.
function claudePayload(root, prompt = PLAIN_PROMPT) {
  return {
    session_id: 's-1',
    transcript_path: path.join(root, 'transcript.jsonl'),
    cwd: root,
    prompt_id: 'p-1',
    permission_mode: 'default',
    hook_event_name: 'UserPromptSubmit',
    prompt,
  };
}

function trail(root) {
  const file = path.join(root, '.securecoder', 'errors.log');
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));
}

// Every run names a temp project as cwd, so a fault can never leave an error
// trail in this repository.
function runHook(args, input, { root, env = cleanEnv() }) {
  return runNode(HOOK, ['user-prompt', ...args], { input: typeof input === 'string' ? input : JSON.stringify(input), env, cwd: root });
}

test('the constraint block is short, scopes itself, and has the shape the skill and hook share', () => {
  const lines = SECURITY_CONSTRAINTS.split('\n');
  assert.match(lines[0], /writing or changing code/);
  assert.ok(lines.length <= 7, `${lines.length} lines`);
  for (const line of lines.slice(1)) assert.match(line, /^- \S/);
  assert.ok(SECURITY_CONSTRAINTS.length < 1000, `${SECURITY_CONSTRAINTS.length} characters`);
  assert.ok(SECURITY_CONSTRAINTS.length < MAX_PROMPT_CONTEXT_CHARS / 2);
  assert.equal(SECURITY_CONSTRAINTS, SECURITY_CONSTRAINTS.trim());
});

test('the secure-codegen skill carries the constraint block verbatim', async () => {
  const text = fs.readFileSync(SKILL, 'utf8').replace(/\r\n/g, '\n');
  const blocks = [...text.matchAll(/<!-- securecoder:constraints:start -->\n([\s\S]*?)\n<!-- securecoder:constraints:end -->/g)];
  assert.equal(blocks.length, 1, 'exactly one marked block');
  assert.equal(blocks[0][1], SECURITY_CONSTRAINTS);

  // OpenCode builds its /secure-codegen command from the skill body, markers included.
  const mod = await import(pathToFileURL(path.join(ROOT, 'opencode', 'index.js')).href);
  const plugin = await mod.SecureCoderPlugin({ client: {}, directory: makeProject(), worktree: null });
  const cfg = {};
  await plugin.config(cfg);
  assert.ok(cfg.command['secure-codegen'].template.includes(SECURITY_CONSTRAINTS));
});

test('user-prompt response: Claude Code and Codex get exactly two keys, Cursor and OpenCode get nothing', () => {
  const expected = { hookSpecificOutput: { hookEventName: 'UserPromptSubmit', additionalContext: 'C' } };
  assert.deepEqual(io.userPromptResponse({ platform: 'claude', context: 'C' }), expected);
  assert.deepEqual(io.userPromptResponse({ platform: 'codex', context: 'C' }), expected);
  assert.equal(io.userPromptResponse({ platform: 'cursor', context: 'C' }), null);
  assert.equal(io.userPromptResponse({ platform: 'opencode', context: 'C' }), null);
  assert.equal(io.userPromptResponse({ platform: 'claude', context: '' }), null);

  assert.equal(io.extractPrompt({ prompt: 'hello' }), 'hello');
  for (const payload of [null, undefined, 'text', 7, [], {}, { prompt: 7 }, { prompt: null }, { prompt: ['x'] }]) {
    assert.equal(io.extractPrompt(payload), '');
  }
});

test('hook: user-prompt injects the constraints as context for Claude Code and Codex', () => {
  const root = makeProject();
  for (const args of [[], ['--platform', 'claude'], ['--platform', 'codex']]) {
    const r = runHook(args, claudePayload(root), { root });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /^\{.*\}\n$/, 'one JSON object on one line');
    const out = JSON.parse(r.stdout);
    assert.deepEqual(Object.keys(out), ['hookSpecificOutput']);
    // Codex rejects any key beyond these two.
    assert.deepEqual(Object.keys(out.hookSpecificOutput), ['hookEventName', 'additionalContext']);
    assert.equal(out.hookSpecificOutput.hookEventName, 'UserPromptSubmit');
    assert.equal(out.hookSpecificOutput.additionalContext, SECURITY_CONSTRAINTS);
  }
  assert.deepEqual(trail(root), []);
});

test('hook: user-prompt emits nothing when its toggle or SecureCoder is off', () => {
  const on = makeProject();
  const emits = (r) => {
    assert.equal(r.status, 0, r.stderr);
    return r.stdout;
  };
  // The other two hook toggles do not reach this one.
  assert.notEqual(emits(runHook([], claudePayload(on), { root: on, env: cleanEnv({ SECURECODER_POST_EDIT: 'off', SECURECODER_SHELL_GUARD: 'off' }) })), '');

  const byProject = makeProject({ config: { hooks: { user_prompt: false } } });
  assert.equal(emits(runHook([], claudePayload(byProject), { root: byProject })), '');
  assert.equal(emits(runHook(['--platform', 'codex'], claudePayload(byProject), { root: byProject })), '');

  assert.equal(emits(runHook([], claudePayload(on), { root: on, env: cleanEnv({ SECURECODER_USER_PROMPT: 'off' }) })), '');
  assert.equal(emits(runHook([], claudePayload(on), { root: on, env: cleanEnv({ SECURECODER_ENABLED: 'off' }) })), '');

  // The environment outranks the project file in both directions.
  assert.notEqual(emits(runHook([], claudePayload(byProject), { root: byProject, env: cleanEnv({ SECURECODER_USER_PROMPT: 'on' }) })), '');

  for (const root of [on, byProject]) assert.deepEqual(trail(root), []);
});

test('hook: user-prompt fails open on a malformed payload and records it', () => {
  const root = makeProject();
  const env = cleanEnv();
  for (const input of ['this is not json', '', '{"prompt": "unterminated']) {
    const r = runHook([], input, { root, env });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout, '');
  }
  assert.deepEqual(trail(root).map((e) => [e.event, e.error]), [
    ['user-prompt', 'hook payload is not JSON (16 chars)'],
    ['user-prompt', 'hook payload is empty'],
    ['user-prompt', 'hook payload is not JSON (24 chars)'],
  ]);
});

test('hook: a payload that is valid JSON but has no usable prompt still gets the constraints', () => {
  const root = makeProject();
  const env = cleanEnv();
  const huge = { ...claudePayload(root), prompt: 'lorem ipsum dolor sit amet '.repeat(40000) };
  for (const input of [{}, { cwd: root }, { cwd: root, prompt: 42 }, { cwd: root, prompt: '' }, null, [], 'just a string', 7, huge]) {
    // Stringified here: runHook passes a string through as raw stdin, and the
    // bare words would be a malformed payload, not a JSON string.
    const r = runHook([], JSON.stringify(input), { root, env });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(JSON.parse(r.stdout).hookSpecificOutput.additionalContext, SECURITY_CONSTRAINTS, JSON.stringify(input).slice(0, 60));
  }
  assert.deepEqual(trail(root), []);
});

test('hook: user-prompt answers Cursor and OpenCode with nothing', () => {
  const root = makeProject();
  for (const platform of ['cursor', 'opencode']) {
    const r = runHook(['--platform', platform], { ...claudePayload(root), prompt: 'build a SQL query from the search box' }, { root });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout, '');
  }
  assert.deepEqual(trail(root), []);
});

test('settings: hooks.user_prompt defaults on and behaves like the other hook toggles', () => {
  const root = makeProject();
  const env = cleanEnv();
  const spec = settings.SCHEMA['hooks.user_prompt'];
  for (const sibling of ['hooks.post_edit', 'hooks.shell_guard']) {
    assert.deepEqual(Object.keys(spec), Object.keys(settings.SCHEMA[sibling]));
    assert.equal(spec.type, settings.SCHEMA[sibling].type);
    assert.equal(spec.default, settings.SCHEMA[sibling].default);
  }
  assert.equal(spec.env, 'SECURECODER_USER_PROMPT');
  assert.equal(spec.weakens(false, true), true);
  assert.equal(spec.weakens(true, false), false);
  assert.match(spec.description, /Claude Code and Codex/);

  const defaults = settings.resolve(root, { env });
  assert.deepEqual(defaults.values['hooks.user_prompt'], { value: true, source: 'default' });
  assert.equal(defaults.effective.hooks.user_prompt, true);
  assert.deepEqual(defaults.warnings, []);

  const fromEnv = settings.resolve(root, { env: { ...env, SECURECODER_USER_PROMPT: 'off' } });
  assert.deepEqual(fromEnv.values['hooks.user_prompt'], { value: false, source: 'env' });

  // Not a kill switch: a team may commit it off, as with the other two hooks.
  const byProject = settings.resolve(makeProject({ config: { hooks: { user_prompt: false } } }), { env });
  assert.deepEqual(byProject.values['hooks.user_prompt'], { value: false, source: 'project' });
  assert.deepEqual(byProject.warnings, []);

  assert.equal(settings.canonicalKey('user_prompt'), 'hooks.user_prompt');
  assert.equal(settings.canonicalKey('user-prompt'), 'hooks.user_prompt');
  const off = settings.setFromText('user-prompt', 'off', { scope: 'local', cwd: root, env });
  assert.equal(off.key, 'hooks.user_prompt');
  assert.equal(off.effective.value, false);
  assert.ok(off.notices.some((n) => n.includes('reduces protection')));
  assert.equal(JSON.parse(fs.readFileSync(path.join(root, '.securecoder.local.json'), 'utf8')).hooks.user_prompt, false);
});

test('cli: hooks.user_prompt shows in config keys and on the dashboard', () => {
  const root = makeProject();
  const env = cleanEnv({ SEMGREP_BIN: 'securecoder-missing', BANDIT_BIN: 'securecoder-missing', CODEQL_BIN: 'securecoder-missing' });
  const keys = runNode(CLI, ['config', 'keys'], { env, cwd: root });
  assert.equal(keys.status, 0, keys.stderr);
  assert.match(keys.stdout, /\| `hooks\.user_prompt` \| on \\\| off \| on \| .*Env: `SECURECODER_USER_PROMPT`\. \|/);

  const status = runNode(CLI, ['status'], { env, cwd: root });
  assert.equal(status.status, 0, status.stderr);
  assert.match(status.stdout, /\| `hooks\.shell_guard` \| on \| default \|\n\| `hooks\.user_prompt` \| on \| default \|/);

  const set = runNode(CLI, ['config', 'set', 'hooks.user_prompt', 'off'], { env, cwd: root });
  assert.equal(set.status, 0, set.stderr);
  assert.match(runNode(CLI, ['status'], { env, cwd: root }).stdout, /\| `hooks\.user_prompt` \| off \| \*\*local\*\* \|/);

  const example = JSON.parse(fs.readFileSync(path.join(ROOT, 'examples', 'securecoder.json'), 'utf8'));
  assert.equal(example.hooks.user_prompt, true);
});

test('hooks.json declares UserPromptSubmit in a shape both Claude Code and Codex accept', () => {
  const config = JSON.parse(fs.readFileSync(path.join(ROOT, 'hooks', 'hooks.json'), 'utf8'));
  // Codex fails the whole file on an unknown top-level key or handler type.
  assert.deepEqual(Object.keys(config), ['description', 'hooks']);
  assert.deepEqual(Object.keys(config.hooks), ['PostToolUse', 'PreToolUse', 'UserPromptSubmit']);
  for (const groups of Object.values(config.hooks)) {
    for (const group of groups) for (const hook of group.hooks) assert.equal(hook.type, 'command');
  }
  const [group, ...rest] = config.hooks.UserPromptSubmit;
  assert.equal(rest.length, 0);
  // No matcher (the event has none) and no statusMessage (it would flash on every prompt).
  assert.deepEqual(Object.keys(group), ['hooks']);
  assert.deepEqual(group.hooks, [{
    type: 'command',
    command: 'node "${CLAUDE_PLUGIN_ROOT}/hooks/securecoder-hook.js" user-prompt',
    timeout: 10,
  }]);
});

test('install-hooks entries mirror hooks.json: same events, matchers, timeouts and sub-commands', () => {
  const declared = JSON.parse(fs.readFileSync(path.join(ROOT, 'hooks', 'hooks.json'), 'utf8')).hooks;
  const built = harnessHooks.buildEntries();
  assert.deepEqual(Object.keys(built), Object.keys(declared));
  const subCommand = (command) => command.split(' ').pop();
  for (const [event, [group, ...rest]] of Object.entries(declared)) {
    assert.equal(rest.length, 0, event);
    assert.equal(built[event].matcher, group.matcher, event);
    assert.equal(built[event].hooks.length, group.hooks.length, event);
    group.hooks.forEach((hook, i) => {
      const ours = built[event].hooks[i];
      assert.deepEqual(Object.keys(ours), Object.keys(hook), event);
      assert.deepEqual({ ...ours, command: subCommand(ours.command) }, { ...hook, command: subCommand(hook.command) }, event);
    });
  }
});

test('install-hooks writes one shell-form command per entry and never an args field', () => {
  const script = harnessHooks.hookScriptPath();
  for (const [event, group] of Object.entries(harnessHooks.buildEntries())) {
    for (const hook of group.hooks) {
      assert.equal(typeof hook.command, 'string', event);
      assert.equal('args' in hook, false, event);
      assert.match(hook.command, /^node ".*securecoder-hook\.js" (post-edit|pre-shell|user-prompt)$/, event);
    }
  }
  assert.equal(harnessHooks.buildEntries(ROOT, 'linux').UserPromptSubmit.hooks[0].command.includes(`"${script}"`), !/[\\"$`]/.test(script));

  // Windows: the path is quoted as it stands, backslashes and all.
  const windowsRoot = 'C:\\Program Files\\secure coder';
  const windows = harnessHooks.buildEntries(windowsRoot, 'win32').PreToolUse.hooks[0].command;
  assert.equal(windows, `node "${harnessHooks.hookScriptPath(windowsRoot)}" pre-shell`);
});

test('install-hooks commands run from a plugin path with spaces and shell metacharacters', { skip: process.platform === 'win32' && 'needs a POSIX shell' }, () => {
  // A stand-in plugin whose hook script reports how it was called.
  const pluginRoot = path.join(fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-plug-'))), 'my plugin $HOME `id` "q" \\ end');
  fs.mkdirSync(path.join(pluginRoot, 'hooks'), { recursive: true });
  fs.writeFileSync(harnessHooks.hookScriptPath(pluginRoot), 'process.stdout.write(JSON.stringify([__filename, ...process.argv.slice(2)]));\n');
  const env = { ...process.env, PATH: `${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH || ''}` };
  for (const [event, group] of Object.entries(harnessHooks.buildEntries(pluginRoot))) {
    const r = spawnSync('sh', ['-c', group.hooks[0].command], { encoding: 'utf8', env });
    assert.equal(r.status, 0, `${event}: ${r.stderr}`);
    const [file, ...args] = JSON.parse(r.stdout);
    assert.equal(file, harnessHooks.hookScriptPath(pluginRoot), event);
    assert.equal(args.length, 1, event);
  }
});

test('install-hooks replaces entries an older version wrote as command + args, and uninstall removes them', () => {
  const script = harnessHooks.hookScriptPath();
  const legacy = (event, extra = {}) => ({ ...extra, hooks: [{ type: 'command', command: 'node', args: [script, event], timeout: 15 }] });
  const mine = { matcher: 'Bash', hooks: [{ type: 'command', command: 'echo mine' }] };
  const seed = () => makeProject({ files: { '.codex/hooks.json': JSON.stringify({ hooks: {
    PostToolUse: [legacy('post-edit', { matcher: 'Write|Edit|MultiEdit|apply_patch' }), mine],
    PreToolUse: [legacy('pre-shell', { matcher: 'Bash' })],
  } }) } });
  const env = cleanEnv();
  const read = (root) => JSON.parse(fs.readFileSync(path.join(root, '.codex', 'hooks.json'), 'utf8')).hooks;
  const ours = (groups) => groups.filter((g) => JSON.stringify(g).includes('securecoder-hook.js'));

  const root = seed();
  const installed = harnessHooks.install('codex', { scope: 'project', root, env });
  assert.deepEqual(installed.events, ['PostToolUse (replaced)', 'PreToolUse (replaced)', 'UserPromptSubmit']);
  for (const again of [false, true]) {
    if (again) harnessHooks.install('codex', { scope: 'project', root, env });
    const hooks = read(root);
    assert.deepEqual(Object.keys(hooks), ['PostToolUse', 'PreToolUse', 'UserPromptSubmit']);
    for (const [event, groups] of Object.entries(hooks)) {
      assert.equal(ours(groups).length, 1, `${event}: one SecureCoder entry`);
      assert.equal(JSON.stringify(groups).includes('"args"'), false, `${event}: no args left`);
    }
    assert.deepEqual(hooks.PostToolUse[0], mine, 'the user entry is untouched and keeps its place');
    assert.equal(hooks.PostToolUse.length, 2);
  }
  assert.equal(harnessHooks.remove('codex', { scope: 'project', root, env }).removed, 3);
  assert.deepEqual(read(root), { PostToolUse: [mine] });

  // Uninstalling straight from the old shape works too.
  const old = seed();
  assert.equal(harnessHooks.remove('codex', { scope: 'project', root: old, env }).removed, 2);
  assert.deepEqual(read(old), { PostToolUse: [mine] });
});
