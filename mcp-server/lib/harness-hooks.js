// Installs SecureCoder's hooks into a harness's own hook configuration.
//
// Needed where a harness does not load plugin-bundled hooks. Codex, for
// example, reads hooks from ~/.codex/hooks.json and <repo>/.codex/hooks.json
// in addition to plugin manifests, and some builds only run the former.
// The generated entries are the same ones hooks/hooks.json declares, with the
// plugin-root variable resolved to an absolute path.
//
// Merging is idempotent: entries are recognized by the hook script name, so
// reinstalling replaces SecureCoder's own entries and never touches yours.

'use strict';

const fs = require('fs');
const path = require('path');
const { PLUGIN_ROOT } = require('./version');

const HOOK_SCRIPT = 'securecoder-hook.js';
const HARNESSES = ['codex'];

function hookScriptPath(pluginRoot = PLUGIN_ROOT) {
  return path.join(pluginRoot, 'hooks', HOOK_SCRIPT);
}

// The events and matchers mirror hooks/hooks.json.
function buildEntries(pluginRoot = PLUGIN_ROOT) {
  const script = hookScriptPath(pluginRoot);
  return {
    PostToolUse: {
      matcher: 'Write|Edit|MultiEdit|apply_patch',
      hooks: [{
        type: 'command',
        command: 'node',
        args: [script, 'post-edit'],
        timeout: 180,
        statusMessage: 'SecureCoder: scanning edited files',
      }],
    },
    PreToolUse: {
      matcher: 'Bash',
      hooks: [{
        type: 'command',
        command: 'node',
        args: [script, 'pre-shell'],
        timeout: 15,
      }],
    },
  };
}

function hooksFile(harness, { scope = 'user', root = process.cwd(), env = process.env } = {}) {
  if (!HARNESSES.includes(harness)) {
    throw new Error(`Unknown harness "${harness}". Supported: ${HARNESSES.join(', ')}.`);
  }
  if (scope === 'project') return path.join(root, '.codex', 'hooks.json');
  if (scope !== 'user') throw new Error(`Unknown scope "${scope}". Use user or project.`);
  const home = env.CODEX_HOME || path.join(env.HOME || require('os').homedir(), '.codex');
  return path.join(home, 'hooks.json');
}

function isOurs(group) {
  return JSON.stringify(group || {}).includes(HOOK_SCRIPT);
}

function readConfig(file) {
  if (!fs.existsSync(file)) return { hooks: {} };
  const text = fs.readFileSync(file, 'utf8');
  let data;
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new Error(`Refusing to modify ${file}: it is not valid JSON (${err.message}). Fix or remove it first.`);
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error(`Refusing to modify ${file}: the top-level value must be a JSON object.`);
  if (!data.hooks || typeof data.hooks !== 'object' || Array.isArray(data.hooks)) data.hooks = {};
  return data;
}

function writeAtomic(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = path.join(path.dirname(file), `.hooks.json.${process.pid}.${Date.now()}.tmp`);
  fs.writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o644 });
  try {
    fs.renameSync(tmp, file);
  } catch (err) {
    try { fs.unlinkSync(tmp); } catch { /* best effort */ }
    throw err;
  }
}

function install(harness, { scope = 'user', root = process.cwd(), env = process.env, pluginRoot = PLUGIN_ROOT } = {}) {
  const file = hooksFile(harness, { scope, root, env });
  const data = readConfig(file);
  const entries = buildEntries(pluginRoot);
  const events = [];
  for (const [event, group] of Object.entries(entries)) {
    const existing = Array.isArray(data.hooks[event]) ? data.hooks[event] : [];
    const kept = existing.filter((g) => !isOurs(g));
    data.hooks[event] = [...kept, group];
    events.push(`${event}${kept.length !== existing.length ? ' (replaced)' : ''}`);
  }
  writeAtomic(file, data);
  return { harness, scope, file, events, script: hookScriptPath(pluginRoot) };
}

function remove(harness, { scope = 'user', root = process.cwd(), env = process.env } = {}) {
  const file = hooksFile(harness, { scope, root, env });
  if (!fs.existsSync(file)) return { harness, scope, file, removed: 0 };
  const data = readConfig(file);
  let removed = 0;
  for (const [event, groups] of Object.entries(data.hooks)) {
    if (!Array.isArray(groups)) continue;
    const kept = groups.filter((g) => !isOurs(g));
    removed += groups.length - kept.length;
    if (kept.length) data.hooks[event] = kept;
    else delete data.hooks[event];
  }
  if (removed) writeAtomic(file, data);
  return { harness, scope, file, removed };
}

module.exports = { HARNESSES, buildEntries, hooksFile, hookScriptPath, install, remove };
