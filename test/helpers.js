'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');

// Environment with every SecureCoder/harness variable removed and an isolated
// user config home, so tests never read or write the developer's real config.
function cleanEnv(extra = {}) {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (/^(SECURECODER_|CLAUDE_PROJECT_DIR$|CURSOR_PROJECT_DIR$|XDG_CONFIG_HOME$)/.test(k)) continue;
    if (/_BIN$/.test(k)) continue;
    env[k] = v;
  }
  return { ...env, SECURECODER_HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'sc-home-')), ...extra };
}

// Temporary git-like project with optional files and project config.
function makeProject({ files = {}, config, local } = {}) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-proj-')));
  fs.mkdirSync(path.join(dir, '.git'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  if (config) fs.writeFileSync(path.join(dir, '.securecoder.json'), JSON.stringify(config, null, 2));
  if (local) fs.writeFileSync(path.join(dir, '.securecoder.local.json'), JSON.stringify(local, null, 2));
  return dir;
}

function pythonBinary() {
  for (const candidate of [process.env.PYTHON_BIN, 'python3', 'python'].filter(Boolean)) {
    const r = spawnSync(candidate, ['--version'], { encoding: 'utf8' });
    if (r.status === 0) return candidate;
  }
  return null;
}

function runNode(script, args, { input, env, cwd } = {}) {
  return spawnSync(process.execPath, [script, ...args], {
    input,
    env,
    cwd,
    encoding: 'utf8',
    timeout: 60000,
  });
}

module.exports = { ROOT, cleanEnv, makeProject, pythonBinary, runNode };
