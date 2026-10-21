// Process helper. Port of CodeQLRunner.runProcess / sanitizeEnvironment.

'use strict';

const { spawn } = require('child_process');
const path = require('path');

// Strips virtualenv/uv-managed Python from PATH so CodeQL extractors resolve a
// system interpreter, mirroring CodeQLRunner.sanitizeEnvironment.
function sanitizedEnv(ramMb) {
  const env = { ...process.env };
  const sep = path.delimiter;
  const systemPaths = ['/usr/bin', '/bin', '/usr/sbin', '/sbin'];
  const existing = (env.PATH || '')
    .split(sep)
    .filter((e) => e && !e.includes('.venv/bin') && !e.includes('Library/Application Support/uv/python'));
  env.PATH = systemPaths.concat(existing.filter((e) => !systemPaths.includes(e))).join(sep);
  delete env.VIRTUAL_ENV;
  delete env.PYTHONPATH;
  delete env.PYTHONHOME;
  if (ramMb) env.CODEQL_JAVA_ARGS = `-Xmx${ramMb}m`;
  return env;
}

// Runs a command, merging stdout+stderr. Resolves { code, output, timedOut }.
// Never rejects for non-zero exit; rejects only if the binary cannot spawn.
function run(args, { cwd, env, timeoutMs = 120000 } = {}) {
  return new Promise((resolve, reject) => {
    const [cmd, ...rest] = args;
    const child = spawn(cmd, rest, { cwd, env: env || process.env });
    let output = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);
    child.stdout.on('data', (d) => { output += d; });
    child.stderr.on('data', (d) => { output += d; });
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, output, timedOut });
    });
  });
}

module.exports = { run, sanitizedEnv };
