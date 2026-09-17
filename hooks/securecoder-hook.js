#!/usr/bin/env node
// SecureCoder command hook for Claude Code, Codex, and Cursor.
//
//   node securecoder-hook.js post-edit [--platform claude|codex|cursor]
//   node securecoder-hook.js pre-shell [--platform claude|codex|cursor]
//
// Reads the harness's hook payload (JSON) from stdin and writes at most one
// JSON response to stdout. Fails open: malformed input, internal errors, or a
// missing analyzer produce no output and exit 0, so a SecureCoder problem can
// never wedge the agent loop. Diagnostics go to stderr.

'use strict';

const path = require('path');

const MAX_STDIN_BYTES = 8 * 1024 * 1024;
const STDIN_TIMEOUT_MS = 10000;

function parseArgs(argv) {
  const out = { event: argv[0], platform: 'claude' };
  for (let i = 1; i < argv.length; i++) {
    if (argv[i] === '--platform') out.platform = argv[++i];
  }
  return out;
}

function readStdin() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve('');
    const chunks = [];
    let size = 0;
    const finish = () => {
      process.stdin.pause();
      process.stdin.removeAllListeners('data');
      resolve(Buffer.concat(chunks).toString('utf8'));
    };
    const timer = setTimeout(finish, STDIN_TIMEOUT_MS);
    process.stdin.on('data', (chunk) => {
      size += chunk.length;
      if (size <= MAX_STDIN_BYTES) chunks.push(chunk);
    });
    process.stdin.on('end', () => { clearTimeout(timer); finish(); });
    process.stdin.on('error', () => { clearTimeout(timer); finish(); });
  });
}

const log = (msg) => process.stderr.write(`[securecoder] ${msg}\n`);

async function main() {
  const { event, platform } = parseArgs(process.argv.slice(2));
  const raw = await readStdin();
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch {
    log('hook payload is not JSON; skipping');
    return;
  }

  const hooks = require(path.join(__dirname, '..', 'mcp-server', 'lib', 'hooks.js'));
  let outcome;
  if (event === 'post-edit') outcome = await hooks.postEdit(payload, { platform, log });
  else if (event === 'pre-shell') outcome = hooks.preShell(payload, { platform });
  else {
    log(`unknown hook event "${event}"`);
    return;
  }
  if (outcome && outcome.response) process.stdout.write(`${JSON.stringify(outcome.response)}\n`);
}

main()
  .catch((err) => log(`hook error (ignored): ${err && err.stack ? err.stack : err}`))
  .finally(() => { process.exitCode = 0; });
