#!/usr/bin/env node
// Hook-facing CLI over the same guardian pipeline as the MCP server.
// Usage: node cli.js [--deep] [--project-root DIR] <file...>
// Prints findings as "[SEV] rule_id file:line: message" lines (empty output =
// clean) so bin/run-sast can pipe it straight back into Claude's context.

'use strict';

const { analyze } = require('./lib/analyze');

function severityTag(v) {
  if (v.hardReject) return 'HIGH';
  const c = String(v.confidence || '').toLowerCase();
  if (['high', 'very-high', 'error', 'critical'].includes(c)) return 'HIGH';
  if (['medium', 'warning'].includes(c)) return 'MED';
  return 'LOW';
}

async function main() {
  const args = process.argv.slice(2);
  let deep = false;
  let projectRoot = process.cwd();
  const files = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--deep') deep = true;
    else if (args[i] === '--project-root') projectRoot = args[++i];
    else files.push(args[i]);
  }
  if (files.length === 0) return;

  const result = await analyze({
    filePaths: files,
    projectRoot,
    includeDeep: deep,
    log: (m) => process.stderr.write(`[securecoder] ${m}\n`),
  });

  for (const v of result.violations) {
    const line = v.location.startLine != null ? `:${v.location.startLine}` : '';
    console.log(`[${severityTag(v)}] ${v.rule.id} ${v.location.file}${line}: ${v.message}`);
  }
  for (const f of result.failures) {
    process.stderr.write(`[securecoder] guardian failure (${f.guardian}): ${f.message.split('\n')[0]}\n`);
  }
}

// Exit 0 always — a non-zero exit would block the Claude Code hook chain.
main().catch((err) => {
  process.stderr.write(`[securecoder] ${err.message}\n`);
  process.exit(0);
});
