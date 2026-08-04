#!/usr/bin/env node
// SecureCoder MCP server (stdio) — zero-dependency JSON-RPC 2.0 over
// newline-delimited JSON. Exposes the guardian pipeline ported from the
// SecureCoder Kotlin engine (github: STG-TuDA/SecureCoder) to Claude Code.

'use strict';

const readline = require('readline');
const { analyze } = require('./lib/analyze');
const { enrichPrompt } = require('./lib/enricher');
const { resetSession } = require('./lib/retry');
const { loadConfig } = require('./lib/config');
const { available } = require('./lib/proc');
const { CodeQLRunner } = require('./lib/codeql');

const SERVER_INFO = { name: 'securecoder-analysis', version: '0.2.0' };
const PROTOCOL_VERSION = '2025-06-18';

const log = (msg) => process.stderr.write(`[securecoder] ${msg}\n`);

const TOOLS = [
  {
    name: 'securecoder_analyze',
    description:
      'Run the SecureCoder security guardian pipeline on source files. Fast guardians (syntax hard-reject checks, semgrep, bandit) always run; pass deep=true to also run CodeQL (slow: builds a CodeQL database, can take minutes). Returns structured violations, remediation feedback with per-rule guidance and code snippets, and — when a session id is given — retry-loop progress tracking (resolved/new/persisting findings, soft/hard limit verdicts). Use the same session id across fix-and-recheck iterations.',
    inputSchema: {
      type: 'object',
      properties: {
        files: {
          type: 'array',
          items: { type: 'string' },
          description: 'Paths of files to analyze (absolute, or relative to project_root).',
        },
        deep: {
          type: 'boolean',
          description: 'Also run deep analyzers (CodeQL). Slow but thorough. Default false.',
        },
        analyzers: {
          type: 'array',
          items: { type: 'string', enum: ['syntax', 'semgrep', 'bandit', 'codeql'] },
          description: 'Explicit analyzer selection; overrides the configured default set.',
        },
        session: {
          type: 'string',
          description: 'Remediation-loop session id. Reuse it on re-analysis after fixes to get progress tracking and retry-limit verdicts.',
        },
        project_root: {
          type: 'string',
          description: 'Project root for relative paths and .securecoder.json lookup. Defaults to the server working directory.',
        },
      },
      required: ['files'],
    },
  },
  {
    name: 'securecoder_enrich_prompt',
    description:
      'Enrich a code-generation prompt with contract-preserving security constraints (SecureCoder heuristic prompt enricher). Returns the enriched prompt and the list of injected constraints. Use before generating code from a user task description.',
    inputSchema: {
      type: 'object',
      properties: {
        prompt: { type: 'string', description: 'The original code-generation prompt or task description.' },
      },
      required: ['prompt'],
    },
  },
  {
    name: 'securecoder_reset_session',
    description: 'Reset a remediation-loop session so attempt counting starts fresh.',
    inputSchema: {
      type: 'object',
      properties: {
        session: { type: 'string', description: 'The session id to reset.' },
      },
      required: ['session'],
    },
  },
  {
    name: 'securecoder_status',
    description: 'Report which analyzers are available on this machine (codeql, semgrep, bandit, syntax-check binaries) and the effective .securecoder.json configuration.',
    inputSchema: {
      type: 'object',
      properties: {
        project_root: { type: 'string', description: 'Project root for config lookup. Defaults to the server working directory.' },
      },
    },
  },
];

function severityTag(v) {
  if (v.hardReject) return 'HIGH';
  const c = String(v.confidence || '').toLowerCase();
  if (['high', 'very-high', 'error', 'critical'].includes(c)) return 'HIGH';
  if (['medium', 'warning'].includes(c)) return 'MED';
  return 'LOW';
}

async function handleAnalyze(args) {
  const result = await analyze({
    filePaths: args.files,
    projectRoot: args.project_root || process.cwd(),
    analyzers: args.analyzers || null,
    includeDeep: args.deep === true,
    session: args.session || null,
    log,
  });

  const lines = [];
  lines.push(`Analyzers run: ${result.analyzersRun.join(', ') || 'none'}`);
  for (const skip of result.skipped) lines.push(`Skipped ${skip.path}: ${skip.reason}`);
  for (const failure of result.failures) {
    lines.push(`Guardian failure (${failure.guardian}): ${failure.message.split('\n')[0]}`);
  }

  if (result.retry) {
    const r = result.retry;
    lines.push('');
    lines.push(`Remediation session '${r.sessionId}': attempt ${r.attempt} (soft limit ${r.softLimit}, hard limit ${r.hardLimit})`);
    lines.push(`Progress vs previous attempt: ${r.progress.resolved} resolved, ${r.progress.introduced} new, ${r.progress.persisting} persisting`);
    lines.push(`Verdict: ${r.verdict} — ${r.guidance}`);
  }

  lines.push('');
  if (result.violations.length === 0) {
    lines.push('CLEAN: no security violations found.');
  } else {
    lines.push(result.feedback);
    lines.push('');
    lines.push('Structured findings:');
    for (const v of result.violations) {
      lines.push(`[${severityTag(v)}] ${v.rule.id} ${v.location.file}:${v.location.startLine ?? '?'}${v.hardReject ? ' (hard-reject)' : ''} — ${v.message}`);
    }
  }
  return lines.join('\n');
}

async function handleStatus(args) {
  const config = loadConfig(args.project_root || process.cwd());
  const checks = {
    codeql: available(config.codeql.binary, ['--version']),
    semgrep: available(config.bins.semgrep, ['--version']),
    bandit: available(config.bins.bandit, ['--version']),
    python: available(config.bins.python, ['--version']),
    node: available(config.bins.node, ['--version']),
    gofmt: available(config.bins.gofmt, ['--help']),
    clang: available(config.bins.clang, ['--version']),
    'clang++': available(config.bins.clangxx, ['--version']),
  };
  const entries = await Promise.all(
    Object.entries(checks).map(async ([name, p]) => [name, await p]),
  );
  const lines = ['Analyzer availability:'];
  for (const [name, ok] of entries) lines.push(`- ${name}: ${ok ? 'available' : 'NOT FOUND'}`);
  const codeqlOk = entries.find(([n]) => n === 'codeql')[1];
  if (codeqlOk) {
    try {
      const version = await new CodeQLRunner(config.codeql.binary).getToolVersion();
      lines.push(`CodeQL version: ${version}`);
    } catch { /* version parse is informational only */ }
  }
  lines.push('');
  lines.push('Effective configuration:');
  lines.push(JSON.stringify(config, null, 2));
  return lines.join('\n');
}

async function callTool(name, args) {
  switch (name) {
    case 'securecoder_analyze':
      return handleAnalyze(args || {});
    case 'securecoder_enrich_prompt': {
      const { enriched, hints } = enrichPrompt((args && args.prompt) || '');
      return `Injected constraints:\n${hints.map((h) => `- ${h}`).join('\n')}\n\nEnriched prompt:\n${enriched}`;
    }
    case 'securecoder_reset_session':
      resetSession(args.session);
      return `Session '${args.session}' reset.`;
    case 'securecoder_status':
      return handleStatus(args || {});
    default:
      throw Object.assign(new Error(`Unknown tool: ${name}`), { code: -32602 });
  }
}

// ── Minimal MCP stdio transport ─────────────────────────────────────────────

let toolQueue = Promise.resolve();

function send(message) {
  process.stdout.write(JSON.stringify(message) + '\n');
}

function reply(id, result) {
  send({ jsonrpc: '2.0', id, result });
}

function replyError(id, code, message) {
  send({ jsonrpc: '2.0', id, error: { code, message } });
}

async function handleMessage(msg) {
  const { id, method, params } = msg;
  const isNotification = id === undefined || id === null;
  try {
    switch (method) {
      case 'initialize':
        reply(id, {
          protocolVersion: (params && params.protocolVersion) || PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: SERVER_INFO,
        });
        break;
      case 'notifications/initialized':
      case 'notifications/cancelled':
        break;
      case 'ping':
        reply(id, {});
        break;
      case 'tools/list':
        reply(id, { tools: TOOLS });
        break;
      case 'tools/call': {
        const { name, arguments: args } = params || {};
        // Serialize tool calls: analysis is disk/CPU-heavy and session attempt
        // counting must follow call order even if a client pipelines requests.
        toolQueue = toolQueue.then(async () => {
          try {
            const text = await callTool(name, args);
            reply(id, { content: [{ type: 'text', text }], isError: false });
          } catch (err) {
            if (err.code === -32602) replyError(id, err.code, err.message);
            else reply(id, { content: [{ type: 'text', text: `Error: ${err.message}` }], isError: true });
          }
        });
        await toolQueue;
        break;
      }
      default:
        if (!isNotification) replyError(id, -32601, `Method not found: ${method}`);
    }
  } catch (err) {
    if (!isNotification) replyError(id, err.code || -32603, err.message || 'Internal error');
  }
}

function main() {
  let pending = 0;
  let stdinClosed = false;
  const maybeExit = () => {
    if (stdinClosed && pending === 0) process.exit(0);
  };
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      return;
    }
    pending++;
    handleMessage(msg)
      .catch((err) => log(`unhandled: ${err.stack || err}`))
      .finally(() => {
        pending--;
        maybeExit();
      });
  });
  // Let in-flight tool calls finish before exiting on stdin close.
  rl.on('close', () => {
    stdinClosed = true;
    maybeExit();
  });
  log(`SecureCoder MCP server started (pid ${process.pid}, cwd ${process.cwd()})`);
}

main();
