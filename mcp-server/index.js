#!/usr/bin/env node
// SecureCoder MCP server (stdio): zero-dependency JSON-RPC 2.0 over
// newline-delimited JSON. Exposes the guardian pipeline ported from the
// SecureCoder Kotlin engine (github: STG-TuDA/SecureCoder) to any MCP client
// (Claude Code, Codex, Cursor, OpenCode, VS Code, ...).

'use strict';

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { fileURLToPath } = require('url');
const { analyze } = require('./lib/analyze');
const { enrichPrompt } = require('./lib/enricher');
const { resetSession } = require('./lib/retry');
const settings = require('./lib/settings');
const report = require('./lib/report');
const { checkTools, nodeVersionOk, hookErrors } = require('./lib/doctor');
const { severityOf } = require('./lib/severity');
const { VERSION, PLUGIN_ROOT } = require('./lib/version');

const SERVER_INFO = { name: 'securecoder-analysis', title: 'SecureCoder', version: VERSION };
const SUPPORTED_PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const CLI_COMMAND = `node "${path.join(PLUGIN_ROOT, 'bin', 'securecoder')}"`;

const log = (msg) => process.stderr.write(`[securecoder] ${msg}\n`);

// ── project root discovery ──────────────────────────────────────────────────
// Preference: explicit project_root argument > client-declared MCP roots >
// harness env vars > the project containing an absolute file argument > the
// server's working directory. Some clients (Codex) start plugin servers
// inside the plugin's install directory, so a cwd inside the plugin is never
// taken as the project.

let clientCapabilities = {};
let rootsDir = null;
let rootsRequest = null;

function insidePlugin(dir) {
  const rel = path.relative(PLUGIN_ROOT, path.resolve(dir));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

async function projectRootFor(args, files = []) {
  if (args && typeof args.project_root === 'string' && args.project_root) return { root: path.resolve(args.project_root), known: true };
  if (rootsRequest) {
    // Roots are fetched right after initialization; don't let a slow client
    // stall a tool call for long.
    await Promise.race([rootsRequest, new Promise((r) => setTimeout(r, 2000))]);
  }
  if (rootsDir) return { root: rootsDir, known: true };
  const env = process.env;
  const fromEnv = env.SECURECODER_PROJECT_DIR || env.CLAUDE_PROJECT_DIR || env.CURSOR_PROJECT_DIR;
  if (fromEnv) return { root: path.resolve(fromEnv), known: true };
  const absoluteFile = files.find((f) => typeof f === 'string' && path.isAbsolute(f));
  if (absoluteFile) return { root: settings.findProjectRoot(path.dirname(absoluteFile)), known: true };
  if (!insidePlugin(process.cwd())) return { root: process.cwd(), known: true };
  if (env.PWD && !insidePlugin(env.PWD)) return { root: path.resolve(env.PWD), known: true };
  return { root: process.cwd(), known: false };
}

const UNKNOWN_ROOT_HINT = 'Could not determine the workspace directory (this client did not provide MCP roots and started the server inside the plugin directory). Pass project_root, or use absolute file paths.';

// Opt-in structured trace log for benchmark/eval runs: every tool call
// appends its pre-flatten result as one JSON line, so scores (violation
// counts, retry verdicts, resolved/introduced/persisting) survive alongside
// the free-text MCP response. Calls are serialized through toolQueue, so
// appendFileSync is safe. The path is a trusted setting (user scope or env).
function traceLog(root, record) {
  const file = settings.resolve(root, { root }).values.trace_log.value;
  if (!file) return;
  try {
    fs.appendFileSync(file, `${JSON.stringify({ ts: new Date().toISOString(), ...record })}\n`);
  } catch (err) {
    log(`trace log write failed: ${err.message}`);
  }
}

const TOOLS = [
  {
    name: 'securecoder_analyze',
    title: 'Analyze files for security issues',
    description:
      'Run the SecureCoder security guardian pipeline on source files. Fast guardians (syntax hard-reject checks, semgrep, bandit) always run; pass deep=true to also run CodeQL (slow: builds a CodeQL database, can take minutes). Returns violations at or above the configured severity threshold and remediation feedback with per-rule guidance and code snippets, split into MUST FIX (hard rejects: a file does not parse) and WEIGH THESE (analyzer hints: fix the real, exploitable ones, dismiss the rest with a reason). With a session id it also tracks the fix loop (resolved/new/persisting findings) and returns an advisory verdict: clean, hard_reject, continue, meta_review (soft limit) or hard_limit_exhausted. Use the same session id across fix-and-recheck iterations.',
    inputSchema: {
      type: 'object',
      properties: {
        files: {
          type: 'array',
          items: { type: 'string' },
          minItems: 1,
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
          description: 'Project root for relative paths and settings lookup. Defaults to the client workspace root.',
        },
      },
      required: ['files'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  {
    name: 'securecoder_enrich_prompt',
    title: 'Add security constraints to a code-generation prompt',
    description:
      'Add contract-preserving constraints to a code-generation prompt (keep names, signatures, requested algorithms and documented behavior exact; change only the unsafe part) and, when the task touches known weakness classes, a CWE checklist for them: how to detect each one, a behavior-preserving repair, its common false positives, and what the repair must preserve. Returns the enriched prompt, the list of injected constraints, and the selected weakness classes. The checklist is guidance, not a list of findings. Use before generating code from a user task description.',
    inputSchema: {
      type: 'object',
      properties: {
        prompt: { type: 'string', description: 'The original code-generation prompt or task description.' },
      },
      required: ['prompt'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'securecoder_reset_session',
    title: 'Reset a remediation session',
    description: 'Reset a remediation-loop session so attempt counting starts fresh.',
    inputSchema: {
      type: 'object',
      properties: {
        session: { type: 'string', description: 'The session id to reset.' },
      },
      required: ['session'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'securecoder_status',
    title: 'SecureCoder status',
    description: 'Show the SecureCoder settings dashboard: effective settings with their source (default/user/project/local/env), which analyzers are installed, config file locations, and warnings. Same as securecoder_config with action "show".',
    inputSchema: {
      type: 'object',
      properties: {
        project_root: { type: 'string', description: 'Project root for settings lookup. Defaults to the client workspace root.' },
      },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'securecoder_config',
    title: 'Read SecureCoder settings',
    description: 'Read-only view of SecureCoder settings. Actions: "show" (dashboard), "doctor" (environment check with install hints), "keys" (every setting with allowed values and defaults), "get" (one setting and its source). Settings are changed only by the user, through the /securecoder command or the securecoder CLI shown in the output; never change them to silence findings.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['show', 'doctor', 'keys', 'get'], description: 'What to return. Default "show".' },
        key: { type: 'string', description: 'Setting name for action "get" (e.g. "mode", "severity_threshold").' },
        project_root: { type: 'string', description: 'Project root for settings lookup. Defaults to the client workspace root.' },
      },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
];

function compactViolation(v) {
  return {
    ruleId: v.rule.id,
    cwe: v.rule.cwe || null,
    severity: severityOf(v),
    analyzer: v.analyzer || null,
    file: v.location.file,
    startLine: v.location.startLine ?? null,
    hardReject: v.hardReject === true,
    message: v.message,
  };
}

async function handleAnalyze(args) {
  if (!Array.isArray(args.files) || args.files.length === 0 || args.files.some((f) => typeof f !== 'string')) {
    throw Object.assign(new Error('files must be a non-empty array of paths'), { code: -32602 });
  }
  const { root, known } = await projectRootFor(args, args.files);
  if (!known && args.files.some((f) => !path.isAbsolute(f))) {
    throw Object.assign(new Error(UNKNOWN_ROOT_HINT), { code: -32602 });
  }
  const result = await analyze({
    filePaths: args.files,
    projectRoot: root,
    analyzers: args.analyzers || null,
    includeDeep: args.deep === true,
    session: args.session || null,
    log,
  });

  traceLog(root, {
    tool: 'securecoder_analyze',
    session: args.session || null,
    files: args.files,
    deep: args.deep === true,
    result,
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
    lines.push(`Verdict: ${r.verdict}: ${r.guidance}`);
  }

  lines.push('');
  if (result.violations.length === 0) {
    lines.push(`CLEAN: no security violations at or above severity ${result.threshold}.`);
  } else {
    lines.push(result.feedback);
    lines.push('');
    lines.push('Structured findings:');
    for (const v of result.violations) {
      lines.push(`[${severityOf(v)}] ${v.rule.id} ${v.location.file}:${v.location.startLine ?? '?'}${v.hardReject ? ' (hard-reject)' : ''}: ${v.message}`);
    }
  }
  if (result.belowThreshold) {
    lines.push(`(${result.belowThreshold} finding(s) below severity_threshold ${result.threshold} omitted.)`);
  }

  const structured = {
    clean: result.violations.length === 0,
    threshold: result.threshold,
    belowThreshold: result.belowThreshold,
    analyzersRun: result.analyzersRun,
    skipped: result.skipped,
    failures: result.failures.map((f) => ({ guardian: f.guardian, message: f.message.split('\n')[0] })),
    violations: result.violations.map(compactViolation),
    retry: result.retry ? {
      sessionId: result.retry.sessionId,
      attempt: result.retry.attempt,
      softLimit: result.retry.softLimit,
      hardLimit: result.retry.hardLimit,
      verdict: result.retry.verdict,
      progress: result.retry.progress,
      best: result.retry.best,
    } : null,
  };
  return { text: lines.join('\n'), structured };
}

async function handleConfig(args) {
  const action = args.action || 'show';
  const { root, known } = await projectRootFor(args);
  const resolved = settings.resolve(root);
  const withHint = (text) => (known || action === 'keys' ? text : `⚠ ${UNKNOWN_ROOT_HINT}\n\n${text}`);
  switch (action) {
    case 'show': {
      const tools = await checkTools(resolved.effective);
      return { text: withHint(report.renderDashboard(resolved, tools, { cliCommand: CLI_COMMAND })) };
    }
    case 'doctor': {
      const tools = await checkTools(resolved.effective);
      return { text: withHint(report.renderDoctor(resolved, tools, nodeVersionOk(), { errors: hookErrors(resolved.root) })) };
    }
    case 'keys':
      return { text: report.renderKeys() };
    case 'get': {
      if (!args.key) throw Object.assign(new Error('action "get" needs a key'), { code: -32602 });
      try {
        settings.requireKey(args.key);
      } catch (err) {
        throw Object.assign(new Error(err.message), { code: -32602 });
      }
      const key = settings.canonicalKey(args.key);
      const { value, source } = resolved.values[key];
      return { text: withHint(`${key} = ${settings.formatValue(value)} (${source})`), structured: { key, value, source } };
    }
    default:
      throw Object.assign(new Error(`Unknown action "${action}"`), { code: -32602 });
  }
}

async function callTool(name, args) {
  switch (name) {
    case 'securecoder_analyze':
      return handleAnalyze(args);
    case 'securecoder_enrich_prompt': {
      if (typeof args.prompt !== 'string') throw Object.assign(new Error('prompt must be a string'), { code: -32602 });
      const { enriched, hints, cwes } = enrichPrompt(args.prompt);
      traceLog((await projectRootFor(args)).root, { tool: 'securecoder_enrich_prompt', prompt: args.prompt, hints, cwes: cwes.map((c) => c.id), enriched });
      const classes = cwes.length ? `\n\nWeakness classes with a checklist in the enriched prompt: ${cwes.map((c) => `${c.id} ${c.name}`).join(', ')}` : '';
      return { text: `Injected constraints:\n${hints.map((h) => `- ${h}`).join('\n')}${classes}\n\nEnriched prompt:\n${enriched}` };
    }
    case 'securecoder_reset_session':
      if (typeof args.session !== 'string' || !args.session) throw Object.assign(new Error('session must be a non-empty string'), { code: -32602 });
      resetSession(args.session);
      traceLog((await projectRootFor(args)).root, { tool: 'securecoder_reset_session', session: args.session });
      return { text: `Session '${args.session}' reset.` };
    case 'securecoder_status':
      return handleConfig({ ...args, action: 'show' });
    case 'securecoder_config':
      return handleConfig(args);
    default:
      throw Object.assign(new Error(`Unknown tool: ${name}`), { code: -32602 });
  }
}

// ── Minimal MCP stdio transport ─────────────────────────────────────────────

let toolQueue = Promise.resolve();
let nextRequestId = 1;
const pendingRequests = new Map();

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function reply(id, result) {
  send({ jsonrpc: '2.0', id, result });
}

function replyError(id, code, message) {
  send({ jsonrpc: '2.0', id, error: { code, message } });
}

// Server → client request (used for roots/list).
function request(method, params, timeoutMs = 5000) {
  const id = `securecoder-${nextRequestId++}`;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingRequests.delete(id);
      reject(new Error(`${method} timed out`));
    }, timeoutMs);
    pendingRequests.set(id, {
      resolve: (v) => { clearTimeout(timer); resolve(v); },
      reject: (e) => { clearTimeout(timer); reject(e); },
    });
    send({ jsonrpc: '2.0', id, method, ...(params ? { params } : {}) });
  });
}

function refreshRoots() {
  if (!clientCapabilities.roots) return;
  rootsRequest = request('roots/list')
    .then((result) => {
      const first = (result && Array.isArray(result.roots) ? result.roots : [])
        .map((r) => r && r.uri)
        .find((uri) => typeof uri === 'string' && uri.startsWith('file://'));
      rootsDir = first ? fileURLToPath(first) : null;
      if (rootsDir) log(`workspace root: ${rootsDir}`);
    })
    // Must not throw: nothing handles this chain until a tool call awaits it,
    // so a rejection here would take the process down. projectRootFor's
    // ladder covers the missing root.
    .catch((err) => log(`roots/list failed (${err.message})`))
    .finally(() => { rootsRequest = null; });
}

function negotiateProtocol(requested) {
  return SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : SUPPORTED_PROTOCOL_VERSIONS[0];
}

async function handleMessage(msg) {
  if (!msg || typeof msg !== 'object' || msg.jsonrpc !== '2.0') {
    if (msg && msg.id !== undefined) replyError(msg.id, -32600, 'Invalid Request');
    return;
  }
  const { id, method, params } = msg;

  // Response to one of our own requests.
  if (method === undefined && id !== undefined && pendingRequests.has(id)) {
    const pending = pendingRequests.get(id);
    pendingRequests.delete(id);
    if (msg.error) pending.reject(new Error(msg.error.message || 'client error'));
    else pending.resolve(msg.result);
    return;
  }

  const isNotification = id === undefined || id === null;
  try {
    switch (method) {
      case 'initialize':
        clientCapabilities = (params && params.capabilities) || {};
        reply(id, {
          protocolVersion: negotiateProtocol(params && params.protocolVersion),
          capabilities: { tools: { listChanged: false } },
          serverInfo: SERVER_INFO,
          instructions: 'SecureCoder checks code for security issues. Call securecoder_analyze with absolute paths of files you create or change (reuse one session id per fix loop), securecoder_enrich_prompt before generating security-sensitive code, and securecoder_config to read settings. Never change SecureCoder settings or exclusions to make findings go away.',
        });
        break;
      case 'notifications/initialized':
      case 'notifications/roots/list_changed':
        refreshRoots();
        break;
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
            const { text, structured } = await callTool(name, args && typeof args === 'object' ? args : {});
            reply(id, { content: [{ type: 'text', text }], ...(structured ? { structuredContent: structured } : {}), isError: false });
          } catch (err) {
            if (err.code === -32602 && !TOOLS.some((t) => t.name === name)) replyError(id, err.code, err.message);
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
  log(`SecureCoder MCP server ${VERSION} started (pid ${process.pid}, cwd ${process.cwd()})`);
}

main();
