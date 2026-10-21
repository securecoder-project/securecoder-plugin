'use strict';

// Speaks MCP to the real server over stdio, including a server→client
// roots/list round trip.

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const readline = require('readline');
const { spawn } = require('child_process');
const { pathToFileURL } = require('url');
const { ROOT, cleanEnv, makeProject } = require('./helpers');

function startServer(env, { roots, rootsError, cwd } = {}) {
  const child = spawn(process.execPath, [path.join(ROOT, 'mcp-server', 'index.js')], { env, cwd, stdio: ['pipe', 'pipe', 'pipe'] });
  const waiters = new Map();
  let nextId = 1;
  let stderr = '';
  child.stderr.on('data', (d) => { stderr += d; });
  // Registered up front so a server that died early fails a test instead of hanging it.
  const closed = new Promise((resolve) => child.on('close', resolve));
  child.stdin.on('error', () => {});
  const rl = readline.createInterface({ input: child.stdout });
  rl.on('line', (line) => {
    const msg = JSON.parse(line);
    if (msg.method === 'roots/list') {
      const answer = rootsError
        ? { error: { code: -32603, message: 'boom' } }
        : { result: { roots: (roots || []).map((r) => ({ uri: pathToFileURL(r).href, name: 'ws' })) } };
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: msg.id, ...answer })}\n`);
      return;
    }
    const waiter = waiters.get(msg.id);
    if (waiter) {
      waiters.delete(msg.id);
      waiter(msg);
    }
  });
  const send = (method, params) => new Promise((resolve, reject) => {
    const id = nextId++;
    waiters.set(id, resolve);
    closed.then((code) => reject(new Error(`server exited (code ${code}) before answering ${method}`)));
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  });
  const notify = (method, params) => child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
  const close = () => {
    child.stdin.end();
    return closed;
  };
  return { send, notify, close, child, stderr: () => stderr };
}

test('initialize negotiates protocol and lists annotated tools', async () => {
  const server = startServer(cleanEnv());
  try {
    const init = await server.send('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } });
    assert.equal(init.result.protocolVersion, '2025-06-18');
    assert.equal(init.result.serverInfo.name, 'securecoder-analysis');
    assert.equal(init.result.serverInfo.version, require('../package.json').version);
    assert.ok(init.result.instructions);

    const future = await server.send('initialize', { protocolVersion: '2099-01-01', capabilities: {} });
    assert.equal(future.result.protocolVersion, '2025-11-25');

    server.notify('notifications/initialized');
    const list = await server.send('tools/list', {});
    const names = list.result.tools.map((t) => t.name).sort();
    assert.deepEqual(names, ['securecoder_analyze', 'securecoder_config', 'securecoder_enrich_prompt', 'securecoder_reset_session', 'securecoder_status']);
    for (const tool of list.result.tools) {
      assert.equal(typeof tool.annotations.readOnlyHint, 'boolean', tool.name);
      assert.equal(tool.inputSchema.type, 'object');
    }
    assert.equal(list.result.tools.find((t) => t.name === 'securecoder_config').annotations.readOnlyHint, true);

    const missing = await server.send('no/such/method', {});
    assert.equal(missing.error.code, -32601);
    const unknownTool = await server.send('tools/call', { name: 'nope', arguments: {} });
    assert.equal(unknownTool.error.code, -32602);
  } finally {
    await server.close();
  }
});

test('tools use the client-declared workspace root for settings', async () => {
  const root = makeProject({ config: { mode: 'enforce' } });
  const server = startServer(cleanEnv({ SEMGREP_BIN: 'securecoder-missing', BANDIT_BIN: 'securecoder-missing', CODEQL_BIN: 'securecoder-missing' }), { roots: [root] });
  try {
    await server.send('initialize', { protocolVersion: '2025-06-18', capabilities: { roots: { listChanged: true } } });
    server.notify('notifications/initialized');

    const get = await server.send('tools/call', { name: 'securecoder_config', arguments: { action: 'get', key: 'mode' } });
    assert.equal(get.result.isError, false);
    assert.deepEqual(get.result.structuredContent, { key: 'mode', value: 'enforce', source: 'project' });

    const status = await server.send('tools/call', { name: 'securecoder_status', arguments: {} });
    assert.match(status.result.content[0].text, /ENABLED · enforce/);
    assert.match(status.result.content[0].text, new RegExp(`CLI: \`node ".*bin[\\\\/]+securecoder"\``));

    const badKey = await server.send('tools/call', { name: 'securecoder_config', arguments: { action: 'get', key: 'nope' } });
    assert.equal(badKey.result.isError, true);
    assert.match(badKey.result.content[0].text, /Unknown setting/);

    const badArgs = await server.send('tools/call', { name: 'securecoder_analyze', arguments: { files: [] } });
    assert.equal(badArgs.result.isError, true);

    const enrich = await server.send('tools/call', { name: 'securecoder_enrich_prompt', arguments: { prompt: 'Write a JavaScript hash function that returns a string' } });
    assert.match(enrich.result.content[0].text, /Injected constraints/);
    assert.doesNotMatch(enrich.result.content[0].text, /Secure-coding checklist/);

    const checklist = await server.send('tools/call', { name: 'securecoder_enrich_prompt', arguments: { prompt: 'Add an endpoint that runs a SQL query built from the search box' } });
    assert.match(checklist.result.content[0].text, /Weakness classes with a checklist in the enriched prompt: CWE-89 SQL injection/);
    assert.match(checklist.result.content[0].text, /Secure-coding checklist[\s\S]*1\. CWE-89 SQL injection\n\s+Detect: /);
  } finally {
    await server.close();
  }
});

test('analyze returns structured results and tracks remediation sessions', async () => {
  const root = makeProject({ files: { 'ok.js': 'module.exports = 1;\n' }, config: { analyzers: ['syntax'] } });
  const server = startServer(cleanEnv({ SECURECODER_PROJECT_DIR: root }));
  try {
    await server.send('initialize', { protocolVersion: '2025-06-18', capabilities: {} });
    server.notify('notifications/initialized');
    const first = await server.send('tools/call', { name: 'securecoder_analyze', arguments: { files: ['ok.js'], session: 's1' } });
    assert.equal(first.result.isError, false, first.result.content[0].text);
    assert.equal(first.result.structuredContent.clean, true);
    assert.equal(first.result.structuredContent.retry.verdict, 'clean');
    assert.equal(first.result.structuredContent.retry.attempt, 1);
    assert.deepEqual(first.result.structuredContent.retry.best, { attempt: 1, findings: 0 });
    const second = await server.send('tools/call', { name: 'securecoder_analyze', arguments: { files: ['ok.js'], session: 's1' } });
    assert.equal(second.result.structuredContent.retry.attempt, 2);
    await server.send('tools/call', { name: 'securecoder_reset_session', arguments: { session: 's1' } });
    const third = await server.send('tools/call', { name: 'securecoder_analyze', arguments: { files: ['ok.js'], session: 's1' } });
    assert.equal(third.result.structuredContent.retry.attempt, 1);
  } finally {
    await server.close();
  }
});

test('server started inside the plugin directory (Codex) derives the project from absolute paths', async () => {
  const root = makeProject({ files: { 'src/ok.js': 'module.exports = 1;\n' }, config: { analyzers: ['syntax'], mode: 'enforce' } });
  const server = startServer(cleanEnv({ PWD: ROOT }), { cwd: ROOT });
  try {
    await server.send('initialize', { protocolVersion: '2025-06-18', capabilities: {} });
    server.notify('notifications/initialized');

    const relative = await server.send('tools/call', { name: 'securecoder_analyze', arguments: { files: ['src/ok.js'] } });
    assert.equal(relative.result.isError, true);
    assert.match(relative.result.content[0].text, /Pass project_root, or use absolute file paths/);

    const absolute = await server.send('tools/call', { name: 'securecoder_analyze', arguments: { files: [path.join(root, 'src', 'ok.js')] } });
    assert.equal(absolute.result.isError, false, absolute.result.content[0].text);
    assert.deepEqual(absolute.result.structuredContent.analyzersRun, ['syntax']);

    const config = await server.send('tools/call', { name: 'securecoder_config', arguments: { action: 'get', key: 'mode' } });
    assert.match(config.result.content[0].text, /^⚠ Could not determine the workspace/);

    const explicit = await server.send('tools/call', { name: 'securecoder_config', arguments: { action: 'get', key: 'mode', project_root: root } });
    assert.deepEqual(explicit.result.structuredContent, { key: 'mode', value: 'enforce', source: 'project' });
  } finally {
    await server.close();
  }
});

const rootsFailures = (stderr) => stderr.split('roots/list failed').length - 1;

test('a failed roots/list is logged once and tool calls fall back to the root ladder', async () => {
  const root = makeProject({ files: { 'ok.js': 'module.exports = 1;\n' }, config: { analyzers: ['syntax'] } });
  const server = startServer(cleanEnv({ SECURECODER_PROJECT_DIR: root }), { rootsError: true });
  try {
    await server.send('initialize', { protocolVersion: '2025-06-18', capabilities: { roots: { listChanged: true } } });
    server.notify('notifications/initialized');
    // Relative path: only resolvable if the ladder supplied the project root.
    const result = await server.send('tools/call', { name: 'securecoder_analyze', arguments: { files: ['ok.js'] } });
    assert.equal(result.result.isError, false, result.result.content[0].text);
    assert.deepEqual(result.result.structuredContent.analyzersRun, ['syntax']);
  } finally {
    await server.close();
  }
  assert.equal(rootsFailures(server.stderr()), 1, server.stderr());
});

test('a failed roots/list with no tool call following does not take the server down', async () => {
  const server = startServer(cleanEnv(), { rootsError: true });
  try {
    await server.send('initialize', { protocolVersion: '2025-06-18', capabilities: { roots: { listChanged: true } } });
    server.notify('notifications/initialized');
    // The ping reply is written after roots/list, so the error is already on its way back.
    await server.send('ping', {});
    await new Promise((r) => setTimeout(r, 400));
    assert.equal(server.child.exitCode, null, server.stderr());
    assert.deepEqual((await server.send('ping', {})).result, {});
  } finally {
    await server.close();
  }
  // Proves the error path ran, so the liveness check above was not vacuous.
  assert.equal(rootsFailures(server.stderr()), 1, server.stderr());
});

test('securecoder_config doctor reports the hook error trail for the project', async () => {
  const { appendError } = require('../mcp-server/lib/error-log');
  const root = makeProject({ config: { analyzers: ['syntax'] } });
  const server = startServer(cleanEnv({ SECURECODER_PROJECT_DIR: root }));
  const doctor = async () => (await server.send('tools/call', { name: 'securecoder_config', arguments: { action: 'doctor' } })).result.content[0].text;
  try {
    await server.send('initialize', { protocolVersion: '2025-06-18', capabilities: {} });
    server.notify('notifications/initialized');
    assert.doesNotMatch(await doctor(), /hook error/);
    appendError(root, { event: 'post-edit', error: new TypeError('x is not a function') });
    const text = await doctor();
    assert.match(text, /⚠ 1 hook error logged in `.*errors\.log`/);
    assert.match(text, /Most recent: \S+ \(post-edit, SecureCoder \S+\): TypeError: x is not a function/);
  } finally {
    await server.close();
  }
});
