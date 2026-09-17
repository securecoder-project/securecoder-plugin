#!/usr/bin/env node
// Consistency checks across every harness manifest. Run before releasing and
// in CI: `node scripts/check-manifests.js`. Exits 1 with a list of problems.
//
// - one version everywhere (package.json is the source of truth)
// - one plugin name everywhere, valid under the Agent Plugins name rules
// - every path a manifest references exists and stays inside the plugin root
// - every SKILL.md follows the Agent Skills frontmatter rules
// - agent files carry name + description; hook configs parse and reference real scripts

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const problems = [];
const fail = (msg) => problems.push(msg);

function readJson(rel) {
  try {
    return JSON.parse(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
  } catch (err) {
    fail(`${rel}: ${err.code === 'ENOENT' ? 'missing' : `invalid JSON (${err.message})`}`);
    return null;
  }
}

function checkPath(rel, from) {
  const resolved = path.resolve(ROOT, rel);
  if (path.relative(ROOT, resolved).startsWith('..')) fail(`${from}: path "${rel}" escapes the plugin root`);
  else if (!fs.existsSync(resolved)) fail(`${from}: path "${rel}" does not exist`);
}

function frontmatter(rel) {
  const text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
  const match = text.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/);
  if (!match) {
    fail(`${rel}: missing YAML frontmatter`);
    return {};
  }
  const meta = {};
  for (const line of match[1].split(/\r?\n/)) {
    const kv = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (kv) meta[kv[1]] = kv[2].replace(/^["']|["']$/g, '');
  }
  return meta;
}

const pkg = readJson('package.json');
const VERSION = pkg && pkg.version;
const NAME = 'securecoder';
const NAME_RULE = /^[a-z0-9](?:[a-z0-9]|[-.](?=[a-z0-9]))*$/;

// ── manifests ────────────────────────────────────────────────────────────────

const manifests = {
  '.claude-plugin/plugin.json': readJson('.claude-plugin/plugin.json'),
  'plugin.json': readJson('plugin.json'),
  '.cursor-plugin/plugin.json': readJson('.cursor-plugin/plugin.json'),
};
for (const [rel, m] of Object.entries(manifests)) {
  if (!m) continue;
  if (m.name !== NAME) fail(`${rel}: name is "${m.name}", expected "${NAME}"`);
  if (!NAME_RULE.test(m.name || '') || (m.name || '').length > 64) fail(`${rel}: name "${m.name}" violates the plugin name rules`);
  if (m.version !== VERSION) fail(`${rel}: version ${m.version} != package.json ${VERSION}`);
  if (!m.description) fail(`${rel}: missing description`);
  if (m.license !== pkg.license) fail(`${rel}: license ${m.license} != package.json ${pkg.license}`);
}

const agentPlugins = manifests['plugin.json'];
if (agentPlugins) {
  // Codex only runs plugin hooks it can find; declare them explicitly rather
  // than relying on default discovery for the portable layout.
  const openai = (agentPlugins.extensions || {})['com.openai'] || {};
  if (!openai.hooks) fail('plugin.json: extensions."com.openai".hooks must point at the hook config');
  else checkPath(String(openai.hooks).replace(/^\.\//, ''), 'plugin.json extensions."com.openai".hooks');
  const allowed = new Set(['$schema', 'name', 'version', 'description', 'author', 'homepage', 'repository', 'license', 'keywords', 'extensions']);
  for (const key of Object.keys(agentPlugins)) if (!allowed.has(key)) fail(`plugin.json: "${key}" is not an Agent Plugins 1.0 field (move it under extensions)`);
  if (agentPlugins.$schema !== 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json') fail('plugin.json: unexpected $schema');
}

const cursor = manifests['.cursor-plugin/plugin.json'];
if (cursor) for (const key of ['skills', 'agents', 'hooks', 'mcpServers']) if (cursor[key]) checkPath(cursor[key], `.cursor-plugin/plugin.json ${key}`);

const claudeMarket = readJson('.claude-plugin/marketplace.json');
if (claudeMarket) {
  const entry = (claudeMarket.plugins || []).find((p) => p.name === NAME);
  if (!entry) fail('.claude-plugin/marketplace.json: no securecoder entry');
  else {
    if (entry.version !== VERSION) fail(`.claude-plugin/marketplace.json: version ${entry.version} != ${VERSION}`);
    checkPath(entry.source, '.claude-plugin/marketplace.json source');
  }
}
const codexMarket = readJson('.agents/plugins/marketplace.json');
if (codexMarket) {
  const entry = (codexMarket.plugins || []).find((p) => p.name === NAME);
  if (!entry) fail('.agents/plugins/marketplace.json: no securecoder entry');
  else checkPath(entry.source && entry.source.path, '.agents/plugins/marketplace.json source.path');
}

// ── MCP configs: all launch the same server entrypoint ───────────────────────

// Each harness expands a different plugin-root variable, so the launch shape
// differs per file. The portable Agent Plugins config avoids variables
// altogether (a plugin-relative cwd), because Cursor and some other clients
// read the root manifest but never expand ${PLUGIN_ROOT}.
const mcpConfigs = [
  ['.claude-plugin/plugin.json (mcpServers)', manifests['.claude-plugin/plugin.json'] && manifests['.claude-plugin/plugin.json'].mcpServers, ['${CLAUDE_PLUGIN_ROOT}/mcp-server/index.js'], undefined],
  ['mcp.json', (readJson('mcp.json') || {}).mcpServers, ['index.js'], './mcp-server'],
  ['.cursor-plugin/mcp.json', (readJson('.cursor-plugin/mcp.json') || {}).mcpServers, ['${CURSOR_PLUGIN_ROOT}/mcp-server/index.js'], undefined],
];
for (const [rel, servers, expectedArgs, expectedCwd] of mcpConfigs) {
  const server = servers && servers['securecoder-analysis'];
  if (!server) {
    fail(`${rel}: missing securecoder-analysis server`);
    continue;
  }
  if (server.command !== 'node' || JSON.stringify(server.args) !== JSON.stringify(expectedArgs) || server.cwd !== expectedCwd) {
    fail(`${rel}: expected command "node", args ${JSON.stringify(expectedArgs)}, cwd ${JSON.stringify(expectedCwd)}`);
  }
}
checkPath('mcp-server/index.js', 'MCP entrypoint');

// ── hooks ────────────────────────────────────────────────────────────────────

for (const [rel, variable] of [['hooks/hooks.json', '${CLAUDE_PLUGIN_ROOT}'], ['hooks/cursor.json', '${CURSOR_PLUGIN_ROOT}']]) {
  const config = readJson(rel);
  if (!config) continue;
  const commands = Object.values(config.hooks || {}).flatMap((groups) => groups.flatMap((g) => (g.hooks ? g.hooks.map((h) => h.command) : [g.command])));
  if (commands.length === 0) fail(`${rel}: no hook commands`);
  for (const command of commands) {
    const script = (command || '').match(/"([^"]+)"/);
    if (!script || !script[1].startsWith(`${variable}/`)) fail(`${rel}: command should quote a ${variable}-relative script: ${command}`);
    else checkPath(script[1].slice(variable.length + 1), rel);
  }
}

// ── skills and agents ────────────────────────────────────────────────────────

const skillsDir = path.join(ROOT, 'skills');
for (const dir of fs.readdirSync(skillsDir)) {
  const rel = `skills/${dir}/SKILL.md`;
  if (!fs.existsSync(path.join(ROOT, rel))) continue;
  const meta = frontmatter(rel);
  if (meta.name !== dir) fail(`${rel}: name "${meta.name}" must match its directory "${dir}"`);
  if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(meta.name || '') || meta.name.length > 64) fail(`${rel}: invalid skill name "${meta.name}"`);
  if (!meta.description || meta.description.length > 1024) fail(`${rel}: description must be 1-1024 characters`);
  for (const mcpTool of (meta['allowed-tools'] || '').match(/mcp__[A-Za-z0-9_-]+/g) || []) {
    if (!mcpTool.startsWith(`mcp__plugin_${NAME}_securecoder-analysis__`)) fail(`${rel}: MCP tool "${mcpTool}" does not use the plugin-scoped name`);
  }
}

for (const file of fs.readdirSync(path.join(ROOT, 'agents')).filter((f) => f.endsWith('.md'))) {
  const rel = `agents/${file}`;
  const meta = frontmatter(rel);
  if (meta.name !== path.basename(file, '.md')) fail(`${rel}: name "${meta.name}" must match the file name`);
  if (!meta.description) fail(`${rel}: missing description`);
  for (const mcpTool of (meta.tools || '').match(/mcp__[A-Za-z0-9_-]+/g) || []) {
    if (!mcpTool.startsWith(`mcp__plugin_${NAME}_securecoder-analysis__`)) fail(`${rel}: MCP tool "${mcpTool}" does not use the plugin-scoped name`);
  }
}

// ── repository hygiene ───────────────────────────────────────────────────────

for (const rel of ['LICENSE', 'README.md', 'INSTALL.md', 'CHANGELOG.md', 'SECURITY.md', 'bin/securecoder', 'opencode/index.js']) checkPath(rel, 'required file');
const changelog = fs.existsSync(path.join(ROOT, 'CHANGELOG.md')) ? fs.readFileSync(path.join(ROOT, 'CHANGELOG.md'), 'utf8') : '';
if (VERSION && !changelog.includes(`## [${VERSION}]`)) fail(`CHANGELOG.md: no "## [${VERSION}]" section`);
for (const stale of ['.mcp.json', 'settings.json']) {
  if (fs.existsSync(path.join(ROOT, stale))) fail(`${stale}: must not exist at the plugin root (see CHANGELOG 0.2.0)`);
}

if (problems.length) {
  process.stderr.write(`Manifest check failed (${problems.length}):\n${problems.map((p) => `  - ${p}`).join('\n')}\n`);
  process.exit(1);
}
process.stdout.write(`Manifest check passed: securecoder ${VERSION} is consistent across Claude Code, Codex/Agent Plugins, Cursor, and OpenCode.\n`);
