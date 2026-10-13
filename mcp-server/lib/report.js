// Text rendering shared by the CLI, the MCP server, and the hooks, so every
// harness shows identical dashboards and findings. Output is plain Markdown
// (tables, no ANSI colors) that reads fine raw and renders well in chat UIs.

'use strict';

const { SCHEMA, formatValue, describeAllowed } = require('./settings');
const { severityOf } = require('./severity');
const { VERSION } = require('./version');

const DASHBOARD_KEYS = [
  'enabled', 'mode', 'severity_threshold', 'hooks.post_edit', 'hooks.shell_guard', 'hooks.user_prompt',
  'analyzers', 'deep_analyzers', 'semgrep_config', 'retry.soft_limit', 'retry.hard_limit', 'exclude_patterns',
];

function cell(text) {
  return String(text).replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function sourceLabel(source) {
  return source === 'default' ? 'default' : `**${source}**`;
}

function renderFiles(resolved) {
  return ['user', 'project', 'local'].map((scope) => {
    const f = resolved.files[scope];
    const state = f.error ? 'invalid JSON' : f.exists ? 'present' : 'not created';
    return `- ${scope}: \`${f.path}\` (${state})`;
  });
}

function renderDashboard(resolved, tools, { cliCommand } = {}) {
  const v = (key) => resolved.values[key].value;
  const lines = [];
  const status = v('enabled') ? 'ENABLED' : 'DISABLED';
  lines.push(`## SecureCoder ${VERSION}: ${status} · ${v('mode')} · threshold ${v('severity_threshold')}`);
  lines.push('');
  lines.push(`Project: \`${resolved.root}\``);
  lines.push('');
  lines.push('| Setting | Value | Source |');
  lines.push('| --- | --- | --- |');
  for (const key of DASHBOARD_KEYS) {
    const { value, source } = resolved.values[key];
    let shown = formatValue(value);
    if (key === 'exclude_patterns' && Array.isArray(value) && value.length > 4) {
      shown = `${value.slice(0, 4).join(', ')} … (+${value.length - 4})`;
    }
    lines.push(`| \`${key}\` | ${cell(shown)} | ${sourceLabel(source)} |`);
  }

  if (tools) {
    const selected = new Set([...v('analyzers'), ...v('deep_analyzers')]);
    lines.push('');
    lines.push('| Analyzer | Enabled | Installed |');
    lines.push('| --- | --- | --- |');
    const byAnalyzer = (name) => tools.filter((t) => t.analyzer === name);
    for (const name of ['syntax', 'semgrep', 'bandit', 'codeql']) {
      const entries = byAnalyzer(name);
      const installed = name === 'syntax'
        ? entries.map((t) => `${t.languages} ${t.available ? '✓' : '✗'}`).join(', ')
        : entries.map((t) => (t.available ? `✓ ${t.version || ''}`.trim() : `✗ \`${t.install}\``)).join('');
      const label = name === 'codeql' ? 'codeql (deep)' : name;
      lines.push(`| ${label} | ${selected.has(name) ? '✓' : '–'} | ${cell(installed)} |`);
    }
  }

  lines.push('');
  lines.push('Config files (precedence: default < user < project < local < env):');
  lines.push(...renderFiles(resolved));

  if (resolved.warnings.length) {
    lines.push('');
    lines.push('Warnings:');
    for (const w of resolved.warnings) lines.push(`- ⚠ ${w}`);
  }
  if (cliCommand) {
    lines.push('');
    lines.push(`CLI: \`${cliCommand}\``);
  }
  return lines.join('\n');
}

function renderDoctor(resolved, tools, node, { errors = null } = {}) {
  const lines = [`## SecureCoder ${VERSION} doctor`, ''];
  lines.push(`- Node.js ${node.version}: ${node.ok ? '✓' : '✗ Node 18 or newer is required'}`);
  for (const t of tools) {
    const what = t.analyzer === 'syntax' ? `syntax guardian (${t.languages})` : t.analyzer;
    if (t.available) lines.push(`- ${t.tool} (\`${t.binary}\`) for ${what}: ✓ ${t.version || ''}`.trimEnd());
    else lines.push(`- ${t.tool} (\`${t.binary}\`) for ${what}: ✗ not found. Install: \`${t.install}\``);
  }
  const selected = new Set(resolved.values.analyzers.value);
  const missingSelected = tools.filter((t) => !t.available && t.analyzer !== 'syntax' && t.analyzer !== 'codeql' && selected.has(t.analyzer));
  lines.push('');
  if (!resolved.values.enabled.value) lines.push('- ⚠ SecureCoder is disabled (`enabled` is off).');
  if (missingSelected.length) {
    lines.push(`- ⚠ Enabled but not installed: ${missingSelected.map((t) => t.tool).join(', ')}. These analyzers are skipped silently until installed.`);
  }
  for (const [scope, f] of Object.entries(resolved.files)) {
    if (f.error) lines.push(`- ✗ ${scope} config \`${f.path}\` is invalid JSON: ${f.error}`);
  }
  for (const w of resolved.warnings) lines.push(`- ⚠ ${w}`);
  if (errors) {
    const { count, last, file } = errors;
    const where = last.analyzer ? `${last.event}, analyzer ${last.analyzer}` : last.event;
    lines.push(`- ⚠ ${count} hook error${count === 1 ? '' : 's'} logged in \`${file}\`: edits may be going unscanned. Delete the file once the cause is fixed.`);
    lines.push(`  Most recent: ${last.ts} (${where}, SecureCoder ${last.version}): ${last.error}`);
  }
  if (lines[lines.length - 1] === '') lines.push('- ✓ No configuration problems found.');
  return lines.join('\n');
}

function renderKeys() {
  const lines = ['| Key | Allowed values | Default | Description |', '| --- | --- | --- | --- |'];
  for (const [key, spec] of Object.entries(SCHEMA)) {
    const scopeNote = spec.trusted ? ' _(user scope or env only)_' : '';
    const envNote = spec.env ? ` Env: \`${spec.env}\`.` : '';
    lines.push(`| \`${key}\` | ${cell(describeAllowed(spec))} | ${cell(formatValue(spec.default))} | ${cell(spec.description)}${scopeNote}${envNote} |`);
  }
  return lines.join('\n');
}

function renderChange(result) {
  const lines = [];
  if (result.removed === undefined) {
    lines.push(`✓ ${result.key} = ${formatValue(result.value)} (${result.scope}: \`${result.file}\`)`);
  } else if (Array.isArray(result.removed)) {
    lines.push(result.removed.length
      ? `✓ Reset ${result.removed.length} setting(s) in ${result.scope} config: ${result.removed.join(', ')}`
      : `Nothing to reset in ${result.scope} config.`);
  } else if (result.removed) {
    lines.push(`✓ Removed ${result.key} from ${result.scope} config; effective value is now ${formatValue(result.effective.value)} (${result.effective.source}).`);
  }
  for (const n of result.notices || []) lines.push(n);
  return lines.join('\n');
}

const MAX_MESSAGE_CHARS = 220;

function shortCwe(cwe) {
  const m = cwe && String(cwe).match(/CWE-\d+/i);
  return m ? m[0].toUpperCase() : null;
}

// Groups findings that several analyzers report for the same line and CWE
// (e.g. bandit B602 and semgrep subprocess-shell-true) into one entry.
function groupFindings(violations) {
  const groups = new Map();
  for (const v of violations) {
    const cwe = shortCwe(v.rule.cwe);
    const key = cwe && v.location.startLine != null ? `${v.location.file}|${v.location.startLine}|${cwe}` : `${v.location.file}|${v.location.startLine}|${v.rule.id}`;
    const group = groups.get(key);
    if (group) group.push(v);
    else groups.set(key, [v]);
  }
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  return [...groups.values()]
    .map((group) => group.sort((a, b) => order[severityOf(a)] - order[severityOf(b)]))
    .sort((a, b) => order[severityOf(a[0])] - order[severityOf(b[0])]);
}

// Compact per-finding lines for hook context and CLI scan output.
function renderFindings(result, { max = 15, header = true } = {}) {
  const lines = [];
  const violations = result.violations;
  const groups = groupFindings(violations);
  if (header) {
    const files = [...new Set(violations.map((v) => v.location.file))];
    lines.push(`SecureCoder found ${groups.length} security finding(s) in ${files.join(', ')}:`);
  }
  for (const group of groups.slice(0, max)) {
    const [v, ...others] = group;
    const where = `${v.location.file}${v.location.startLine != null ? `:${v.location.startLine}` : ''}`;
    const cwe = shortCwe(v.rule.cwe);
    let message = v.message.split('\n')[0];
    if (message.length > MAX_MESSAGE_CHARS) message = `${message.slice(0, MAX_MESSAGE_CHARS - 1)}…`;
    const also = others.length ? ` (also: ${others.map((o) => o.rule.id).join(', ')})` : '';
    lines.push(`- [${severityOf(v)}] ${v.rule.id}${cwe ? ` ${cwe}` : ''} at ${where}${v.hardReject ? ' (hard-reject: file does not parse)' : ''}: ${message}${also}`);
  }
  if (groups.length > max) lines.push(`- …and ${groups.length - max} more.`);
  if (result.belowThreshold) {
    lines.push(`(${result.belowThreshold} finding(s) below severity_threshold ${result.threshold} not shown.)`);
  }
  for (const f of result.failures || []) {
    lines.push(`(Analyzer ${f.guardian} failed: ${f.message.split('\n')[0]})`);
  }
  return lines.join('\n');
}

module.exports = { renderDashboard, renderDoctor, renderKeys, renderChange, renderFindings };
