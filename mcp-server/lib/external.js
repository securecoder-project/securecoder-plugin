// semgrep / bandit adapters mapped onto the guardian Violation shape.
// These are the fast analyzers used by the PostToolUse hook path; CodeQL is
// the deep analyzer behind the MCP tool.

'use strict';

const { run } = require('./proc');

function severityToConfidence(sev) {
  const s = String(sev || '').toUpperCase();
  if (s === 'ERROR' || s === 'HIGH' || s === 'CRITICAL') return 'high';
  if (s === 'WARNING' || s === 'MEDIUM') return 'medium';
  return 'low';
}

// bandit -q -f json <files>
async function runBandit(filePaths, { binary = 'bandit', extraArgs = [], timeoutMs = 60000 } = {}) {
  const pyFiles = filePaths.filter((p) => p.rel.endsWith('.py'));
  if (pyFiles.length === 0) return [];
  let result;
  try {
    result = await run([binary, '-q', '-f', 'json', ...extraArgs, ...pyFiles.map((p) => p.abs)], { timeoutMs });
  } catch {
    return []; // binary missing → guardian disabled
  }
  let parsed;
  try {
    parsed = JSON.parse(result.output);
  } catch {
    return [];
  }
  const absToRel = new Map(pyFiles.map((p) => [p.abs, p.rel]));
  return (parsed.results || []).map((r) => ({
    rule: {
      id: r.test_id || 'bandit',
      name: r.test_name || null,
      cwe: r.issue_cwe && r.issue_cwe.id ? `CWE-${r.issue_cwe.id}` : null,
    },
    message: r.issue_text || 'Bandit finding',
    location: {
      file: absToRel.get(r.filename) || r.filename,
      startLine: r.line_number || null,
      endLine: (r.line_range && r.line_range[r.line_range.length - 1]) || r.line_number || null,
    },
    hardReject: false,
    confidence: severityToConfidence(r.issue_severity),
    raw: JSON.stringify(r),
    analyzer: 'bandit',
  }));
}

// semgrep --json --quiet --no-git-ignore --config=<cfg> <files>
async function runSemgrep(filePaths, { binary = 'semgrep', config = 'p/owasp-top-ten', timeoutMs = 120000 } = {}) {
  if (filePaths.length === 0) return [];
  let result;
  try {
    result = await run(
      [binary, '--json', '--quiet', '--no-git-ignore', `--config=${config}`, ...filePaths.map((p) => p.abs)],
      { timeoutMs },
    );
  } catch {
    return [];
  }
  let parsed;
  try {
    parsed = JSON.parse(result.output);
  } catch {
    return [];
  }
  const absToRel = new Map(filePaths.map((p) => [p.abs, p.rel]));
  return (parsed.results || []).map((r) => {
    const extra = r.extra || {};
    const meta = extra.metadata || {};
    const cwe = Array.isArray(meta.cwe) ? meta.cwe[0] : meta.cwe;
    const owasp = Array.isArray(meta.owasp) ? meta.owasp[0] : meta.owasp;
    return {
      rule: { id: r.check_id || 'semgrep', cwe: cwe || null, owasp: owasp || null },
      message: extra.message || 'Semgrep finding',
      location: {
        file: absToRel.get(r.path) || r.path,
        startLine: r.start && r.start.line,
        endLine: r.end && r.end.line,
      },
      hardReject: false,
      confidence: severityToConfidence(extra.severity),
      raw: JSON.stringify({ check_id: r.check_id, severity: extra.severity, metadata: meta }),
      analyzer: 'semgrep',
    };
  });
}

module.exports = { runBandit, runSemgrep };
