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

// The analyzer's JSON report. A run that timed out or printed something else
// (a crash, a traceback, a failed rule download) produced no result at all;
// reading that as "no findings" would make a broken analyzer look like clean
// code. It throws instead, and analyze.js reports it as that analyzer's
// failure. A binary that is not installed is different: it is handled by the
// callers as a disabled guardian, and `doctor` reports it.
function parseReport(name, { code, output, timedOut }, timeoutMs) {
  if (timedOut) throw new Error(`${name} timed out after ${timeoutMs}ms`);
  try {
    return JSON.parse(output);
  } catch {
    const firstLine = output.split('\n').map((l) => l.trim()).find(Boolean) || 'no output';
    throw new Error(`${name} exited with code ${code} without a JSON report: ${firstLine.slice(0, 200)}`);
  }
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
  const parsed = parseReport('bandit', result, timeoutMs);
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
  const parsed = parseReport('semgrep', result, timeoutMs);
  // A fatal error (the ruleset could not be downloaded or is invalid) still
  // comes with a JSON report: non-zero exit, no results, the reason under
  // `errors`. Exit 1 only means findings. A target that does not parse is not
  // this case; semgrep exits 0 for it.
  const errors = Array.isArray(parsed.errors) ? parsed.errors : [];
  if (result.code !== 0 && result.code !== 1 && errors.length > 0 && !(parsed.results || []).length) {
    throw new Error(`semgrep exited with code ${result.code}: ${String(errors[0].message || errors[0].type || 'error').split('\n')[0].slice(0, 200)}`);
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
