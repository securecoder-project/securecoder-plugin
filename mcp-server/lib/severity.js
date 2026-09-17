// Normalizes the heterogeneous guardian confidence/severity labels (CodeQL
// SARIF levels, semgrep ERROR/WARNING/INFO, bandit HIGH/MEDIUM/LOW) onto one
// LOW < MEDIUM < HIGH scale used for display and severity_threshold filtering.

'use strict';

const LEVELS = ['LOW', 'MEDIUM', 'HIGH'];

function severityOf(violation) {
  if (violation.hardReject) return 'HIGH';
  const c = String(violation.confidence || '').toLowerCase();
  if (['high', 'very-high', 'error', 'critical'].includes(c)) return 'HIGH';
  if (['medium', 'warning'].includes(c)) return 'MEDIUM';
  return 'LOW';
}

function rank(level) {
  const idx = LEVELS.indexOf(String(level || '').toUpperCase());
  return idx < 0 ? 0 : idx;
}

// Hard rejects (unparseable output) always survive: the candidate is invalid
// regardless of how the user tuned the threshold.
function meetsThreshold(violation, threshold) {
  return violation.hardReject === true || rank(severityOf(violation)) >= rank(threshold);
}

module.exports = { LEVELS, severityOf, rank, meetsThreshold };
