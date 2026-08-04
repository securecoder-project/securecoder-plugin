// Port of engine/workflow GuardianRetryPolicy.kt + the data-prep side of
// GuardianRetryDecider.kt. The original used a second LLM to decide whether
// the fix loop was still making progress; here the calling agent (Claude) IS
// the LLM, so the server tracks attempt history per session and returns the
// same decision-ready summary plus a policy verdict for the agent to act on.

'use strict';

const { violationKey } = require('./feedback');

const sessions = new Map();

function summarizeViolation(v) {
  return {
    ruleId: v.rule.id,
    message: v.message,
    file: v.location.file,
    startLine: v.location.startLine ?? null,
    hardReject: v.hardReject ?? null,
  };
}

// Records one guardian attempt and returns the retry assessment.
function recordAttempt(sessionId, violations, policy = {}) {
  const softLimit = policy.softLimit ?? 7;
  const hardLimit = policy.hardLimit ?? 14;

  const history = sessions.get(sessionId) || [];
  const attempt = history.length + 1;
  const previous = history[history.length - 1] || null;

  const currentKeys = new Set(violations.map(violationKey));
  const previousKeys = new Set(previous ? previous.keys : []);
  const resolved = previous ? [...previousKeys].filter((k) => !currentKeys.has(k)).length : 0;
  const introduced = previous ? [...currentKeys].filter((k) => !previousKeys.has(k)).length : violations.length;
  const persisting = previous ? [...currentKeys].filter((k) => previousKeys.has(k)).length : 0;

  history.push({
    attempt,
    keys: [...currentKeys],
    violations: violations.map(summarizeViolation),
  });
  sessions.set(sessionId, history);

  let verdict;
  if (violations.length === 0) {
    verdict = 'clean';
  } else if (violations.some((v) => v.hardReject === true)) {
    verdict = 'hard_reject';
  } else if (attempt >= hardLimit) {
    verdict = 'hard_limit_exhausted';
  } else if (attempt >= softLimit) {
    verdict = 'meta_review';
  } else {
    verdict = 'continue';
  }

  return {
    sessionId,
    attempt,
    softLimit,
    hardLimit,
    verdict,
    progress: { resolved, introduced, persisting },
    recentHistory: history.slice(-4).map((h) => ({ attempt: h.attempt, violations: h.violations })),
  };
}

function resetSession(sessionId) {
  sessions.delete(sessionId);
}

// Guidance text mirroring the GuardianRetryDecider system prompt, addressed
// to the calling agent instead of a dedicated decider LLM.
function verdictGuidance(assessment) {
  switch (assessment.verdict) {
    case 'clean':
      return 'No violations remain. The remediation loop is done.';
    case 'hard_reject':
      return 'A hard-reject violation is present (e.g., the file does not parse). Fix it before anything else; do not iterate on other findings until this is resolved.';
    case 'hard_limit_exhausted':
      return `Hard retry limit (${assessment.hardLimit}) reached. Stop patching, report status PARTIAL, and flag remaining findings for human review.`;
    case 'meta_review':
      return `Soft retry limit (${assessment.softLimit}) reached at attempt ${assessment.attempt}. Review the recent history: be conservative about stopping, prefer continuing unless the loop is clearly stuck (same findings persisting with no resolutions across attempts). If stuck, stop and report PARTIAL with the persisting findings.`;
    default:
      return `Attempt ${assessment.attempt} of ${assessment.hardLimit}. Continue fixing and re-analyze with the same session id.`;
  }
}

module.exports = { recordAttempt, resetSession, verdictGuidance };
