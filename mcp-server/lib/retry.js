// Port of engine/workflow GuardianRetryPolicy.kt + the data-prep side of
// GuardianRetryDecider.kt. The original used a second LLM to decide whether
// the fix loop was still making progress; here the calling agent (Claude) IS
// the LLM, so the server tracks attempt history per session and returns the
// same decision-ready summary plus a policy verdict for the agent to act on.

'use strict';

const { violationKey } = require('./feedback');

// Only the previous attempt (progress diff) and the last few (recentHistory)
// are ever read, so older entries are dropped. The attempt count is stored
// separately because it has to keep counting past the cap.
const HISTORY_LIMIT = 4;

// session id → { attempts, history: last HISTORY_LIMIT entries, best }
// `best` is the running fewest-findings attempt, { attempt, findings } | null.
// It is a scalar pair rather than a history, so it survives the cap above.
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

  const state = sessions.get(sessionId) || { attempts: 0, history: [], best: null };
  const attempt = state.attempts + 1;
  const previous = state.history[state.history.length - 1] || null;

  const currentKeys = new Set(violations.map(violationKey));
  const previousKeys = new Set(previous ? previous.keys : []);
  const resolved = previous ? [...previousKeys].filter((k) => !currentKeys.has(k)).length : 0;
  const introduced = previous ? [...currentKeys].filter((k) => !previousKeys.has(k)).length : violations.length;
  const persisting = previous ? [...currentKeys].filter((k) => previousKeys.has(k)).length : 0;

  state.attempts = attempt;
  state.history = state.history
    .concat({
      attempt,
      keys: [...currentKeys],
      violations: violations.map(summarizeViolation),
    })
    .slice(-HISTORY_LIMIT);

  // A hard-reject attempt is never the best: a file that does not parse often
  // shows few findings precisely because the analyzers could not read it, so
  // naming it as the state to go back to would be bad advice. Strictly-lower
  // replacement makes the earliest attempt win ties.
  const hardReject = violations.some((v) => v.hardReject === true);
  // De-duplicated, the same base as the progress numbers and the count the
  // feedback reports, so "attempt 4 had 2" agrees with what attempt 4 showed.
  const findings = currentKeys.size;
  if (!hardReject && (!state.best || findings < state.best.findings)) {
    state.best = { attempt, findings };
  }
  sessions.set(sessionId, state);

  let verdict;
  if (violations.length === 0) {
    verdict = 'clean';
  } else if (hardReject) {
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
    findings,
    best: state.best ? { ...state.best } : null,
    progress: { resolved, introduced, persisting },
    recentHistory: state.history.map((h) => ({ attempt: h.attempt, violations: h.violations })),
  };
}

function resetSession(sessionId) {
  sessions.delete(sessionId);
}

// The original engine falls back to its fewest-violation candidate at the hard
// limit. This server does not own the agent loop and keeps no earlier file
// contents, so it can only name that attempt; the text has to say so. Nothing
// is added when the best attempt is the current one or merely ties it, so the
// agent is never told to revert to itself or to an equally bad state.
function fallbackNote(assessment) {
  const { best, attempt, findings } = assessment;
  if (!best || best.attempt === attempt || best.findings >= findings) return '';
  return ` Attempt ${best.attempt} had ${best.findings} finding(s); the current state has ${findings}. Consider reverting to that state before reporting. This is advisory: SecureCoder does not keep earlier file contents and cannot apply the revert.`;
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
      return `Hard retry limit (${assessment.hardLimit}) reached. Stop patching, report status PARTIAL, and flag remaining findings for human review.${fallbackNote(assessment)}`;
    case 'meta_review':
      return `Soft retry limit (${assessment.softLimit}) reached at attempt ${assessment.attempt}. Review the recent history: be conservative about stopping, prefer continuing unless the loop is clearly stuck (same findings persisting with no resolutions across attempts). If stuck, stop and report PARTIAL with the persisting findings.`;
    default:
      return `Attempt ${assessment.attempt} of ${assessment.hardLimit}. Fix the findings that are real and re-analyze with the same session id. If every remaining finding is one you have dismissed with a reason, stop and report those dismissals instead of iterating.`;
  }
}

module.exports = { recordAttempt, resetSession, verdictGuidance };
