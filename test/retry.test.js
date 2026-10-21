'use strict';

// The per-session history is capped, so everything derived from it (attempt
// number, progress diff, limit verdicts) is driven past the cap here. The
// running best attempt lives outside that history and is covered below it.

const test = require('node:test');
const assert = require('node:assert/strict');
const { recordAttempt, resetSession, verdictGuidance } = require('../mcp-server/lib/retry');

const violation = (id, extra = {}) => ({
  rule: { id },
  message: `message for ${id}`,
  location: { file: 'a.py', startLine: 1, endLine: 1 },
  ...extra,
});

const drive = (session, count, violations, policy) =>
  Array.from({ length: count }, () => recordAttempt(session, violations, policy));

test('attempt numbering keeps counting past the history cap', () => {
  const results = drive('retry-count', 10, [violation('r1')]);
  assert.deepEqual(results.map((r) => r.attempt), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  assert.equal(results[9].sessionId, 'retry-count');
});

test('recentHistory holds at most the last four attempts', () => {
  const results = drive('retry-history', 10, [violation('r1')]);
  assert.deepEqual(results.map((r) => r.recentHistory.length), [1, 2, 3, 4, 4, 4, 4, 4, 4, 4]);
  assert.deepEqual(results[9].recentHistory.map((h) => h.attempt), [7, 8, 9, 10]);
  assert.deepEqual(results[9].recentHistory[3], {
    attempt: 10,
    violations: [{ ruleId: 'r1', message: 'message for r1', file: 'a.py', startLine: 1, hardReject: null }],
  });
});

test('progress is diffed against the immediately previous attempt after the cap', () => {
  const session = 'retry-progress';
  const first = recordAttempt(session, [violation('a'), violation('b')]);
  assert.deepEqual(first.progress, { resolved: 0, introduced: 2, persisting: 0 });
  drive(session, 5, [violation('a'), violation('b')]);

  const seventh = recordAttempt(session, [violation('b'), violation('c'), violation('d')]);
  assert.equal(seventh.attempt, 7);
  assert.deepEqual(seventh.progress, { resolved: 1, introduced: 2, persisting: 1 });

  // 'a' left the previous attempt, so it counts as introduced again, not persisting.
  const eighth = recordAttempt(session, [violation('a'), violation('b')]);
  assert.deepEqual(eighth.progress, { resolved: 2, introduced: 1, persisting: 1 });

  const ninth = recordAttempt(session, []);
  assert.equal(ninth.verdict, 'clean');
  assert.deepEqual(ninth.progress, { resolved: 2, introduced: 0, persisting: 0 });
});

test('soft and hard limits beyond the cap fire at the right attempt', () => {
  const policy = { softLimit: 6, hardLimit: 8 };
  const results = drive('retry-limits', 10, [violation('r1')], policy);
  assert.deepEqual(results.map((r) => r.verdict), [
    'continue', 'continue', 'continue', 'continue', 'continue',
    'meta_review', 'meta_review',
    'hard_limit_exhausted', 'hard_limit_exhausted', 'hard_limit_exhausted',
  ]);
  assert.equal(results[9].softLimit, 6);
  assert.equal(results[9].hardLimit, 8);

  const rejected = recordAttempt('retry-limits', [violation('r1', { hardReject: true })], policy);
  assert.equal(rejected.attempt, 11);
  assert.equal(rejected.verdict, 'hard_reject');
});

test('resetSession restarts at attempt 1 with an empty history', () => {
  const session = 'retry-reset';
  drive(session, 6, [violation('r1')]);
  resetSession(session);
  const fresh = recordAttempt(session, [violation('r1')]);
  assert.equal(fresh.attempt, 1);
  assert.deepEqual(fresh.progress, { resolved: 0, introduced: 1, persisting: 0 });
  assert.deepEqual(fresh.recentHistory.map((h) => h.attempt), [1]);
});

// --- fewest-findings fallback at the hard limit ---

const POLICY = { softLimit: 3, hardLimit: 6 };
const hardLimitText = (limit) =>
  `Hard retry limit (${limit}) reached. Stop patching, report status PARTIAL, and flag remaining findings for human review.`;
const MENTIONS_FALLBACK = /revert|advisory|Attempt \d+ had/i;

const findings = (count, extra) => Array.from({ length: count }, (_, i) => violation(`r${i + 1}`, extra));

// One attempt per entry: a number is that many ordinary findings, an array is
// passed through as the attempt's violations.
const play = (session, attempts, policy = POLICY) =>
  attempts.map((a) => recordAttempt(session, Array.isArray(a) ? a : findings(a), policy));

test('hard limit names the fewest-findings attempt when the count was not monotonic', () => {
  const results = play('best-non-monotonic', [5, 4, 6, 2, 7, 9]);
  assert.deepEqual(results.map((r) => r.best), [
    { attempt: 1, findings: 5 },
    { attempt: 2, findings: 4 },
    { attempt: 2, findings: 4 },
    { attempt: 4, findings: 2 },
    { attempt: 4, findings: 2 },
    { attempt: 4, findings: 2 },
  ]);

  const last = results[5];
  assert.equal(last.verdict, 'hard_limit_exhausted');
  assert.equal(last.findings, 9);
  assert.equal(
    verdictGuidance(last),
    `${hardLimitText(6)} Attempt 4 had 2 finding(s); the current state has 9. Consider reverting to that state before reporting. This is advisory: SecureCoder does not keep earlier file contents and cannot apply the revert.`,
  );
});

test('hard limit does not suggest reverting when the current attempt is the best', () => {
  const last = play('best-is-current', [5, 4, 6, 3, 4, 2])[5];
  assert.equal(last.verdict, 'hard_limit_exhausted');
  assert.deepEqual(last.best, { attempt: 6, findings: 2 });
  assert.equal(verdictGuidance(last), hardLimitText(6));
});

test('hard limit does not suggest reverting to an attempt the current one ties', () => {
  const last = play('best-tied-by-current', [5, 2, 6, 3, 4, 2])[5];
  assert.equal(last.verdict, 'hard_limit_exhausted');
  assert.equal(last.findings, 2);
  // The earlier attempt keeps the title, but an equal count is no reason to go back.
  assert.deepEqual(last.best, { attempt: 2, findings: 2 });
  assert.equal(verdictGuidance(last), hardLimitText(6));
});

test('the earliest of several equally good attempts is the one named', () => {
  const last = play('best-tie-break', [5, 2, 6, 2, 4, 7])[5];
  assert.deepEqual(last.best, { attempt: 2, findings: 2 });
  const guidance = verdictGuidance(last);
  assert.match(guidance, /Attempt 2 had 2 finding\(s\); the current state has 7\./);
  assert.doesNotMatch(guidance, /Attempt 4/);
});

test('a hard-reject attempt is never the best, even with the lowest count', () => {
  const results = play('best-skips-hard-reject', [4, findings(1, { hardReject: true }), 3, 5, 5, 6]);
  assert.equal(results[1].verdict, 'hard_reject');
  assert.equal(results[1].findings, 1);
  assert.deepEqual(results[1].best, { attempt: 1, findings: 4 });

  const last = results[5];
  assert.equal(last.verdict, 'hard_limit_exhausted');
  assert.deepEqual(last.best, { attempt: 3, findings: 3 });
  assert.match(verdictGuidance(last), /Attempt 3 had 3 finding\(s\); the current state has 6\./);
});

test('a session where every attempt had a hard reject has no best', () => {
  // One unparseable file next to ordinary findings still disqualifies the attempt.
  const rejected = [violation('syntax', { hardReject: true }), violation('r1')];
  const results = play('best-all-hard-reject', Array.from({ length: 7 }, () => rejected));
  assert.deepEqual(results.map((r) => r.best), [null, null, null, null, null, null, null]);
  // hard_reject outranks the limits, so the fallback note never applies here.
  assert.deepEqual([...new Set(results.map((r) => r.verdict))], ['hard_reject']);
  assert.doesNotMatch(verdictGuidance(results[6]), MENTIONS_FALLBACK);
});

test('the best attempt survives the history cap, and a clean attempt can be it', () => {
  const policy = { softLimit: 3, hardLimit: 8 };
  const last = play('best-past-cap', [3, 0, 5, 5, 5, 5, 5, 4], policy)[7];
  assert.equal(last.attempt, 8);
  assert.equal(last.verdict, 'hard_limit_exhausted');
  assert.deepEqual(last.recentHistory.map((h) => h.attempt), [5, 6, 7, 8]);
  assert.deepEqual(last.best, { attempt: 2, findings: 0 });
  assert.match(verdictGuidance(last), /Attempt 2 had 0 finding\(s\); the current state has 4\./);
});

test('guidance for the other verdicts never mentions the fallback', () => {
  // Attempt 1 stays strictly better than every later non-clean attempt, so
  // only the verdict keeps the note out.
  const results = play('best-other-verdicts', [1, 3, 3, findings(2, { hardReject: true }), 0]);
  assert.deepEqual(results.map((r) => r.verdict), ['continue', 'continue', 'meta_review', 'hard_reject', 'clean']);
  assert.deepEqual(results[3].best, { attempt: 1, findings: 1 });
  for (const r of results) assert.doesNotMatch(verdictGuidance(r), MENTIONS_FALLBACK);

  assert.equal(verdictGuidance(results[1]), 'Attempt 2 of 6. Fix the findings that are real and re-analyze with the same session id. If every remaining finding is one you have dismissed with a reason, stop and report those dismissals instead of iterating.');
  assert.match(verdictGuidance(results[2]), /^Soft retry limit \(3\) reached at attempt 3\./);
  assert.match(verdictGuidance(results[3]), /^A hard-reject violation is present/);
  assert.equal(verdictGuidance(results[4]), 'No violations remain. The remediation loop is done.');
});

test('exact duplicates count once, like the feedback summary and the progress numbers', () => {
  const twice = recordAttempt('best-dedup', [violation('r1'), violation('r1'), violation('r2')]);
  assert.equal(twice.findings, 2);
  assert.deepEqual(twice.best, { attempt: 1, findings: 2 });
});

test('resetSession forgets the best attempt', () => {
  const session = 'best-reset';
  assert.deepEqual(play(session, [1, 4])[1].best, { attempt: 1, findings: 1 });
  resetSession(session);

  const results = play(session, [4, 4, 4, 4, 4, 4]);
  assert.deepEqual(results[0].best, { attempt: 1, findings: 4 });
  assert.equal(results[5].verdict, 'hard_limit_exhausted');
  assert.equal(verdictGuidance(results[5]), hardLimitText(6));
});
