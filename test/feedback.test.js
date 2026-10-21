'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  buildFeedback,
  hintForRule,
  violationKey,
  MUST_FIX_HEADING,
  WEIGH_HEADING,
  MUST_FIX_PREAMBLE,
  WEIGH_PREAMBLE,
  TRIAGE_RULE,
} = require('../mcp-server/lib/feedback');

function finding(ruleId, line, { file = 'a.py', message = `${ruleId} message`, hardReject = false } = {}) {
  return { rule: { id: ruleId }, message, location: { file, startLine: line, endLine: line }, hardReject };
}

const SQLI = finding('py/sql-injection', 4);
const WEAK_HASH = finding('B324', 9); // no curated hint
const BROKEN = finding('python-syntax', 2, { hardReject: true });
const NO_FILES = new Map();

// Text of one section: from its heading up to the next heading or the end.
function section(text, heading) {
  const start = text.indexOf(`\n${heading} (`);
  if (start === -1) return null;
  const other = heading === MUST_FIX_HEADING ? WEIGH_HEADING : MUST_FIX_HEADING;
  const end = text.indexOf(`\n${other} (`, start + 1);
  return text.slice(start + 1, end === -1 ? text.length : end);
}

test('a mixed set renders hard rejects as must-fix, first, and the rest as hints to weigh', () => {
  // The hard reject arrives last and is still rendered first.
  const text = buildFeedback([SQLI, WEAK_HASH, BROKEN], NO_FILES);
  const lines = text.split('\n');

  assert.equal(lines[0], 'Security analysis found 3 finding(s): 1 must be fixed, 2 to weigh.');
  assert.doesNotMatch(text, /Address all/);

  const mustFix = section(text, MUST_FIX_HEADING);
  const weigh = section(text, WEIGH_HEADING);
  assert.ok(text.indexOf(`${MUST_FIX_HEADING} (1)`) < text.indexOf(`${WEIGH_HEADING} (2)`));
  assert.ok(mustFix.includes(MUST_FIX_PREAMBLE));
  assert.ok(weigh.includes(WEIGH_PREAMBLE));
  assert.ok(WEIGH_PREAMBLE.includes(TRIAGE_RULE));

  assert.match(mustFix, /^1\. \[python-syntax\] python-syntax message @ a\.py:2$/m);
  assert.doesNotMatch(mustFix, /sql-injection|B324/);
  // Numbering continues across sections; first-seen order within one.
  assert.match(weigh, /^2\. \[py\/sql-injection\] py\/sql-injection message @ a\.py:4$/m);
  assert.match(weigh, /^3\. \[B324\] B324 message @ a\.py:9$/m);
  assert.doesNotMatch(weigh, /python-syntax/);
});

test('the preambles carry the framing: parse errors are mandatory, the rest are hints', () => {
  assert.match(MUST_FIX_PREAMBLE, /does not parse or compile\. Fix them first: nothing else can be judged/);
  assert.match(WEIGH_PREAMBLE, /hints, not verdicts/);
  assert.match(TRIAGE_RULE, /real, exploitable issue/);
  assert.match(TRIAGE_RULE, /without changing documented behavior/);
  assert.match(TRIAGE_RULE, /do not patch it, and say why you are dismissing it \("false positive because/);
});

test('only hard rejects: no advisory heading or preamble', () => {
  const text = buildFeedback([BROKEN, finding('go-syntax', 1, { file: 'm.go', hardReject: true })], NO_FILES);
  assert.equal(text.split('\n')[0], 'Security analysis found 2 finding(s): 2 must be fixed.');
  assert.ok(text.includes(`${MUST_FIX_HEADING} (2)`));
  assert.ok(!text.includes(WEIGH_HEADING));
  assert.ok(!text.includes(WEIGH_PREAMBLE));
  assert.doesNotMatch(text, /weigh|hints/i);
});

test('only advisory findings: no mandatory heading or preamble', () => {
  const text = buildFeedback([SQLI, WEAK_HASH], NO_FILES);
  assert.equal(text.split('\n')[0], 'Security analysis found 2 finding(s): 2 to weigh.');
  assert.ok(text.includes(`${WEIGH_HEADING} (2)`));
  assert.ok(!text.includes(MUST_FIX_HEADING));
  assert.ok(!text.includes(MUST_FIX_PREAMBLE));
  assert.doesNotMatch(text, /must be fixed|Address all/);
  assert.match(text, /^1\. \[py\/sql-injection\]/m);
});

test('only an explicit hardReject === true is mandatory', () => {
  const loose = [
    { rule: { id: 'r1' }, message: 'm', location: { file: 'a.py', startLine: 1 } },
    { rule: { id: 'r2' }, message: 'm', location: { file: 'a.py', startLine: 2 }, hardReject: null },
  ];
  const text = buildFeedback(loose, NO_FILES);
  assert.ok(!text.includes(MUST_FIX_HEADING));
  assert.ok(text.includes(`${WEIGH_HEADING} (2)`));
});

test('targeted guidance lands in the section its rule belongs to, de-duplicated', () => {
  const text = buildFeedback([
    SQLI,
    finding('py/sql-injection', 20),
    finding('py/redos', 30),
    finding('py/polynomial-redos', 31), // same hint as py/redos
    WEAK_HASH,
    BROKEN,
  ], NO_FILES);
  const mustFix = section(text, MUST_FIX_HEADING);
  const weigh = section(text, WEIGH_HEADING);
  const count = (haystack, needle) => haystack.split(needle).length - 1;

  assert.equal(count(mustFix, `- ${hintForRule('python-syntax')}`), 1);
  assert.equal(count(mustFix, '\n- '), 1);
  assert.match(mustFix, /^Targeted guidance:$/m);

  assert.equal(count(weigh, `- ${hintForRule('py/sql-injection')}`), 1);
  assert.equal(count(weigh, `- ${hintForRule('py/redos')}`), 1);
  assert.equal(count(weigh, '\n- '), 2);
  // In the hints section the guidance is advice on how to fix, not an order to.
  assert.match(weigh, /^Targeted guidance for the ones you fix:$/m);
  assert.ok(!weigh.includes(hintForRule('python-syntax')));
});

test('a rule with no curated hint adds no guidance block', () => {
  assert.equal(hintForRule('B324'), null);
  const text = buildFeedback([WEAK_HASH], NO_FILES);
  assert.doesNotMatch(text, /Targeted guidance/);
  assert.deepEqual(text.split('\n').slice(2), [`${WEIGH_HEADING} (1)`, WEIGH_PREAMBLE, '1. [B324] B324 message @ a.py:9']);
});

test('duplicates collapse to one entry and are not counted twice', () => {
  const text = buildFeedback([SQLI, { ...SQLI }, BROKEN, { ...BROKEN }, WEAK_HASH], NO_FILES);
  assert.equal(text.split('\n')[0], 'Security analysis found 3 finding(s): 1 must be fixed, 2 to weigh.');
  assert.equal(text.match(/^\d+\. \[/gm).length, 3);
  assert.doesNotMatch(text, /more$/m);
});

test('snippets show numbered lines around the finding when file content is available', () => {
  const content = Array.from({ length: 12 }, (_, i) => `line${i + 1}`).join('\n');
  const text = buildFeedback([finding('py/sql-injection', 6)], new Map([['a.py', content]]), { linesAround: 2 });
  const start = text.indexOf('SNIPPET: a.py');
  assert.equal(
    text.slice(start),
    ['SNIPPET: a.py', '<<<', '    4 | line4', '    5 | line5', '    6 | line6', '    7 | line7', '    8 | line8', '>>>'].join('\n'),
  );

  // Clamped at the file edges, and rendered in the must-fix section too.
  const edge = buildFeedback([finding('python-syntax', 1, { hardReject: true })], new Map([['a.py', 'only\nthree\nlines']]), { linesAround: 6 });
  assert.ok(edge.endsWith(['SNIPPET: a.py', '<<<', '    1 | only', '    2 | three', '    3 | lines', '>>>'].join('\n')));
});

test('snippets are omitted for files without content', () => {
  const text = buildFeedback([SQLI, finding('py/sql-injection', 3, { file: 'b.py' })], new Map([['b.py', 'l1\nl2\nl3']]));
  assert.equal(text.match(/^SNIPPET: /gm).length, 1);
  assert.match(text, /^SNIPPET: b\.py$/m);
  assert.doesNotMatch(buildFeedback([SQLI, BROKEN], NO_FILES), /SNIPPET|<<<|>>>/);
});

test('the listing cap never crowds out hard rejects and reports the remainder', () => {
  const hints = Array.from({ length: 5 }, (_, i) => finding('py/sql-injection', 10 + i));
  const rejects = [BROKEN, finding('go-syntax', 1, { file: 'm.go', hardReject: true })];

  // Hard rejects arrive after the cap would already be full.
  const capped = buildFeedback([...hints, ...rejects], NO_FILES, { maxListedViolations: 3 });
  assert.equal(capped.split('\n')[0], 'Security analysis found 7 finding(s): 2 must be fixed, 5 to weigh.');
  assert.match(capped, /^1\. \[python-syntax\]/m);
  assert.match(capped, /^2\. \[go-syntax\]/m);
  assert.match(capped, /^3\. \[py\/sql-injection\] .* @ a\.py:10$/m);
  assert.equal(capped.match(/^\d+\. \[/gm).length, 3);
  assert.ok(capped.includes(`${WEIGH_HEADING} (5)`));
  assert.ok(capped.endsWith('\n…and 4 more'));

  // A cap smaller than the hard rejects still lists every one of them.
  const tight = buildFeedback([...hints, ...rejects], NO_FILES, { maxListedViolations: 1 });
  assert.equal(section(tight, MUST_FIX_HEADING).match(/^\d+\. \[/gm).length, 2);
  assert.equal(section(tight, WEIGH_HEADING).match(/^\d+\. \[/gm), null);
  assert.ok(tight.endsWith('\n…and 5 more'));

  // Under the cap: no remainder line.
  assert.doesNotMatch(buildFeedback([...hints, ...rejects], NO_FILES), /more$/m);
});

test('syntax hints describe a file on disk, not a resent candidate', () => {
  const expected = {
    'python-syntax': 'The Python file does not parse. Fix the syntax error.',
    'javascript-syntax': 'The JavaScript file does not parse. Fix the syntax error.',
    'go-syntax': 'The Go file does not parse. Fix the syntax error.',
    'c-syntax': 'The C file does not compile. Fix the syntax error.',
    'cpp-syntax': 'The C++ file does not compile. Fix the syntax error.',
  };
  for (const [ruleId, hint] of Object.entries(expected)) {
    assert.equal(hintForRule(ruleId), hint);
    assert.doesNotMatch(hintForRule(ruleId), /resend|complete file|escaped string/i);
  }
  // The other curated hints are untouched.
  assert.match(hintForRule('py/sql-injection'), /^Do not concatenate user input into SQL\./);
  assert.match(hintForRule('js/path-injection'), /server-side allowlist/);
});

test('violationKey is stable: rule, message, file and line range', () => {
  const v = { rule: { id: 'py/sql-injection' }, message: 'm', location: { file: 'a.py', startLine: 3, endLine: 3 }, hardReject: false };
  assert.equal(violationKey(v), 'py/sql-injection|m|a.py|3|3');
  assert.equal(violationKey({ ...v, hardReject: true }), 'py/sql-injection|m|a.py|3|3');
  assert.equal(violationKey({ rule: { id: 'python-syntax' }, message: 'bad', location: { file: 'b.py', startLine: 1 } }), 'python-syntax|bad|b.py|1|');
});
