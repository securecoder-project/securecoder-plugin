// Port of engine/workflow FeedbackBuilder.kt — turns guardian violations into
// remediation feedback for the coding agent: dedup + prioritization, per-rule
// targeted guidance, and numbered code snippets around each finding.
//
// Unlike the engine's builder, the output is split in two. Hard rejects (the
// file does not parse) are mandatory. Everything else is presented as hints to
// weigh: telling the agent to fix every finding makes it patch false positives
// and change behavior it should have left alone. The split is fixed, not a
// setting.

'use strict';

// Section headings and preambles. Plain text, stable strings: this is read raw
// by a model and matched by tests.
const MUST_FIX_HEADING = 'MUST FIX';
const WEIGH_HEADING = 'WEIGH THESE';
const MUST_FIX_PREAMBLE = 'Each of these means a file does not parse or compile. Fix them first: nothing else can be judged until every file parses.';
// The rule for every finding that is not a hard reject. The post-edit hook's
// advisory suffix (hook-io.js) reuses it so both channels say the same thing.
const TRIAGE_RULE = 'Weigh each one against the code: fix it if it is a real, exploitable issue you can fix without changing documented behavior; otherwise do not patch it, and say why you are dismissing it ("false positive because …").';
const WEIGH_PREAMBLE = `These are analyzer hints, not verdicts. ${TRIAGE_RULE}`;
// Per-rule hints are advice on how to fix, not a reason to fix; the label in
// the hints section says so.
const GUIDANCE_LABEL = 'Targeted guidance:';
const WEIGH_GUIDANCE_LABEL = 'Targeted guidance for the ones you fix:';

// Curated remediation hints per rule id, ported from FeedbackBuilder.hintForRule.
// The *-syntax hints are reworded: the engine asked an LLM to resend a whole
// file, while here the agent edits real files on disk.
function hintForRule(ruleId) {
  if (ruleId === 'py/stack-trace-exposure') {
    return 'Do not return exception messages or stack traces to the client. Log details internally and send a generic error response.';
  }
  if (ruleId === 'py/sql-injection') {
    return 'Do not concatenate user input into SQL. Use parameterized queries or prepared statements for every untrusted value.';
  }
  if (ruleId === 'py/ldap-injection') {
    return 'Escape untrusted LDAP filter components or use safe query-building APIs; do not splice request values directly into LDAP filters or DNs.';
  }
  if (ruleId === 'py/polynomial-redos' || ruleId === 'py/redos' || ruleId.includes('redos') || ruleId.includes('regex-injection')) {
    return 'Avoid compiling or executing user-controlled regular expressions. Treat user input as literal text, use a strict allowlist parser, or support only a fixed set of server-defined patterns.';
  }
  if (ruleId === 'python-syntax') {
    return 'The Python file does not parse. Fix the syntax error.';
  }
  if (ruleId === 'javascript-syntax') {
    return 'The JavaScript file does not parse. Fix the syntax error.';
  }
  if (ruleId === 'go-syntax') {
    return 'The Go file does not parse. Fix the syntax error.';
  }
  if (ruleId === 'c-syntax') {
    return 'The C file does not compile. Fix the syntax error.';
  }
  if (ruleId === 'cpp-syntax') {
    return 'The C++ file does not compile. Fix the syntax error.';
  }
  if (ruleId.includes('path-injection')) {
    return 'Do not keep iterating on basename/realpath/commonpath/startswith checks alone. Replace user-controlled file paths with a server-side allowlist or map user input to fixed known files or IDs instead of opening arbitrary paths.';
  }
  if (ruleId.includes('url-redirection')) {
    return 'Do not redirect to arbitrary external URLs from user input. Prefer fixed internal routes or a server-side allowlist of exact destinations; relative internal paths are safer than validating free-form URLs.';
  }
  if (ruleId.includes('ssrf') || ruleId.includes('server-side-request-forgery')) {
    return 'Do not let user input directly choose remote hosts, schemes, or redirect targets. Map user input to fixed server-side destinations or enforce a strict allowlist that removes attacker control over the final URL.';
  }
  if (ruleId.includes('code-injection')) {
    return 'Do not use exec, eval, dynamic import strings, template evaluation, shell execution, or subprocess on user input. Replace dynamic execution with a fixed allowlist or a dedicated parser for the tiny set of supported operations.';
  }
  if (ruleId.includes('unsafe-deserialization')) {
    return 'Do not deserialize user-controlled data with unsafe object loaders. Switch to a safe data format such as JSON or a safe YAML loader and validate the decoded structure before use.';
  }
  if (ruleId.includes('reflective-xss') || ruleId.includes('jinja2') || ruleId.includes('bad-tag-filter')) {
    return 'Escape untrusted values before embedding them into HTML, templates, or browser-executed responses. Prefer plain text or structured JSON over reflecting raw user input into executable browser contexts.';
  }
  if (ruleId.includes('header-injection') || ruleId.includes('http-response-splitting')) {
    return 'Do not place raw user input into HTTP headers. Validate against a strict allowlist and reject CR, LF, and other header-control characters.';
  }
  if (ruleId.includes('log-injection') || ruleId.includes('clear-text-logging-sensitive-data')) {
    return 'Do not log raw attacker-controlled strings or sensitive values. Remove CR/LF and other control characters from log fields, and mask or omit secrets before logging.';
  }
  if (ruleId.includes('xpath-injection')) {
    return 'Do not splice user input into XPath strings. Use variables, bound parameters, or a fixed server-side expression that treats input as data.';
  }
  if (ruleId.includes('weak-crypto-key') || ruleId.includes('weak-sensitive-data-hashing') || ruleId.includes('insecure-protocol') || ruleId.includes('insecure-default-protocol')) {
    return 'Keep the requested algorithm and API contract, but upgrade the weak cryptography: use adequate key sizes, secure randomness, modern hashing or password-hashing primitives, and secure protocol defaults.';
  }
  if (ruleId.includes('overly-permissive-file')) {
    return 'Create or update files with the minimum required permissions only. Prefer owner-only read/write permissions unless the prompt explicitly requires broader access.';
  }
  if (ruleId.includes('command-line-injection') || ruleId.includes('shell-command-constructed-from-input')) {
    return 'Do not send user input through shell parsing. Use constant commands with argument-separated APIs, or replace shell execution with direct filesystem or process APIs.';
  }
  if (ruleId.includes('hardcoded-credentials')) {
    return 'Do not leave real secrets in source code. Pull credentials from environment variables, secret stores, or caller-provided secure inputs.';
  }
  return null;
}

function violationKey(v) {
  return [v.rule.id, v.message, v.location.file, v.location.startLine, v.location.endLine].join('|');
}

// Dedup identical findings, preserving first-seen order.
function prioritizeViolations(violations) {
  const seen = new Map();
  for (const v of violations) {
    const key = violationKey(v);
    if (!seen.has(key)) seen.set(key, v);
  }
  return [...seen.values()];
}

function makeSnippet(fileContent, startLine, endLine, linesAround) {
  const lines = fileContent.split('\n');
  const clamp = (n) => Math.min(Math.max(n, 1), lines.length);
  const from = clamp((startLine || 1) - linesAround);
  const to = clamp((endLine || startLine || 20) + linesAround);
  const out = [];
  for (let i = from; i <= to; i++) {
    out.push(`${String(i).padStart(5)} | ${lines[i - 1]}`);
  }
  return out.join('\n');
}

// One section: heading with its count, preamble, the de-duplicated hints for
// the rules in it, then the listed entries. `firstNumber` keeps the numbering
// continuous across sections so "finding 3" is unambiguous.
function renderSection({ heading, preamble, guidanceLabel, violations, listed, firstNumber }, fileContents, linesAround) {
  const lines = [`${heading} (${violations.length})`, preamble];
  const ruleHints = [...new Set(violations.map((v) => v.rule.id))]
    .map(hintForRule)
    .filter(Boolean);
  if (ruleHints.length > 0) {
    lines.push(guidanceLabel);
    for (const hint of [...new Set(ruleHints)]) lines.push(`- ${hint}`);
  }
  listed.forEach((v, idx) => {
    const loc = [v.location.file, v.location.startLine].filter((x) => x != null).join(':');
    lines.push(`${firstNumber + idx}. [${v.rule.id}] ${v.message} @ ${loc}`);
    const content = fileContents.get(v.location.file);
    if (content != null) {
      lines.push(`SNIPPET: ${v.location.file}`);
      lines.push('<<<');
      lines.push(makeSnippet(content, v.location.startLine, v.location.endLine, linesAround));
      lines.push('>>>');
    }
  });
  return lines;
}

// violations: Violation[]; fileContents: Map<rel path, content>
function buildFeedback(violations, fileContents, { maxListedViolations = 20, linesAround = 6 } = {}) {
  const prioritized = prioritizeViolations(violations);
  const mustFix = prioritized.filter((v) => v.hardReject === true);
  const weigh = prioritized.filter((v) => v.hardReject !== true);
  // Hard rejects are always listed; the cap only ever trims the weigh section.
  const weighListed = weigh.slice(0, Math.max(0, maxListedViolations - mustFix.length));

  const counts = [];
  if (mustFix.length > 0) counts.push(`${mustFix.length} must be fixed`);
  if (weigh.length > 0) counts.push(`${weigh.length} to weigh`);
  const lines = [`Security analysis found ${prioritized.length} finding(s)${counts.length > 0 ? `: ${counts.join(', ')}` : ''}.`];

  if (mustFix.length > 0) {
    lines.push('');
    lines.push(...renderSection({
      heading: MUST_FIX_HEADING,
      preamble: MUST_FIX_PREAMBLE,
      guidanceLabel: GUIDANCE_LABEL,
      violations: mustFix,
      listed: mustFix,
      firstNumber: 1,
    }, fileContents, linesAround));
  }
  if (weigh.length > 0) {
    lines.push('');
    lines.push(...renderSection({
      heading: WEIGH_HEADING,
      preamble: WEIGH_PREAMBLE,
      guidanceLabel: WEIGH_GUIDANCE_LABEL,
      violations: weigh,
      listed: weighListed,
      firstNumber: mustFix.length + 1,
    }, fileContents, linesAround));
    if (weigh.length > weighListed.length) {
      lines.push(`…and ${weigh.length - weighListed.length} more`);
    }
  }
  return lines.join('\n');
}

module.exports = {
  buildFeedback,
  prioritizeViolations,
  hintForRule,
  violationKey,
  MUST_FIX_HEADING,
  WEIGH_HEADING,
  MUST_FIX_PREAMBLE,
  WEIGH_PREAMBLE,
  TRIAGE_RULE,
};
