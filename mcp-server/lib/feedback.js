// Port of engine/workflow FeedbackBuilder.kt — turns guardian violations into
// remediation feedback for the coding agent: dedup + prioritization, per-rule
// targeted guidance, and numbered code snippets around each finding.

'use strict';

// Curated remediation hints per rule id, ported verbatim from FeedbackBuilder.hintForRule.
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
  if (ruleId === 'source-escaped-output') {
    return 'Do not return code as an escaped string blob with literal \\n sequences. Send the real source file contents with actual newlines.';
  }
  if (ruleId === 'source-placeholder-output') {
    return "Do not return placeholders like '...' or '(same code)'. Send the complete final source file.";
  }
  if (ruleId === 'python-syntax') {
    return 'The Python file does not parse. Fix the syntax error and resend the complete file with valid Python syntax.';
  }
  if (ruleId === 'javascript-syntax') {
    return 'The JavaScript file does not parse. Fix the syntax error and resend the complete file, not an explanation or escaped string.';
  }
  if (ruleId === 'go-syntax') {
    return 'The Go file does not parse. Fix the syntax error and resend the complete file with valid Go syntax.';
  }
  if (ruleId === 'c-syntax') {
    return 'The C file does not compile cleanly. Fix the syntax error and resend the complete file with valid C syntax.';
  }
  if (ruleId === 'cpp-syntax') {
    return 'The C++ file does not compile cleanly. Fix the syntax error and resend the complete file with valid C++ syntax.';
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

// violations: Violation[]; fileContents: Map<rel path, content>
function buildFeedback(violations, fileContents, { maxListedViolations = 20, linesAround = 6 } = {}) {
  const lines = [];
  lines.push(`Security analysis found ${violations.length} violation(s). Address all of them.`);
  const ruleHints = [...new Set(violations.map((v) => v.rule.id))]
    .map(hintForRule)
    .filter(Boolean);
  if (ruleHints.length > 0) {
    lines.push('Targeted guidance:');
    for (const hint of [...new Set(ruleHints)]) lines.push(`- ${hint}`);
  }
  const prioritized = prioritizeViolations(violations);
  const listed = prioritized.slice(0, maxListedViolations);
  listed.forEach((v, idx) => {
    const loc = [v.location.file, v.location.startLine].filter((x) => x != null).join(':');
    lines.push(`${idx + 1}. [${v.rule.id}] ${v.message} @ ${loc}`);
    const content = fileContents.get(v.location.file);
    if (content != null) {
      lines.push(`SNIPPET: ${v.location.file}`);
      lines.push('<<<');
      lines.push(makeSnippet(content, v.location.startLine, v.location.endLine, linesAround));
      lines.push('>>>');
    }
  });
  if (prioritized.length > listed.length) {
    lines.push(`…and ${prioritized.length - listed.length} more`);
  }
  return lines.join('\n');
}

module.exports = { buildFeedback, prioritizeViolations, hintForRule, violationKey };
