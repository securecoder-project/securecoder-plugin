---
description: >
    Security-aware code generation. Auto-invoked whenever writing, refactoring, or reviewing
    code — injects security constraints before generation and attaches SAST findings after.
    Use explicitly via /securecoder:secure-codegen to trigger the full pipeline manually.
---

# SecureCoder: Secure Code Generation Skill

You are generating code with security as a first-class constraint, not an afterthought.

## Pre-Generation Constraint Injection

If the `securecoder_enrich_prompt` MCP tool is available, pass the user's task description
through it first and honor every injected constraint — they are contract-preserving rules
(keep names, signatures, sync/async behavior, and requested algorithms exact; fix only the
unsafe part).

Then, before writing ANY code, reason through the following security properties for the task at hand:

### Threat Modelling (brief, inline)

- What is the trust boundary for this code? (user input? external API? filesystem?)
- What's the worst-case exploitation if this code has a bug? (RCE, data leak, privilege escalation, DoS?)
- Which OWASP Top 10 categories are relevant here?

### Mandatory Constraints by Code Category

**Input handling / parsing**

- All external input MUST be validated and sanitized before use
- Prefer allowlists over denylists
- Never pass raw user input to shell commands, SQL, or eval-equivalent calls
- Use parameterized queries / prepared statements, no string interpolation into queries

**Authentication / authorization**

- Fail closed: deny by default, grant explicitly
- Do not roll custom crypto — use established libraries (libsodium, bcrypt, argon2, etc.)
- Secrets (tokens, passwords, keys) never in source code, env vars or secret manager only

**Memory / resource safety** (C/C++/Rust unsafe)

- Annotate all unsafe blocks with a SAFETY comment explaining the invariant
- Prefer bounded operations; flag all unbounded loops / allocations

**Serialization / deserialization**

- Validate schema before deserializing untrusted data
- Never deserialize arbitrary objects from untrusted sources (Java ObjectInputStream, Python pickle, etc.)

**Concurrency**

- Identify all shared mutable state; prefer immutable data or ownership-based concurrency
- Flag potential TOCTOU conditions

**Dependencies**

- Flag any new dependency introduced; note the purpose and whether a stdlib alternative exists
- Prefer pinned versions

## Generation Mode

Write the code. Embed inline security comments (`// SECURITY:`, or `) at any point where a security decision was made — e.g., why a particular sanitization was chosen, why a particular algorithm, why a boundary check exists. These comments are not noise; they are the audit trail.

## Post-Generation Self-Review Checklist

After writing the code, run through this checklist and emit findings as a compact block:

```
SECURITY REVIEW:
[ ] No injection sinks with unvalidated input (SQL, shell, eval, template)
[ ] No hardcoded secrets or credentials
[ ] Error paths don't leak sensitive info in messages/logs
[ ] All external data validated at trust boundary
[ ] Crypto: using established library, appropriate algorithm
[ ] Dependencies: no unnecessary additions
[ ] [language-specific] <add any language-specific check relevant to the task>

FINDINGS: <none | list any issues found, each with severity HIGH/MED/LOW>
```

If any HIGH severity finding exists, STOP and fix before presenting the code.

## Static Analyzer Integration

After each file write, the PostToolUse hook runs the fast SecureCoder guardians (syntax
hard-reject checks, semgrep, bandit) and injects any findings into context automatically.

For deep analysis, call the `securecoder_analyze` MCP tool with `deep: true` — this runs
CodeQL with security-extended query suites (slow: builds a CodeQL database).

When findings are present, invoke the `securecoder-remediator` agent to run the fix →
re-analyze loop. It uses `securecoder_analyze` with a session id so the server tracks
attempts against the configured soft/hard retry limits.

## $ARGUMENTS

If arguments are provided, treat them as additional security context or a specific security requirement to enforce (e.g., "enforce FIPS 140-2", "PCI-DSS scope", "no external network calls").
