---
name: secure-codegen
description: Security-aware code generation. Use whenever writing, refactoring, or reviewing code that handles untrusted input, authentication, secrets, cryptography, file paths, shell or SQL execution, deserialization, or network requests. Injects security constraints before generation and runs SecureCoder analysis after.
argument-hint: "[extra security requirement, e.g. \"PCI-DSS scope\" or \"no outbound network calls\"]"
---

# SecureCoder: secure code generation

Treat security as a first-class requirement of the task.

Extra security context from the user (may be empty): $ARGUMENTS

Enforce any extra context as a hard requirement, for example "FIPS 140-2 algorithms only",
"PCI-DSS scope", or "no outbound network calls".

## 1. Core constraints

These hold for every coding task. On Claude Code and Codex a SecureCoder hook adds this same
block to every prompt, so you may already have it; this skill is the elaboration, not the only
carrier. On other harnesses, this is where you get it.

<!-- securecoder:constraints:start -->
SecureCoder secure-coding constraints. They apply when this request involves writing or changing code; otherwise ignore them.
- Preserve the requested contract: names, signatures, return types, output formats and documented behavior. Never weaken functionality for security, and never add behavior that was not asked for.
- Validate and canonicalize untrusted input at the trust boundary; enforce containment or allowlists for file paths and URLs.
- Use parameterized queries and argument-vector process APIs; never build SQL, shell commands, or eval/template input from untrusted strings.
- Escape or encode output for its sink; keep CR/LF and other control characters out of headers and log fields.
- Use safe parsers and deserializers for untrusted data.
- Use established, correctly parameterized cryptography; keep secrets out of source code.
<!-- securecoder:constraints:end -->

## 2. Before writing code

If the `securecoder_enrich_prompt` MCP tool is available, pass the task description through it
and honor every constraint it returns. The constraints preserve the contract: keep names,
signatures, sync/async behavior, and requested algorithms exactly, and change only the unsafe part.
When the task touches known weakness classes, the tool also returns a CWE checklist for them.
Use it as guidance while writing; it is not a list of findings.

Then do a short inline threat model:

- Where is the trust boundary (user input, external API, filesystem, environment)?
- What is the worst outcome if this code is wrong (RCE, data leak, privilege escalation, DoS)?
- Which OWASP Top 10 / CWE categories apply?

## 3. More by code category

What the core constraints do not already say:

**Input handling and parsing**
- Prefer allowlists over denylists.

**Authentication and authorization**
- Fail closed: deny by default, grant explicitly.
- Use established libraries for password hashing (libsodium, argon2, bcrypt). Never write custom
  crypto.
- Read secrets from the environment or a secret manager.

**Memory and resource safety** (C, C++, unsafe Rust)
- Give every `unsafe` block a SAFETY comment stating the invariant.
- Prefer bounded operations. Flag unbounded loops and allocations driven by input.

**Serialization**
- Validate the schema before deserializing untrusted data.
- Never deserialize arbitrary objects from untrusted sources (pickle, Java `ObjectInputStream`,
  unsafe YAML loaders).

**Concurrency**
- Identify shared mutable state. Prefer immutability or ownership-based designs.
- Watch for TOCTOU races on files and permissions.

**Dependencies**
- Justify every new dependency and note whether a standard-library alternative exists.
- Prefer pinned versions.

## 4. While writing

Add a short `SECURITY:` comment (in the language's comment syntax) wherever you make a
security decision, such as a sanitization choice, an algorithm, or a boundary check. These
comments are the audit trail. Don't add them to routine code.

## 5. After writing

SecureCoder's post-edit hook scans every file you write with fast analyzers (syntax, semgrep,
bandit) on harnesses that support hooks, and adds any findings to your context. They come in two
kinds:

- **Hard rejects** (the file does not parse) must be fixed.
- **Everything else is a hint to weigh.** Fix a finding when it is a real, exploitable issue that
  can be fixed without changing documented behavior. Dismiss anything else, and say why.

If SecureCoder is in enforce mode, the hook also holds the turn until findings at or above the
threshold are dealt with. Never change SecureCoder settings to get past it.

Hold analyzer findings and your own review to the same three rules:

- **Sink absence.** Never report a vulnerability whose sink category is absent from the code in
  front of you: no path traversal without filesystem access, no command injection without command
  execution, no SSRF or open redirect without a network or redirect sink.
- **No defense in depth.** Report exploitable issues with a concrete attacker-controlled path, not
  hardening opportunities.
- **Behavior preservation is a veto.** If it cannot be fixed without changing documented behavior,
  it is not a finding; it is a note.

For code where a missed issue would be costly, or when the user asks for a thorough check, call
`securecoder_analyze` with `deep: true` to include CodeQL. It is slow because it builds a database.

When findings worth fixing remain, delegate to the `securecoder-remediator` agent, or run the
loop yourself: call `securecoder_analyze` with one stable `session` id, fix, re-analyze, and
follow the verdict it returns.

Finish with a compact self-review:

```
SECURITY REVIEW
[ ] No injection sinks reachable with unvalidated input (SQL, shell, eval, template, path)
[ ] No hardcoded secrets or credentials
[ ] Error paths don't leak sensitive details
[ ] External data validated at the trust boundary
[ ] Crypto uses an established library and a current algorithm
[ ] No unnecessary new dependencies
FINDINGS: none | <severity-tagged list of exploitable issues>
DISMISSED: none | <finding: why it is not one>
NOTES: none | <issues that cannot be fixed without changing documented behavior>
```

If a real HIGH finding remains, fix it before presenting the code.
