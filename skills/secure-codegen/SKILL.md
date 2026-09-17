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

## 1. Before writing code

If the `securecoder_enrich_prompt` MCP tool is available, pass the task description through it
and honor every constraint it returns. The constraints preserve the contract: keep names,
signatures, sync/async behavior, and requested algorithms exactly, and change only the unsafe part.

Then do a short inline threat model:

- Where is the trust boundary (user input, external API, filesystem, environment)?
- What is the worst outcome if this code is wrong (RCE, data leak, privilege escalation, DoS)?
- Which OWASP Top 10 / CWE categories apply?

## 2. Constraints by code category

**Input handling and parsing**
- Validate external input at the trust boundary. Prefer allowlists over denylists.
- Never pass raw input to a shell, SQL, `eval`, a template engine, or a file path.
- Use parameterized queries or prepared statements. Never interpolate into queries.

**Authentication and authorization**
- Fail closed: deny by default, grant explicitly.
- Use established libraries for crypto and password hashing (libsodium, argon2, bcrypt). Never
  write custom crypto.
- Keep secrets out of source code. Read them from the environment or a secret manager.

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

## 3. While writing

Add a short `SECURITY:` comment (in the language's comment syntax) wherever you make a
security decision, such as a sanitization choice, an algorithm, or a boundary check. These
comments are the audit trail. Don't add them to routine code.

## 4. After writing

SecureCoder's post-edit hook scans every file you write with fast analyzers (syntax, semgrep,
bandit) on harnesses that support hooks, and adds any findings to your context. Fix those findings
before moving on, or explain why one is a false positive.

For code where a missed issue would be costly, or when the user asks for a thorough check, call
`securecoder_analyze` with `deep: true` to include CodeQL. It is slow because it builds a database.

When findings remain, delegate to the `securecoder-remediator` agent, or run the loop yourself:
call `securecoder_analyze` with one stable `session` id, fix, re-analyze, and follow the verdict
it returns.

Finish with a compact self-review:

```
SECURITY REVIEW
[ ] No injection sinks reachable with unvalidated input (SQL, shell, eval, template, path)
[ ] No hardcoded secrets or credentials
[ ] Error paths don't leak sensitive details
[ ] External data validated at the trust boundary
[ ] Crypto uses an established library and a current algorithm
[ ] No unnecessary new dependencies
FINDINGS: none | <severity-tagged list>
```

If a HIGH finding remains, fix it before presenting the code.
