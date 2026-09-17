# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/parsakaz/securecoder-claude-plugin/security/advisories/new).
Don't open a public issue. Include the harness (Claude Code, Codex, Cursor, OpenCode) and version,
the SecureCoder version (`securecoder --version`), and steps to reproduce. We aim to acknowledge
reports within 5 business days.

Only the latest release receives security fixes.

## Trust model

SecureCoder runs locally, with your user's permissions, inside the coding agent you install it in.

- **Hooks and the MCP server execute analyzers** (semgrep, bandit, CodeQL, and language syntax
  checkers) on files the agent edits. Everything happens on your machine. The exception is
  semgrep registry rulesets (`p/...`, the default `p/owasp-top-ten`), which semgrep downloads from
  semgrep.dev. Set `semgrep_config` to a local rules path to stay fully offline.
- **Repository config is untrusted.** `.securecoder.json` and `.securecoder.local.json` live in the
  repository, so a malicious clone controls them. Settings that select executables or arguments
  (`bins.*`, `codeql.binary`, `language_overrides.python.extra_args`) or write files (`trace_log`)
  are ignored in those files and honored only in user config (`~/.config/securecoder/config.json`)
  or environment variables. `securecoder doctor` lists any ignored keys.
- **Repository config can still weaken analysis**: turn SecureCoder off, raise the threshold, or add
  exclusions. That is intentional, since teams tune these per project, and every change is visible:
  `/securecoder` shows each value's source. Put `enabled`, `mode`, or `severity_threshold` in user
  config or the `SECURECODER_*` environment variables when you need a floor a repository can't
  lower. Environment variables take precedence over every file.
- **Agents cannot change settings through MCP.** The `securecoder_config` tool is read-only. Changes
  go through the CLI, which runs as a normal shell command subject to your harness's approval
  settings, and the `/securecoder` skill is user-invoked only.
- **Hooks fail open.** A crashing analyzer or malformed payload never blocks your agent. In enforce
  mode, the block comes from findings, not from errors. SecureCoder is a guardrail and does not
  replace code review.
