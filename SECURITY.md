# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/securecoder-project/securecoder-plugin/security/advisories/new).
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
  or environment variables. `securecoder doctor` lists any ignored keys. A file named by
  `SECURECODER_CONFIG` stands in for `.securecoder.json` and is treated the same way.
- **A repository file cannot switch SecureCoder off.** `enabled` and `mode` may be strengthened by
  `.securecoder.json` or `.securecoder.local.json`, but a value that would take either below what
  the defaults and your user config give is ignored, with a warning in `/securecoder` and
  `securecoder doctor` that names the key and the scope. The CLI refuses to write such a value.
  The agent being checked can write both files, so they do not get to decide this. Turning
  SecureCoder off, or lowering an `enforce` you set in user config, takes user config or the
  `SECURECODER_ENABLED` / `SECURECODER_MODE` environment variables. Environment variables take
  precedence over every file. The floor is your user config, not the project file: a local file
  may undo strengthening that the project file added.
- **Repository config can still weaken analysis.** Only those two keys have a floor. A repository
  file can raise `severity_threshold`, remove `analyzers`, add `exclude_patterns`, or switch off
  individual hooks (`hooks.post_edit`, `hooks.shell_guard`, `hooks.user_prompt`), and through those
  it can narrow the post-edit scan or stop it. That is intentional, since teams tune these per
  project, and `/securecoder` shows each value's source. User config is not a floor for them,
  because project config takes precedence over it. Where you need a value no repository can
  lower, set the environment variable (`SECURECODER_SEVERITY`, `SECURECODER_POST_EDIT`,
  `SECURECODER_SHELL_GUARD`, `SECURECODER_USER_PROMPT`); `analyzers` and `exclude_patterns` have
  none.
- **Agents cannot change settings through MCP.** The `securecoder_config` tool is read-only. Changes
  go through the CLI, which runs as a normal shell command subject to your harness's approval
  settings, and the `/securecoder` skill is user-invoked only.
- **"Do not change settings" is an instruction, not a mechanism.** The `securecoder-remediator`
  agent and the MCP server's instructions tell the model never to change settings, exclusions, or
  the threshold to make findings go away. Nothing enforces that. The remediator holds Bash, Write,
  and Edit (it needs Bash to fall back to `securecoder scan` when the MCP tool is unavailable), and
  any agent that can write files can edit a project config file. Since 0.3.0 such an edit cannot
  turn SecureCoder off or lower `mode`. Exclusions, the threshold, the analyzer list, and the hook
  toggles in project config remain editable by it.
- **Hook responses are acted on by the harness; verdicts are advice.** `mode` decides what the
  hooks return, and the harness acts on it: added context, a blocked turn, or an approval prompt.
  The per-prompt constraints are injected the same way on Claude Code and Codex; elsewhere they
  depend on the model loading the `secure-codegen` skill. The retry limits and the verdict
  `securecoder_analyze` returns are text for the model. SecureCoder does not run the fix loop and
  cannot stop it.
- **Hooks fail open.** A crashing analyzer or malformed payload never blocks your agent. In enforce
  mode, the block comes from findings, not from errors. Each fault appends one line to
  `.securecoder/errors.log` in the project (capped at 64 KiB, newest kept), and `securecoder doctor`
  reports the count and the most recent entry, so a hook that has been failing does not look like
  clean code forever. A semgrep or bandit run that crashes, times out, or cannot load its ruleset
  counts as a fault of that analyzer, not as "no findings". The trail has limits: it cannot show a
  hook that was never invoked, and an analyzer that is simply not installed is skipped without an
  entry (`doctor` lists what is installed). SecureCoder is a guardrail and does not replace code
  review.
