---
name: securecoder
description: View and change SecureCoder security settings (on/off, advisory or enforce mode, severity threshold, analyzers, CodeQL, semgrep ruleset, exclusions, retry limits), scan changed files, or check analyzer installation. Use only when the user invokes /securecoder or explicitly asks to configure SecureCoder.
argument-hint: "[status|on|off|mode|severity|analyzers|deep|ruleset|limits|exclude|hooks|scan|doctor|init|reset|keys|help] [value] [--scope user|project|local]"
disable-model-invocation: true
allowed-tools: Bash(securecoder *) Bash(node *bin/securecoder *) mcp__plugin_securecoder_securecoder-analysis__securecoder_config mcp__plugin_securecoder_securecoder-analysis__securecoder_status
---

# /securecoder

The user's arguments: `$ARGUMENTS`

You are the front end for SecureCoder's settings. Every read and write goes through the
`securecoder` CLI, which validates values, applies the scope rules, and prints the result.
Your job is to translate the arguments into **one CLI call** (two for `limits` and mixed
`analyzers` edits), run it, and show its output.

## Running the CLI

- Run `securecoder <args>` as a plain, standalone command (Claude Code puts it on PATH). Don't
  chain it with `||`, `&&`, `;`, pipes, or `echo`: the exit code comes back to you anyway, and a
  compound command needs extra permission prompts.
- Only if that fails with "command not found", run `node "<plugin root>/bin/securecoder" <args>`.
  The plugin root is two directories above this skill's folder. The `securecoder_config` MCP
  tool output ends with the exact command line to use.
- Single-quote every value that contains `*`, `?`, spaces, or `$` so the shell passes it through
  unchanged (for example `'*.gen.ts'`).
- Pass `--scope` only when the user gave one. Without it the CLI writes to `local`
  (`.securecoder.local.json`, personal) inside a project and to `user` elsewhere.

## Argument mapping

| User types | Run |
| --- | --- |
| *(nothing)*, `status` | `securecoder status`, then open the interactive menu below |
| `on` / `off` | `securecoder config set enabled on` / `… enabled off` |
| `mode advisory` / `mode enforce` | `securecoder config set mode <value>` |
| `severity low\|medium\|high` | `securecoder config set severity_threshold <value>` |
| `analyzers syntax,semgrep` | `securecoder config set analyzers syntax,semgrep` |
| `analyzers +bandit -semgrep` | `securecoder config add analyzers bandit`, then `securecoder config remove analyzers semgrep` |
| `deep on` / `deep off` | `securecoder config add deep_analyzers codeql` / `securecoder config remove deep_analyzers codeql` |
| `ruleset <id or path>` | `securecoder config set semgrep_config '<value>'` |
| `limits <soft> <hard>` | `securecoder config set retry.soft_limit <soft>`, then `securecoder config set retry.hard_limit <hard>` |
| `exclude add <glob>` / `exclude remove <glob>` | `securecoder config add exclude_patterns '<glob>'` / `… remove exclude_patterns '<glob>'` |
| `exclude list` | `securecoder config get exclude_patterns` |
| `hooks post-edit on\|off` | `securecoder config set hooks.post_edit <on\|off>` |
| `hooks shell-guard on\|off` | `securecoder config set hooks.shell_guard <on\|off>` |
| `get <key>` / `set <key> <value>` / `unset <key>` | `securecoder config get\|set\|unset <key> [value]` |
| `scan [paths…] [--deep]` | `securecoder scan [--deep] [paths…]` (no paths: files changed since HEAD) |
| `doctor` | `securecoder doctor` |
| `init` | `securecoder config init --scope project`, then ask whether to also run `securecoder config gitignore` |
| `reset <key>` | `securecoder config unset <key>` |
| `reset` | Ask which scope to clear (user, project, or local) and confirm, then `securecoder config reset --scope <scope>` |
| `keys`, `help` | `securecoder config keys`, followed by a short list of the subcommands above |

If the arguments match nothing here, run `securecoder config keys` and suggest the closest
subcommand. Don't guess at a write.

## Showing results

- Show the CLI output as-is. It is Markdown and already has the values, sources, and file paths.
- Relay every line that starts with `⚠` or `Note:` exactly; don't soften or drop it. A `⚠` line
  means the change reduced protection. A `Note:` line means a higher-precedence scope or
  environment variable still overrides the value.
- On exit code 2 (invalid key or value), show the error and the allowed values, then ask what
  the user meant. Do not retry with a guess.
- For `scan`: summarize the findings by severity. If there are any, offer to fix them with the
  `securecoder-remediator` agent (or a `securecoder_analyze` fix-and-recheck loop using one
  session id).

## Interactive menu (no arguments)

After showing the dashboard, ask what to change. Use a multiple-choice question tool if you have
one; otherwise show a numbered list and wait for the reply:

1. **Protection level**: turn SecureCoder on or off, switch advisory ↔ enforce, change the
   severity threshold
2. **Analyzers**: choose fast analyzers, turn deep CodeQL on or off, change the semgrep ruleset
3. **Scope of analysis**: exclusions, retry limits, post-edit scan and shell-guard hooks
4. **Nothing**: leave settings unchanged

Ask one follow-up question to get the concrete value, run the matching command from the table,
and show the updated line. Use the current values from the dashboard as the default choice.
Also ask which scope to write to (local = just me in this repo, project = shared with the team
via `.securecoder.json`, user = all my projects).

## Rules

- Change settings only because the user asked in this command. Never change them to hide findings.
- Never edit `.securecoder*.json` or the user config file by hand. The CLI enforces validation
  and the trust rule: executable paths (`bins.*`, `codeql.binary`) and `trace_log` are accepted
  only in user scope.
- `enforce` blocks the agent until findings at or above the threshold are fixed, and makes risky
  shell commands require approval. Mention this when the user enables it.
