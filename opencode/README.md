# SecureCoder for OpenCode

`index.js` is a native [OpenCode plugin](https://opencode.ai/docs/plugins/) built on the same analysis pipeline as the other harnesses. When OpenCode loads it, it:

- registers the `securecoder-analysis` MCP server (unless your `opencode.json` already defines one with that name)
- adds the `/securecoder` (settings) and `/secure-codegen` commands, and the `securecoder-remediator` subagent (`@securecoder-remediator`). Entries you already defined with those names are left untouched
- scans every file changed by `write`, `edit`, `multiedit`, or `patch` and appends findings to that tool's result, so the model sees them right away
- runs the shell guard on `bash`: in advisory mode a note is appended to the command output; in enforce mode a flagged command is refused before it runs

It has no dependencies and needs only Node-compatible built-ins (OpenCode runs plugins on Bun).

## Install from a checkout

```shell
git clone https://github.com/securecoder-project/securecoder-plugin ~/.local/share/securecoder
mkdir -p ~/.config/opencode/plugins
printf 'export * from "%s";\nexport { default } from "%s";\n' \
  ~/.local/share/securecoder/opencode/index.js ~/.local/share/securecoder/opencode/index.js \
  > ~/.config/opencode/plugins/securecoder.js
```

For a single project, write the same loader to `.opencode/plugins/securecoder.js` in that project instead.

Update later with `git -C ~/.local/share/securecoder pull`.

## Install from npm

Once the package is published, add it to `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["securecoder-agent-plugin"]
}
```

## Differences from Claude Code

- OpenCode has no hook that can block after a tool has run. In enforce mode, post-edit findings are appended with stronger wording rather than blocking the turn.
- OpenCode has no documented per-prompt hook, so SecureCoder does not add its secure-coding constraints to every prompt here as it does on Claude Code and Codex. The constraints reach the model through the `/secure-codegen` command, and `hooks.user_prompt` has no effect.
- Settings are shared with every other harness: the same `.securecoder.json`, `.securecoder.local.json`, and `~/.config/securecoder/config.json`. That includes the rule that a file inside the repository cannot turn SecureCoder off or lower `mode`.
- The scan and the shell guard fail open here too. A fault in either is logged to OpenCode and appended to `.securecoder/errors.log` in the project, and `securecoder doctor` reports it.
