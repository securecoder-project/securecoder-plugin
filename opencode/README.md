# SecureCoder for OpenCode

`index.js` is a native [OpenCode plugin](https://opencode.ai/docs/plugins/) built on the same analysis pipeline as the other harnesses. When OpenCode loads it, it:

- registers the `securecoder-analysis` MCP server (unless your `opencode.json` already defines one with that name)
- adds the `/securecoder` (settings) and `/secure-codegen` commands, and the `securecoder-remediator` subagent (`@securecoder-remediator`). Entries you already defined with those names are left untouched
- scans every file changed by `write`, `edit`, `multiedit`, or `patch` and appends findings to that tool's result, so the model sees them right away
- runs the shell guard on `bash`: in advisory mode a note is appended to the command output; in enforce mode a flagged command is refused before it runs

It has no dependencies and needs only Node-compatible built-ins (OpenCode runs plugins on Bun).

## Install from a checkout

```shell
git clone https://github.com/parsakaz/securecoder-claude-plugin ~/.local/share/securecoder
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
- Settings are shared with every other harness: the same `.securecoder.json`, `.securecoder.local.json`, and `~/.config/securecoder/config.json`.
