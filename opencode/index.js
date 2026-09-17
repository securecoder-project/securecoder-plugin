// SecureCoder for OpenCode.
//
// Registers, through OpenCode's plugin API:
//   - the securecoder-analysis MCP server (unless the user configured one)
//   - /securecoder (settings) and /secure-codegen commands, from the shared skills
//   - the securecoder-remediator subagent, from the shared agent definition
//   - a post-edit scan: findings are appended to the write/edit/patch tool result
//   - the shell guard: advisory notes are appended to the bash result; in enforce
//     mode a flagged command is blocked before it runs
//
// Zero dependencies. The analysis code is the same CommonJS pipeline every
// other harness uses.

import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const hooks = require(join(PLUGIN_ROOT, 'mcp-server', 'lib', 'hooks.js'));

const EDIT_TOOLS = new Set(['write', 'edit', 'multiedit', 'patch', 'apply_patch']);
const SHELL_TOOLS = new Set(['bash', 'shell']);

// Splits a Markdown file with YAML frontmatter into { meta, body }. Only the
// flat `key: value` lines SecureCoder's own files use are parsed.
function readMarkdown(relPath) {
  const text = readFileSync(join(PLUGIN_ROOT, relPath), 'utf8');
  const match = text.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!match) return { meta: {}, body: text };
  const meta = {};
  for (const line of match[1].split(/\r?\n/)) {
    const kv = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (kv) meta[kv[1]] = kv[2].replace(/^["']|["']$/g, '');
  }
  return { meta, body: match[2] };
}

function cliCommand() {
  return `node "${join(PLUGIN_ROOT, 'bin', 'securecoder')}"`;
}

function registerConfig(cfg, directory) {
  cfg.mcp = cfg.mcp || {};
  if (!cfg.mcp['securecoder-analysis']) {
    cfg.mcp['securecoder-analysis'] = {
      type: 'local',
      command: ['node', join(PLUGIN_ROOT, 'mcp-server', 'index.js')],
      environment: { SECURECODER_PROJECT_DIR: directory },
      enabled: true,
    };
  }

  cfg.command = cfg.command || {};
  if (!cfg.command.securecoder) {
    const { meta, body } = readMarkdown('skills/securecoder/SKILL.md');
    cfg.command.securecoder = {
      description: meta.description,
      template: `On this machine the SecureCoder CLI is: ${cliCommand()}\nUse it wherever the instructions below say \`securecoder\`.\n\n${body}`,
    };
  }
  if (!cfg.command['secure-codegen']) {
    const { meta, body } = readMarkdown('skills/secure-codegen/SKILL.md');
    cfg.command['secure-codegen'] = { description: meta.description, template: body };
  }

  cfg.agent = cfg.agent || {};
  if (!cfg.agent['securecoder-remediator']) {
    const { meta, body } = readMarkdown('agents/securecoder-remediator.md');
    cfg.agent['securecoder-remediator'] = {
      description: meta.description,
      mode: 'subagent',
      prompt: `${body}\n\nOn this machine the SecureCoder CLI is: ${cliCommand()}`,
    };
  }
}

export const SecureCoderPlugin = async ({ client, directory, worktree }) => {
  const projectDir = worktree || directory || process.cwd();
  const shellNotes = new Map();

  const log = (level, message) => {
    try {
      const pending = client && client.app && client.app.log({ body: { service: 'securecoder', level, message } });
      if (pending && typeof pending.catch === 'function') pending.catch(() => {});
    } catch {
      // Logging must never break a tool call.
    }
  };

  return {
    config: async (cfg) => {
      try {
        registerConfig(cfg, projectDir);
      } catch (err) {
        log('error', `failed to register SecureCoder commands/agent/MCP: ${err.message}`);
      }
    },

    'tool.execute.before': async (input, output) => {
      if (!SHELL_TOOLS.has(input.tool)) return;
      let outcome;
      try {
        outcome = hooks.preShell({ args: output.args, cwd: projectDir }, { platform: 'opencode' });
      } catch (err) {
        log('warn', `shell guard error (ignored): ${err.message}`);
        return;
      }
      if (!outcome.response) return;
      if (outcome.response.block) {
        throw new Error(`${outcome.response.text}\nSecureCoder is in enforce mode, so this command was not run. Use a safer command, or ask the user to run it themselves.`);
      }
      shellNotes.set(input.callID, outcome.response.text);
    },

    'tool.execute.after': async (input, output) => {
      if (SHELL_TOOLS.has(input.tool)) {
        const note = shellNotes.get(input.callID);
        shellNotes.delete(input.callID);
        if (note && output && typeof output.output === 'string') output.output += `\n\n${note}`;
        return;
      }
      if (!EDIT_TOOLS.has(input.tool) || !output || typeof output.output !== 'string') return;
      try {
        const outcome = await hooks.postEdit(
          { args: input.args, cwd: projectDir },
          { platform: 'opencode', log: (m) => log('debug', m) },
        );
        if (outcome.response) output.output += `\n\n${outcome.response.text}`;
      } catch (err) {
        log('warn', `post-edit scan error (ignored): ${err.message}`);
      }
    },
  };
};

export default { id: 'securecoder', server: SecureCoderPlugin };
