// SecureCoder for OpenCode.
//
// Registers, through OpenCode's plugin API:
//   - the securecoder-analysis MCP server (unless the user configured one)
//   - /securecoder (settings) and /secure-codegen commands, from the shared skills
//   - the securecoder-remediator subagent, from the shared agent definition
//   - a post-edit scan: findings are appended to the write/edit/patch tool result
//   - the shell guard: advisory notes are appended to the shell result; in enforce
//     mode a flagged command is blocked before it runs
//
// One default export serves both plugin APIs: OpenCode 2.x calls `setup(ctx)`
// and registers through its domain editors; OpenCode 1.x calls `server(input)`
// and gets the hook object with a `config` hook. Both read the same definitions.
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

const MCP_NAME = 'securecoder-analysis';
const AGENT_NAME = 'securecoder-remediator';

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

function mcpServer(directory) {
  return {
    type: 'local',
    command: ['node', join(PLUGIN_ROOT, 'mcp-server', 'index.js')],
    environment: { SECURECODER_PROJECT_DIR: directory },
  };
}

// The slash commands, as prompt templates. `$ARGUMENTS` stands for the text
// the user typed after the command name.
function commandDefinitions() {
  const settingsSkill = readMarkdown('skills/securecoder/SKILL.md');
  const codegenSkill = readMarkdown('skills/secure-codegen/SKILL.md');
  return [
    {
      name: 'securecoder',
      description: settingsSkill.meta.description,
      template: `On this machine the SecureCoder CLI is: ${cliCommand()}\nUse it wherever the instructions below say \`securecoder\`.\n\n${settingsSkill.body}`,
    },
    { name: 'secure-codegen', description: codegenSkill.meta.description, template: codegenSkill.body },
  ];
}

function agentDefinition() {
  const { meta, body } = readMarkdown('agents/securecoder-remediator.md');
  return {
    description: meta.description,
    prompt: `${body}\n\nOn this machine the SecureCoder CLI is: ${cliCommand()}`,
  };
}

// OpenCode 2.x hands a command its invocation prompt; the template expansion
// that 1.x did for config commands is ours to do. A leading "/name" is dropped
// in case the host passes the raw input.
function expandTemplate(template, name, promptText) {
  let args = typeof promptText === 'string' ? promptText.trim() : '';
  const prefix = `/${name}`;
  if (args === prefix || args.startsWith(`${prefix} `)) args = args.slice(prefix.length).trim();
  return template.split('$ARGUMENTS').join(args);
}

// OpenCode 2.x tool results carry the model-visible text in `content` (a
// string or a list of parts) next to a structured `output`. Returns a new
// result with `text` appended where the model will read it.
function appendToResult(result, text) {
  const base = result && typeof result === 'object' ? result : {};
  const { content, output } = base;
  if (typeof content === 'string') return { ...base, content: `${content}\n\n${text}` };
  if (Array.isArray(content)) return { ...base, content: [...content, { type: 'text', text }] };
  const parts = [];
  if (typeof output === 'string') parts.push({ type: 'text', text: output });
  else if (output !== undefined) parts.push({ type: 'text', text: JSON.stringify(output) });
  parts.push({ type: 'text', text });
  return { ...base, content: parts };
}

// The two tool hooks, shared by both plugin APIs. Each harness API passes the
// tool name, call id, and tool arguments; `deliver` splices text into the
// result in that API's shape.
function createToolHooks(projectDir, log) {
  const shellNotes = new Map();

  // Throws to block the call in enforce mode.
  const before = (tool, callID, args) => {
    if (!SHELL_TOOLS.has(tool)) return;
    let outcome;
    try {
      outcome = hooks.preShell({ args, cwd: projectDir }, { platform: 'opencode' });
    } catch (err) {
      log('warn', `shell guard error (ignored): ${err.message}`);
      hooks.recordError({ event: 'pre-shell', error: err, payload: { cwd: projectDir } });
      return;
    }
    if (!outcome.response) return;
    if (outcome.response.block) {
      throw new Error(`${outcome.response.text}\nSecureCoder is in enforce mode, so this command was not run. Use a safer command, or ask the user to run it themselves.`);
    }
    shellNotes.set(callID, outcome.response.text);
  };

  // Returns the text to append to the tool result, or null.
  const after = async (tool, callID, args) => {
    if (SHELL_TOOLS.has(tool)) {
      const note = shellNotes.get(callID);
      shellNotes.delete(callID);
      return note || null;
    }
    if (!EDIT_TOOLS.has(tool)) return null;
    try {
      const outcome = await hooks.postEdit(
        { args, cwd: projectDir },
        { platform: 'opencode', log: (m) => log('debug', m) },
      );
      return outcome.response ? outcome.response.text : null;
    } catch (err) {
      log('warn', `post-edit scan error (ignored): ${err.message}`);
      hooks.recordError({ event: 'post-edit', error: err, payload: { cwd: projectDir } });
      return null;
    }
  };

  const discard = (callID) => shellNotes.delete(callID);

  return { before, after, discard };
}

// ---------------------------------------------------------------------------
// OpenCode 1.x

function registerConfig(cfg, directory) {
  cfg.mcp = cfg.mcp || {};
  if (!cfg.mcp[MCP_NAME]) cfg.mcp[MCP_NAME] = { ...mcpServer(directory), enabled: true };

  cfg.command = cfg.command || {};
  for (const { name, description, template } of commandDefinitions()) {
    if (!cfg.command[name]) cfg.command[name] = { description, template };
  }

  cfg.agent = cfg.agent || {};
  if (!cfg.agent[AGENT_NAME]) {
    const { description, prompt } = agentDefinition();
    cfg.agent[AGENT_NAME] = { description, mode: 'subagent', prompt };
  }
}

export const SecureCoderPlugin = async ({ client, directory, worktree }) => {
  const projectDir = worktree || directory || process.cwd();

  const log = (level, message) => {
    try {
      const pending = client && client.app && client.app.log({ body: { service: 'securecoder', level, message } });
      if (pending && typeof pending.catch === 'function') pending.catch(() => {});
    } catch {
      // Logging must never break a tool call.
    }
  };

  const tools = createToolHooks(projectDir, log);

  return {
    config: async (cfg) => {
      try {
        registerConfig(cfg, projectDir);
      } catch (err) {
        log('error', `failed to register SecureCoder commands/agent/MCP: ${err.message}`);
      }
    },

    'tool.execute.before': async (input, output) => {
      tools.before(input.tool, input.callID, output && output.args);
    },

    'tool.execute.after': async (input, output) => {
      if (!output || typeof output.output !== 'string') {
        tools.discard(input.callID);
        return;
      }
      const text = await tools.after(input.tool, input.callID, input.args);
      if (text) output.output += `\n\n${text}`;
    },
  };
};

// ---------------------------------------------------------------------------
// OpenCode 2.x

// Names already taken are left alone, so a user's own command keeps winning.
async function existingCommandNames(ctx) {
  try {
    const listed = await ctx.command.list();
    const items = Array.isArray(listed) ? listed : (listed && Array.isArray(listed.data) ? listed.data : []);
    return new Set(items.map((c) => c && c.name).filter(Boolean));
  } catch {
    return new Set();
  }
}

// Not a named export: OpenCode 1.x calls every exported function as a plugin.
async function setup(ctx) {
  const location = (ctx && ctx.location) || {};
  const projectDir = (location.project && location.project.directory) || location.directory || process.cwd();

  // OpenCode 2.x has no logging API for plugins; warnings land in the server log.
  const log = (level, message) => {
    if (level === 'debug') return;
    try {
      console.error(`[securecoder] ${level}: ${message}`);
    } catch {
      // Logging must never break a tool call.
    }
  };

  const tools = createToolHooks(projectDir, log);

  const register = async (what, fn) => {
    try {
      await fn();
    } catch (err) {
      log('error', `failed to register SecureCoder ${what}: ${err.message}`);
    }
  };

  await register('MCP server', () => ctx.mcp.transform((editor) => {
    if (!editor.get(MCP_NAME)) editor.set(MCP_NAME, mcpServer(projectDir));
  }));

  const taken = await existingCommandNames(ctx);
  await register('commands', () => ctx.command.transform((editor) => {
    for (const { name, description, template } of commandDefinitions()) {
      if (taken.has(name)) continue;
      editor.add({
        name,
        description,
        execute: async (invocation) => {
          await ctx.session.prompt({
            sessionID: invocation.sessionID,
            text: expandTemplate(template, name, invocation.prompt && invocation.prompt.text),
            delivery: invocation.delivery,
          });
        },
      });
    }
  }));

  await register('agent', () => ctx.agent.transform((editor) => {
    if (editor.get(AGENT_NAME)) return;
    const { description, prompt } = agentDefinition();
    // update() on an unknown id creates the agent from OpenCode's defaults.
    editor.update(AGENT_NAME, (agent) => {
      agent.mode = 'subagent';
      agent.description = description;
      agent.system = prompt;
    });
  }));

  await register('tool hooks', async () => {
    await ctx.tool.hook('execute.before', async (event) => {
      tools.before(event.tool, event.id, event.input);
    });
    await ctx.tool.hook('execute.after', async (event) => {
      if (event.status !== 'completed') {
        tools.discard(event.id);
        return;
      }
      const text = await tools.after(event.tool, event.id, event.input);
      if (text) event.result = appendToResult(event.result, text);
    });
  });
}

export default { id: 'securecoder', setup, server: SecureCoderPlugin };
