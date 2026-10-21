// The core secure-coding constraints: the one block of text SecureCoder wants
// in front of the model for every coding request.
//
// It has two carriers and one source, this constant:
//   - the user-prompt hook (hooks.js userPrompt) injects it on every prompt,
//     which is the only delivery that does not depend on the model choosing to
//     load something;
//   - skills/secure-codegen/SKILL.md repeats it verbatim between the
//     `securecoder:constraints:start` / `:end` markers, for harnesses with no
//     per-prompt hook. A test compares the two, so edit both together.
//
// Keep it short. It is paid for on every prompt, and a long block is the
// quickest way to get `hooks.user_prompt` switched off. The first line scopes
// it, so it is harmless on a prompt that is not about code.

'use strict';

const SECURITY_CONSTRAINTS = [
  'SecureCoder secure-coding constraints. They apply when this request involves writing or changing code; otherwise ignore them.',
  '- Preserve the requested contract: names, signatures, return types, output formats and documented behavior. Never weaken functionality for security, and never add behavior that was not asked for.',
  '- Validate and canonicalize untrusted input at the trust boundary; enforce containment or allowlists for file paths and URLs.',
  '- Use parameterized queries and argument-vector process APIs; never build SQL, shell commands, or eval/template input from untrusted strings.',
  '- Escape or encode output for its sink; keep CR/LF and other control characters out of headers and log fields.',
  '- Use safe parsers and deserializers for untrusted data.',
  '- Use established, correctly parameterized cryptography; keep secrets out of source code.',
].join('\n');

// Ceiling for everything the user-prompt hook injects (this block plus the
// knowledge-base lines for the prompt). Claude Code moves hook context over
// 10,000 characters into a file and Codex does the same above roughly 2,500
// tokens; staying far below both keeps the text in the prompt itself.
const MAX_PROMPT_CONTEXT_CHARS = 2000;

module.exports = { SECURITY_CONSTRAINTS, MAX_PROMPT_CONTEXT_CHARS };
