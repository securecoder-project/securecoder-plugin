// Contract-preserving constraints appended to a code-generation prompt, plus a
// CWE checklist from the knowledge base when the task touches known weakness
// classes.
//
// The constraints are the same four for every task. The original engine's
// enricher also added hints keyed on phrases in the task text; those were
// removed there because they tracked specific benchmark task families too
// closely, and they are not carried here either. Anything task-specific comes
// from the knowledge base, selected by the keyword rules the user-prompt hook
// uses.

'use strict';

const { selectEntries, renderChecklist } = require('./knowledge-base');

const CONTRACT_HINTS = [
  'Preserve the exact externally visible contract from the prompt. Do not change function names, parameter lists, synchronous behavior, return types, export shape, or container shape unless the prompt explicitly asks for it.',
  'If the prompt specifies an algorithm, mode, iteration count, key size, encoding, field names, or fallback behavior, keep those details exact and only change the unsafe part of the implementation.',
  "Stay within the requested language and runtime ecosystem. Do not switch languages, mix in another language's standard library or syntax, or introduce new third-party dependencies unless the prompt explicitly requires them.",
  'If the prompt gives examples or documents invalid-input behavior, make the implementation match those examples exactly. Do not invent stricter behavior that breaks the documented fallback, sentinel, or error-return contract.',
];

function enrichPrompt(prompt) {
  const hints = [...CONTRACT_HINTS];
  const constrained = `${prompt.trimEnd()}\n\nAdditional constraints:\n${hints.map((h) => `- ${h}`).join('\n')}`;

  // Empty for a task that matches no weakness class: no checklist is better
  // than a generic one.
  const selected = selectEntries(prompt);
  const checklist = renderChecklist(selected);
  const enriched = checklist ? `${constrained}\n\n${checklist}` : constrained;
  return { enriched, hints, checklist, cwes: selected.map((entry) => ({ id: entry.id, name: entry.name })) };
}

module.exports = { enrichPrompt };
