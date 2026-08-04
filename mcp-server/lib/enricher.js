// Port of openai-bridge HeuristicPromptEnricher.kt — contract-preserving
// constraint injection appended to a code-generation prompt.

'use strict';

const HASH_OR_BINARY_HINT_REGEX = /(hash|encrypt|cipher|key|salt)[\s\S]*(returns?|@returns?|return type)[\s\S]*string/i;

function enrichPrompt(prompt) {
  const hints = [];

  hints.push('Preserve the exact externally visible contract from the prompt. Do not change function names, parameter lists, synchronous behavior, return types, export shape, or container shape unless the prompt explicitly asks for it.');
  hints.push('If the prompt specifies an algorithm, mode, iteration count, key size, encoding, field names, or fallback behavior, keep those details exact and only change the unsafe part of the implementation.');
  hints.push("Stay within the requested language and runtime ecosystem. Do not switch languages, mix in another language's standard library or syntax, or introduce new third-party dependencies unless the prompt explicitly requires them.");
  hints.push('If the prompt gives examples or documents invalid-input behavior, make the implementation match those examples exactly. Do not invent stricter behavior that breaks the documented fallback, sentinel, or error-return contract.');

  const has = (s) => prompt.toLowerCase().includes(s.toLowerCase());
  if (has('pure C') || has('NOT C++')) {
    hints.push('For pure C tasks, keep the implementation valid ISO C and do not use C++ headers, std:: types, references, namespaces, classes, templates, or exceptions.');
  }
  if (has('Golang') || has('Go.') || prompt.includes('```go')) {
    hints.push('For Go tasks, prefer a self-contained standard-library implementation. Avoid introducing external modules unless the prompt explicitly names them.');
  }
  if (has('JavaScript') || has('Node.js') || prompt.includes('```js')) {
    hints.push('For JavaScript tasks, keep the function synchronous unless the prompt explicitly asks for async or Promise behavior.');
  }
  if (HASH_OR_BINARY_HINT_REGEX.test(prompt)) {
    hints.push('If the function returns hashes, salts, ciphertext, keys, or other binary values as strings, return a printable encoding such as hex instead of coercing raw bytes directly to string.');
  }
  if (has('temporary file') && has('file name')) {
    hints.push('If the function must return a temporary filename or path, create a named temporary file (for example mkstemp or NamedTemporaryFile) rather than an anonymous tmpfile, and return the path.');
  }
  if (has('archive') && (has('extract') || has('untar'))) {
    hints.push('For archive extraction tasks, validate extracted entry paths against the destination root and keep archive extraction behavior minimal. Avoid unnecessary ACL or metadata restoration if the prompt does not require it.');
  }

  const unique = [...new Set(hints)];
  const enriched = `${prompt.trimEnd()}\n\nAdditional constraints:\n${unique.map((h) => `- ${h}`).join('\n')}`;
  return { enriched, hints: unique };
}

module.exports = { enrichPrompt };
