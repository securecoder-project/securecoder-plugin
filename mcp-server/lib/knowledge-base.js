// CWE knowledge base: picks the catalog entries (security-knowledge-base.json)
// a task is likely to touch and renders them as guidance.
//
// There is no classifier here on purpose. The host agent is the model; this
// module only narrows the catalog with keywords so that the few relevant
// entries, not all of them, are put in front of it.
//
// Selection, for a task text and optional file paths:
//   - Keywords are matched case-insensitively on word boundaries. The words of
//     a phrase must be adjacent, with at most an article (a, an, the) between
//     them, so "fetch url" matches "fetch the URL" and nothing looser.
//   - An entry's score is the number of its keywords that match. Entries are
//     returned best score first, catalog order breaking ties, at most
//     MAX_SELECTED of them. No match is an empty selection, never an error.
//   - Languages are detected from the given file paths, from file names in the
//     text ("src/app.py") and from unambiguous language names ("TypeScript",
//     "C++"; not "Go" or "C", which are ordinary words too).
//   - An entry with an empty `languages` list is language-neutral: detected
//     languages never add or remove it. An entry that lists languages is
//     limited to them: when the task is clearly in other languages it is not
//     selected whatever its keywords say; when one of its languages is
//     detected, that alone selects it (and counts one point); when no
//     language is detected at all, its keywords decide as for any entry.

'use strict';

const { detectLanguages } = require('./languages');

const MAX_SELECTED = 6;
// A prompt can be megabytes of pasted text. What a task is about is settled
// in its first few thousand characters, and a bound keeps the hook fast.
const MAX_TEXT_CHARS = 20000;

const BOUNDARY_BEFORE = '(?<![a-z0-9])';
const BOUNDARY_AFTER = '(?![a-z0-9])';
const BETWEEN_WORDS = '[^a-z0-9]+(?:(?:a|an|the)[^a-z0-9]+)?';

const LANGUAGE_NAMES = [
  ['python', 'python[23]?'],
  ['javascript', 'javascript|typescript|node\\.?js'],
  ['go', 'golang'],
  ['java', 'java|kotlin'],
  ['ruby', 'ruby'],
  ['cpp', 'c\\+\\+|cpp'],
  ['csharp', 'c#|csharp'],
].map(([language, names]) => [language, new RegExp(`${BOUNDARY_BEFORE}(?:${names})(?![a-z0-9+#])`)]);

function keywordPattern(keyword) {
  const words = keyword.split(' ').filter(Boolean).map((word) => word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  // A boundary is only meaningful next to a letter or digit: "eval(" has to
  // match in "eval(x)".
  const before = /^[a-z0-9]/.test(keyword) ? BOUNDARY_BEFORE : '';
  const after = /[a-z0-9]$/.test(keyword) ? BOUNDARY_AFTER : '';
  return new RegExp(`${before}${words.join(BETWEEN_WORDS)}${after}`);
}

let compiled = null;

// The catalog with its keyword patterns, built on first use. Entries are
// frozen because selections hand out the catalog's own objects.
function catalog() {
  if (!compiled) {
    compiled = require('./security-knowledge-base.json').entries.map((entry) => ({
      entry: Object.freeze(entry),
      patterns: entry.keywords.map(keywordPattern),
    }));
  }
  return compiled;
}

function entries() {
  return catalog().map((item) => item.entry);
}

// Tokens of the text that could be file names. URLs and e-mail addresses are
// left out: "example.cc" is a host, not a C++ source file.
// Abbreviations are left out too: every part of "D.C." or "U.S.C." is a
// single letter, which no source file name is.
function mentionedFiles(text) {
  return text.split(/[\s"'`()<>[\]{},;]+/)
    .filter((token) => token.includes('.') && !token.includes('://') && !token.includes('@') && !token.startsWith('www.'))
    // The lookbehind anchors the run of trailing punctuation at its start, so
    // a long run is scanned once, not once per position.
    .map((token) => token.replace(/(?<![.:!?])[.:!?]+$/, '').replace(/:\d+(?::\d+)?$/, ''))
    .filter((token) => token.split('.').some((part) => part.length > 1));
}

function taskLanguages(text, lowered, files) {
  const named = (Array.isArray(files) ? files : []).filter((file) => typeof file === 'string');
  const languages = detectLanguages([...named, ...mentionedFiles(text)].map((file) => file.replace(/\\/g, '/')));
  for (const [language, pattern] of LANGUAGE_NAMES) {
    if (pattern.test(lowered)) languages.add(language);
  }
  return languages;
}

// Returns catalog entries, best match first. Total: any input (a non-string,
// an empty or enormous text, a damaged catalog) gives a selection, possibly
// empty, because the callers are a hook that must fail open and a prompt
// enricher that must still return its other constraints.
function selectEntries(text, { files = [] } = {}) {
  try {
    const source = (typeof text === 'string' ? text : '').slice(0, MAX_TEXT_CHARS);
    const lowered = source.toLowerCase();
    const languages = taskLanguages(source, lowered, files);
    const scored = [];
    catalog().forEach(({ entry, patterns }, index) => {
      const inLanguage = entry.languages.some((language) => languages.has(language));
      if (entry.languages.length > 0 && languages.size > 0 && !inLanguage) return;
      const score = patterns.filter((pattern) => pattern.test(lowered)).length + (inLanguage ? 1 : 0);
      if (score > 0) scored.push({ entry, score, index });
    });
    return scored
      .sort((a, b) => b.score - a.score || a.index - b.index)
      .slice(0, MAX_SELECTED)
      .map((item) => item.entry);
  } catch {
    return [];
  }
}

const COMPACT_LEAD = 'Weakness classes likely relevant here (guidance, not findings):';

// One line per entry, for the per-prompt hook: short enough to be paid for on
// every matching prompt.
function renderCompact(selection) {
  if (!Array.isArray(selection) || selection.length === 0) return '';
  return [COMPACT_LEAD, ...selection.map((entry) => `- ${entry.id} ${entry.name}: ${entry.summary}`)].join('\n');
}

const CHECKLIST_PREAMBLE = 'Secure-coding checklist for the weakness classes likely relevant to this task. For each item, check whether the code you write or review actually contains the described sink. Treat an item as a finding only if it does and the issue can be fixed without changing behavior for valid input. Respect every "Do not flag if" note: those are the common false positives and must not be reported. The checklist is guidance, not a list of findings.';

// All four fields per entry, for securecoder_enrich_prompt.
function renderChecklist(selection) {
  if (!Array.isArray(selection) || selection.length === 0) return '';
  const items = selection.map((entry, index) => [
    `${index + 1}. ${entry.id} ${entry.name}`,
    `   Detect: ${entry.detect}`,
    `   Repair: ${entry.repair}`,
    `   ${entry.false_positives}`,
    `   Preserve: ${entry.preserve}`,
  ].join('\n'));
  return [CHECKLIST_PREAMBLE, ...items].join('\n');
}

module.exports = { MAX_SELECTED, entries, selectEntries, renderCompact, renderChecklist };
