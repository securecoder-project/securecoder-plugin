// Port of engine/guardian {Python,JavaScript,Go,C,Cpp}SyntaxGuardian.kt.
// Fast hard-reject checks: a candidate that does not even parse should never
// survive the loop. Each guardian silently no-ops when its binary is missing.

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { run } = require('./proc');

const C_STANDARD_HEADERS = new Set([
  'stdio.h', 'stdlib.h', 'string.h', 'unistd.h', 'stdbool.h', 'ctype.h',
  'errno.h', 'time.h', 'regex.h', 'sys/stat.h', 'sys/types.h', 'fcntl.h',
  'stdint.h', 'stddef.h', 'math.h', 'limits.h',
]);

const CPP_STANDARD_HEADERS = new Set([
  'iostream', 'string', 'cstring', 'cctype', 'fstream', 'sstream', 'cstdlib',
  'unistd.h', 'filesystem', 'memory', 'vector', 'map', 'algorithm', 'ctime',
  'iomanip', 'cstdio', 'tuple', 'stdexcept', 'utility', 'regex', 'array',
  'optional', 'set', 'unordered_map',
]);

function usesOnlyStandardHeaders(content, allowed) {
  const includes = [...content.matchAll(/^\s*#include\s*<([^>]+)>/gm)].map((m) => m[1]);
  return includes.length === 0 || includes.every((h) => allowed.has(h));
}

function violation(ruleId, ruleName, fileName, message, line) {
  return {
    rule: { id: ruleId, name: ruleName },
    message,
    location: { file: fileName, startLine: line },
    hardReject: true,
    confidence: 'HIGH',
    analyzer: 'syntax',
  };
}

function lastNonEmptyLine(output) {
  const lines = output.split('\n').map((l) => l.trim()).filter(Boolean);
  return lines.length ? lines[lines.length - 1] : null;
}

function firstNonEmptyLine(output) {
  return output.split('\n').map((l) => l.trim()).find(Boolean) || null;
}

function matchLine(output, regex, source = 'first') {
  const target = source === 'full' ? output : (output.split('\n')[0] || '');
  const m = target.match(regex);
  return m ? parseInt(m[1], 10) : null;
}

// Runs one check command against a file's content in a temp dir.
// Returns null on success, an output string on failure, or undefined if the
// binary is unavailable (guardian disables itself, matching the Kotlin port).
async function checkInTemp(prefix, fileBaseName, content, argsFor, timeoutMs) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  try {
    const tempFile = path.join(tempDir, fileBaseName);
    fs.writeFileSync(tempFile, content);
    let result;
    try {
      result = await run(argsFor(tempFile), { timeoutMs });
    } catch {
      return undefined;
    }
    return result.code === 0 ? null : result.output;
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

const GUARDIANS = [
  {
    name: 'PythonSyntaxGuardian',
    binKey: 'python',
    defaultBin: 'python3',
    matches: (f) => f.rel.endsWith('.py'),
    async check(file, bin, timeoutMs) {
      const output = await checkInTemp('python-guardian-', path.basename(file.rel) || 'snippet.py',
        file.content, (p) => [bin, '-m', 'py_compile', p], timeoutMs);
      if (output == null) return output;
      return violation('python-syntax', 'python_syntax_error', file.rel,
        lastNonEmptyLine(output) || 'Python syntax error',
        matchLine(output, /line (\d+)/, 'full'));
    },
  },
  {
    name: 'JavaScriptSyntaxGuardian',
    binKey: 'node',
    defaultBin: 'node',
    matches: (f) => /\.(js|mjs|cjs)$/.test(f.rel),
    async check(file, bin, timeoutMs) {
      const output = await checkInTemp('js-guardian-', path.basename(file.rel),
        file.content, (p) => [bin, '--check', p], timeoutMs);
      if (output == null) return output;
      // Prefer the actual error line; recent Node versions append a
      // "Node.js vX.Y.Z" banner as the last line of --check output.
      const errorLine = output.split('\n').map((l) => l.trim())
        .filter((l) => /^\w*(Syntax|Reference|Type)Error/.test(l)).pop();
      return violation('javascript-syntax', 'javascript_syntax_error', file.rel,
        errorLine || lastNonEmptyLine(output) || 'JavaScript syntax error',
        matchLine(output, /:(\d+)/));
    },
  },
  {
    name: 'GoSyntaxGuardian',
    binKey: 'gofmt',
    defaultBin: 'gofmt',
    matches: (f) => f.rel.endsWith('.go'),
    async check(file, bin, timeoutMs) {
      const output = await checkInTemp('go-guardian-', path.basename(file.rel),
        file.content, (p) => [bin, '-e', p], timeoutMs);
      if (output == null) return output;
      return violation('go-syntax', 'go_syntax_error', file.rel,
        firstNonEmptyLine(output) || 'Go syntax error',
        matchLine(output, /:(\d+):(\d+)/));
    },
  },
  {
    name: 'CSyntaxGuardian',
    binKey: 'clang',
    defaultBin: 'clang',
    matches: (f) => f.rel.endsWith('.c') && usesOnlyStandardHeaders(f.content, C_STANDARD_HEADERS),
    async check(file, bin, timeoutMs) {
      const output = await checkInTemp('c-guardian-', path.basename(file.rel),
        file.content, (p) => [bin, '-std=c11', '-fsyntax-only', p], timeoutMs);
      if (output == null) return output;
      return violation('c-syntax', 'c_syntax_error', file.rel,
        firstNonEmptyLine(output) || 'C syntax error',
        matchLine(output, /:(\d+):\d+:/));
    },
  },
  {
    name: 'CppSyntaxGuardian',
    binKey: 'clangxx',
    defaultBin: 'clang++',
    matches: (f) => /\.(cpp|cc|cxx)$/.test(f.rel) && usesOnlyStandardHeaders(f.content, CPP_STANDARD_HEADERS),
    async check(file, bin, timeoutMs) {
      const output = await checkInTemp('cpp-guardian-', path.basename(file.rel),
        file.content, (p) => [bin, '-std=c++17', '-fsyntax-only', p], timeoutMs);
      if (output == null) return output;
      return violation('cpp-syntax', 'cpp_syntax_error', file.rel,
        firstNonEmptyLine(output) || 'C++ syntax error',
        matchLine(output, /:(\d+):\d+:/));
    },
  },
];

// files: [{ rel, content }]. bins: optional { python, node, gofmt, clang, clangxx }.
async function runSyntaxGuardians(files, { bins = {}, timeoutMs = 20000 } = {}) {
  const violations = [];
  for (const guardian of GUARDIANS) {
    const bin = bins[guardian.binKey] || guardian.defaultBin;
    for (const file of files.filter(guardian.matches)) {
      const result = await guardian.check(file, bin, timeoutMs);
      if (result === undefined) break; // binary missing → skip this guardian entirely
      if (result) violations.push(result);
    }
  }
  return violations;
}

module.exports = { runSyntaxGuardians };
