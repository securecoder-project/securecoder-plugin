// Environment checks: which analyzer binaries resolve on this machine, with
// platform-appropriate install hints for the ones that do not.

'use strict';

const { run } = require('./proc');

function installHint(tool, platform = process.platform) {
  const mac = platform === 'darwin';
  const win = platform === 'win32';
  switch (tool) {
    case 'semgrep':
      return mac ? 'brew install semgrep' : win ? 'pipx install semgrep  (or use WSL)' : 'pipx install semgrep';
    case 'bandit':
      return mac ? 'brew install bandit' : 'pipx install bandit';
    case 'codeql':
      return mac ? 'brew install codeql' : 'download from https://github.com/github/codeql-action/releases (codeql-bundle) and add to PATH';
    case 'python':
      return mac ? 'brew install python' : win ? 'winget install Python.Python.3.12' : 'install python3 with your package manager';
    case 'node':
      return 'install Node.js 18+ from https://nodejs.org';
    case 'gofmt':
      return mac ? 'brew install go' : win ? 'winget install GoLang.Go' : 'install Go from https://go.dev/dl';
    case 'clang':
    case 'clang++':
      return mac ? 'xcode-select --install' : win ? 'winget install LLVM.LLVM' : 'install clang with your package manager';
    default:
      return null;
  }
}

// Binaries each analyzer needs. The syntax guardian degrades per language, so
// its binaries are reported individually rather than as one pass/fail.
function toolChecks(config) {
  return [
    { tool: 'semgrep', binary: config.bins.semgrep, probe: ['--version'], analyzer: 'semgrep' },
    { tool: 'bandit', binary: config.bins.bandit, probe: ['--version'], analyzer: 'bandit' },
    { tool: 'codeql', binary: config.codeql.binary, probe: ['version', '--format=terse'], analyzer: 'codeql' },
    { tool: 'python', binary: config.bins.python, probe: ['--version'], analyzer: 'syntax', languages: 'Python' },
    { tool: 'node', binary: config.bins.node, probe: ['--version'], analyzer: 'syntax', languages: 'JavaScript' },
    // gofmt has no version flag (-h exits 2); any successful spawn proves it is installed.
    { tool: 'gofmt', binary: config.bins.gofmt, probe: ['-h'], analyzer: 'syntax', languages: 'Go', noVersion: true },
    { tool: 'clang', binary: config.bins.clang, probe: ['--version'], analyzer: 'syntax', languages: 'C' },
    { tool: 'clang++', binary: config.bins.clangxx, probe: ['--version'], analyzer: 'syntax', languages: 'C++' },
  ];
}

// A binary counts as installed when it spawns at all (run() rejects only on
// ENOENT/EACCES); the version string is informational.
async function probeBinary(binary, probe, noVersion) {
  try {
    const { code, output, timedOut } = await run([binary, ...probe], { timeoutMs: 15000 });
    if (noVersion || code !== 0 || timedOut) return { found: true, version: null };
    // Prefer a line that looks like a version over update banners.
    const lines = output.split('\n').map((l) => l.trim()).filter(Boolean);
    const line = lines.find((l) => /\d+\.\d+/.test(l)) || lines[0];
    return { found: true, version: line ? line.slice(0, 80) : null };
  } catch {
    return { found: false, version: null };
  }
}

async function checkTools(config) {
  const checks = toolChecks(config);
  const results = await Promise.all(checks.map(async (check) => {
    const { found, version } = await probeBinary(check.binary, check.probe, check.noVersion);
    return {
      tool: check.tool,
      binary: check.binary,
      analyzer: check.analyzer,
      languages: check.languages || null,
      available: found,
      version,
      install: found ? null : installHint(check.tool),
    };
  }));
  return results;
}

function nodeVersionOk() {
  const major = Number(process.versions.node.split('.')[0]);
  return { version: process.versions.node, ok: major >= 18 };
}

module.exports = { checkTools, installHint, nodeVersionOk };
