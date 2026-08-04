// Port of guardian/codeql LanguageDetector.kt

'use strict';

function languageFromExtension(ext) {
  switch (ext.toLowerCase()) {
    case 'kt': case 'kts': case 'java':
      return 'java';
    case 'js': case 'jsx': case 'ts': case 'tsx':
      return 'javascript';
    case 'py':
      return 'python';
    case 'rb':
      return 'ruby';
    case 'go':
      return 'go';
    case 'swift':
      return 'swift';
    case 'c': case 'cc': case 'cpp': case 'cxx':
    case 'h': case 'hh': case 'hpp': case 'hxx':
      return 'cpp';
    case 'cs':
      return 'csharp';
    default:
      return null;
  }
}

function extensionOf(fileName) {
  const base = fileName.split('/').pop();
  const idx = base.lastIndexOf('.');
  return idx >= 0 ? base.slice(idx + 1) : '';
}

function detectLanguages(fileNames) {
  const langs = new Set();
  for (const name of fileNames) {
    const lang = languageFromExtension(extensionOf(name));
    if (lang) langs.add(lang);
  }
  return langs;
}

module.exports = { detectLanguages, languageFromExtension, extensionOf };
