// High-signal checks for shell commands an agent is about to run. Deliberately
// small: every rule here should almost never fire on routine development
// commands, because a noisy guard trains agents and users to ignore it.

'use strict';

const RULES = [
  {
    id: 'pipe-remote-to-shell',
    title: 'Remote script piped into a shell',
    advice: 'Download the script to a file, inspect or checksum it, then run it explicitly.',
    test: (cmd) => /\b(curl|wget|iwr|invoke-webrequest)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b/i.test(cmd)
      || /\b(ba|z)?sh\s+(-c\s+)?["']?\$\(\s*(curl|wget)\b/i.test(cmd)
      || /\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|;]*\|\s*iex\b/i.test(cmd),
  },
  {
    id: 'tls-verification-disabled',
    title: 'TLS certificate verification disabled',
    advice: 'Keep certificate verification on; fix the trust store or pin the expected certificate instead.',
    test: (cmd) => /\bcurl\b(?=[^|;&]*\s(-k|--insecure)\b)/.test(cmd)
      || /\bwget\b[^|;&]*--no-check-certificate\b/.test(cmd)
      || /\bGIT_SSL_NO_VERIFY=(1|true)\b/i.test(cmd)
      || /\bhttp\.sslVerify\s+false\b/i.test(cmd)
      || /\bNODE_TLS_REJECT_UNAUTHORIZED=0\b/.test(cmd)
      || /\b(pip|pip3)\b[^|;&]*--trusted-host\b/.test(cmd),
  },
  {
    id: 'world-writable-permissions',
    title: 'World-writable permissions',
    advice: 'Grant the minimum permissions needed (for example 755 for directories, 644 for files, 600 for secrets).',
    test: (cmd) => /\bchmod\s+(-[a-zA-Z]+\s+)*(0?777|a\+w|o\+w|ugo\+w)\b/.test(cmd),
  },
  {
    id: 'broad-recursive-delete',
    title: 'Recursive delete of a broad or unresolved target',
    advice: 'Delete a specific, validated path; guard variables with ${VAR:?} so an empty value cannot expand to /.',
    test: (cmd) => /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f?[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*|--recursive)\b[^;&|]*?\s(\/|~\/?|\$HOME\/?|\/\*|\.\/?\*?|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\/?)(\s|$|;|&|\|)/.test(cmd)
      && !/\$\{[A-Za-z_][A-Za-z0-9_]*:\?/.test(cmd),
  },
  {
    id: 'secret-in-command',
    title: 'Credential passed inline on the command line',
    advice: 'Read secrets from environment variables or a secret store; inline values leak into shell history, process lists, and logs.',
    test: (cmd) => /\b(AKIA|ASIA)[0-9A-Z]{16}\b/.test(cmd)
      || /\bgh[pousr]_[A-Za-z0-9]{36,}\b/.test(cmd)
      || /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/.test(cmd)
      || /\bsk-(ant-|proj-)?[A-Za-z0-9_-]{20,}\b/.test(cmd)
      || /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(cmd),
  },
];

function checkShellCommand(command) {
  if (typeof command !== 'string' || !command.trim()) return [];
  return RULES.filter((rule) => {
    try {
      return rule.test(command);
    } catch {
      return false;
    }
  }).map(({ id, title, advice }) => ({ id, title, advice }));
}

module.exports = { checkShellCommand, RULES };
