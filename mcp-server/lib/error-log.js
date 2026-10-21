// Persistent error trail for the hooks. A hook fails open, so a fault leaves
// no trace the user will ever see; one JSON line per fault is appended to
// <project root>/.securecoder/errors.log and `doctor` reports what is there.
//
// The path is inside the workspace, so its contents are untrusted: nothing
// here follows a symlink, reads more than the size cap, or returns a field it
// has not bounded. Appending can never throw into the hook path.

'use strict';

const fs = require('fs');
const path = require('path');
const { VERSION } = require('./version');

const LOG_DIR = '.securecoder';
const LOG_FILE = 'errors.log';
// The file never grows past this. When an append would exceed it, the oldest
// entries are dropped until the rest fits in half, so trimming is infrequent.
const MAX_LOG_BYTES = 64 * 1024;
const KEEP_BYTES = MAX_LOG_BYTES / 2;
const MAX_ERROR_CHARS = 300;
const MAX_FIELD_CHARS = 40;

const NOFOLLOW = fs.constants.O_NOFOLLOW || 0; // not defined on Windows
const APPEND_FLAGS = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND | NOFOLLOW;
const REWRITE_FLAGS = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | NOFOLLOW;

function logPath(root) {
  return path.join(root, LOG_DIR, LOG_FILE);
}

// Whitespace, control characters (C0 and C1) and the invisible formatting
// characters that can reorder or hide text, since entries are shown to people
// and relayed to a model.
const UNPRINTABLE = /[\s\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]+/g;

function oneLine(value, max) {
  const text = (typeof value === 'string' ? value : JSON.stringify(value) || String(value)).replace(UNPRINTABLE, ' ').trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

// "TypeError: x is not a function" for errors, the text itself for strings,
// JSON for anything else. No stack trace: entries stay small.
function describeError(error) {
  try {
    if (typeof error === 'string') return oneLine(error, MAX_ERROR_CHARS);
    if (error && typeof error.message === 'string') {
      const name = typeof error.name === 'string' && error.name ? error.name : 'Error';
      return oneLine(error.message ? `${name}: ${error.message}` : name, MAX_ERROR_CHARS);
    }
    const json = JSON.stringify(error);
    return oneLine(json === undefined ? String(error) : json, MAX_ERROR_CHARS);
  } catch {
    return 'unknown error';
  }
}

// The last `maxBytes` of the file, cut forward to a line boundary. Bounded so
// that a planted or runaway file cannot stall the hook or doctor.
function readTail(file, size, maxBytes) {
  const length = Math.min(size, maxBytes);
  const buf = Buffer.alloc(length);
  const fd = fs.openSync(file, fs.constants.O_RDONLY | NOFOLLOW);
  let read;
  try {
    read = fs.readSync(fd, buf, 0, length, size - length);
  } finally {
    fs.closeSync(fd);
  }
  const tail = buf.subarray(0, read);
  if (length === size) return tail.toString('utf8');
  const cut = tail.indexOf(0x0a);
  return cut === -1 ? '' : tail.subarray(cut + 1).toString('utf8');
}

// Appends one entry. Returns whether it was written; never throws. A missing
// or read-only root, or a .securecoder that is not a real directory, is a
// silent no-op.
function appendError(root, details) {
  try {
    const { event, error, analyzer } = details || {};
    const entry = { ts: new Date().toISOString(), event: oneLine(event == null ? 'unknown' : event, MAX_FIELD_CHARS) };
    if (analyzer) entry.analyzer = oneLine(analyzer, MAX_FIELD_CHARS);
    entry.error = describeError(error);
    entry.version = VERSION;
    const line = `${JSON.stringify(entry)}\n`;

    const dir = path.join(root, LOG_DIR);
    try {
      fs.mkdirSync(dir);
    } catch (err) {
      if (err.code !== 'EEXIST') return false;
    }
    if (!fs.lstatSync(dir).isDirectory()) return false;

    const file = path.join(dir, LOG_FILE);
    const stat = fs.lstatSync(file, { throwIfNoEntry: false });
    if (stat && !stat.isFile()) return false;
    const size = stat ? stat.size : 0;
    if (size + Buffer.byteLength(line) > MAX_LOG_BYTES) {
      const kept = readTail(file, size, KEEP_BYTES);
      fs.writeFileSync(file, `${kept}${kept && !kept.endsWith('\n') ? '\n' : ''}${line}`, { flag: REWRITE_FLAGS });
    } else {
      fs.writeFileSync(file, line, { flag: APPEND_FLAGS });
    }
    return true;
  } catch {
    return false;
  }
}

function parseEntry(line) {
  let raw;
  try {
    raw = JSON.parse(line);
  } catch {
    return null;
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const field = (value, max) => (value == null ? 'unknown' : oneLine(value, max));
  // One odd line must not hide the rest of the trail.
  try {
    const entry = {
      ts: field(raw.ts, MAX_FIELD_CHARS),
      event: field(raw.event, MAX_FIELD_CHARS),
      error: field(raw.error, MAX_ERROR_CHARS),
      version: field(raw.version, MAX_FIELD_CHARS),
    };
    if (raw.analyzer != null) entry.analyzer = oneLine(raw.analyzer, MAX_FIELD_CHARS);
    return entry;
  } catch {
    return null;
  }
}

// { count, last, file } for a project's error trail, or null when the file is
// absent, empty, or holds no parseable entry. Garbage and partial lines are
// skipped. Never throws.
function readErrorLog(root) {
  try {
    const file = logPath(root);
    // O_NOFOLLOW covers only the last path component, so the directory is
    // checked as appendError checks it.
    if (!fs.lstatSync(path.dirname(file)).isDirectory()) return null;
    const stat = fs.lstatSync(file, { throwIfNoEntry: false });
    if (!stat || !stat.isFile() || stat.size === 0) return null;
    const entries = readTail(file, stat.size, MAX_LOG_BYTES).split('\n').map(parseEntry).filter(Boolean);
    if (entries.length === 0) return null;
    return { count: entries.length, last: entries[entries.length - 1], file };
  } catch {
    return null;
  }
}

module.exports = { MAX_LOG_BYTES, appendError, readErrorLog, logPath };
