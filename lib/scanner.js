'use strict';

const fs = require('fs');
const path = require('path');
const { PATTERNS } = require('./patterns');

const SCAN_EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.ts']);
const SKIP_DIR_NAMES = new Set(['.git', '.bin', 'test', 'tests', '__tests__', 'docs', 'examples']);
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024; // skip huge bundled/minified files

function shouldSkipDir(dirName) {
  return SKIP_DIR_NAMES.has(dirName);
}

function walk(dir, fileList) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    return fileList; // permission errors, broken symlinks, etc. — skip quietly
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (!shouldSkipDir(entry.name)) {
        walk(fullPath, fileList);
      }
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      if (SCAN_EXTENSIONS.has(ext)) {
        fileList.push(fullPath);
      }
    }
  }
  return fileList;
}

function scanFile(filePath) {
  const findings = [];
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch {
    return findings;
  }
  if (stat.size > MAX_FILE_SIZE_BYTES) return findings;

  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return findings;
  }

  for (const pattern of PATTERNS) {
    // reset lastIndex for global regexes reused across files
    pattern.regex.lastIndex = 0;
    const match = pattern.regex.exec(content);
    if (match) {
      const line = content.slice(0, match.index).split('\n').length;
      findings.push({
        file: filePath,
        line,
        id: pattern.id,
        label: pattern.label,
        severity: pattern.severity,
        why: pattern.why,
        snippet: match[0].slice(0, 80),
      });
    }
  }
  return findings;
}

/**
 * Scan a directory tree (e.g. node_modules) for suspicious patterns.
 * @param {string} targetDir
 * @returns {{findings: Array, filesScanned: number}}
 */
function scanDirectory(targetDir) {
  const files = walk(targetDir, []);
  let findings = [];
  for (const file of files) {
    findings = findings.concat(scanFile(file));
  }
  return { findings, filesScanned: files.length };
}

module.exports = { scanDirectory, scanFile, walk };
