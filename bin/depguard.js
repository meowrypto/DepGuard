#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs');
const { scanDirectory } = require('../lib/scanner');

const COLORS = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
  green: '\x1b[32m',
};

const SEVERITY_ORDER = { low: 0, medium: 1, high: 2 };

function parseArgs(argv) {
  const args = { target: 'node_modules', json: false, failOn: 'high' };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--json') {
      args.json = true;
    } else if (arg === '--fail-on') {
      args.failOn = argv[++i];
    } else if (arg === '--help' || arg === '-h') {
      args.help = true;
    } else if (!arg.startsWith('-')) {
      args.target = arg;
    }
  }
  return args;
}

function printHelp() {
  console.log(`
DepGuard - scan installed dependencies for crypto-stealer style behavior

Usage:
  npx depguard [target] [options]

Arguments:
  target            Directory to scan (default: node_modules)

Options:
  --json            Output findings as JSON instead of a formatted report
  --fail-on <level> Minimum severity that causes a non-zero exit code
                     (low | medium | high, default: high)
  -h, --help        Show this help

Examples:
  npx depguard
  npx depguard node_modules --fail-on medium
  npx depguard . --json > depguard-report.json
`);
}

function severityColor(sev) {
  if (sev === 'high') return COLORS.red;
  if (sev === 'medium') return COLORS.yellow;
  return COLORS.dim;
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    printHelp();
    process.exit(0);
  }

  const targetDir = path.resolve(process.cwd(), args.target);

  if (!fs.existsSync(targetDir)) {
    console.error(`DepGuard: target directory not found: ${targetDir}`);
    process.exit(2);
  }

  const { findings, filesScanned } = scanDirectory(targetDir);

  if (args.json) {
    console.log(JSON.stringify({ target: targetDir, filesScanned, findings }, null, 2));
  } else {
    console.log(`${COLORS.bold}DepGuard${COLORS.reset} scanned ${filesScanned} file(s) in ${targetDir}\n`);

    if (findings.length === 0) {
      console.log(`${COLORS.green}No suspicious patterns found.${COLORS.reset}`);
    } else {
      const sorted = [...findings].sort(
        (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]
      );
      for (const f of sorted) {
        const color = severityColor(f.severity);
        console.log(
          `${color}[${f.severity.toUpperCase()}]${COLORS.reset} ${f.label} ${COLORS.dim}(${f.id})${COLORS.reset}`
        );
        console.log(`  ${path.relative(process.cwd(), f.file)}:${f.line}`);
        console.log(`  ${COLORS.dim}${f.why}${COLORS.reset}`);
        console.log(`  ${COLORS.dim}match: ${f.snippet.replace(/\s+/g, ' ')}${COLORS.reset}\n`);
      }
      console.log(`${COLORS.bold}${findings.length} finding(s) total.${COLORS.reset}`);
      console.log(
        `${COLORS.dim}Note: these are heuristics, not proof of malice. Review each match before deleting anything.${COLORS.reset}`
      );
    }
  }

  const threshold = SEVERITY_ORDER[args.failOn] ?? SEVERITY_ORDER.high;
  const shouldFail = findings.some((f) => SEVERITY_ORDER[f.severity] >= threshold);
  process.exit(shouldFail ? 1 : 0);
}

main();
