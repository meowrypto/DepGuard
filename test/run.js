'use strict';

const assert = require('assert');
const path = require('path');
const { scanDirectory } = require('../lib/scanner');

function test(name, fn) {
  try {
    fn();
    console.log(`  ok - ${name}`);
  } catch (err) {
    console.error(`  FAIL - ${name}`);
    console.error(err);
    process.exitCode = 1;
  }
}

console.log('DepGuard tests\n');

test('clean package produces no findings', () => {
  const { findings } = scanDirectory(path.join(__dirname, 'fixtures', 'clean_pkg'));
  assert.strictEqual(findings.length, 0, `expected 0 findings, got ${findings.length}`);
});

test('malicious-style package is flagged', () => {
  const { findings } = scanDirectory(path.join(__dirname, 'fixtures', 'malicious_pkg'));
  const ids = findings.map((f) => f.id);
  assert.ok(ids.includes('clipboard-read'), 'should catch clipboard-read');
  assert.ok(ids.includes('clipboard-write'), 'should catch clipboard-write');
  assert.ok(ids.includes('discord-webhook'), 'should catch discord-webhook');
});

if (process.exitCode === 1) {
  console.log('\nSome tests failed.');
} else {
  console.log('\nAll tests passed.');
}
