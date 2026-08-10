import { describe, it } from '@paulmillr/jsbt/test.js';
import { ok } from 'node:assert';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
// Subpaths exposed on both npm (package.json) and JSR (jsr.json) exports maps.
// _md.js is already exported; _blake.js / _u64.js are the same class of internal
// helper module and are imported directly by downstream packages building BLAKE
// variants on top of noble primitives (see issue #136).
const INTERNALS = ['./_blake.js', './_u64.js'];

const pkgExports = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).exports;
const jsrExports = JSON.parse(readFileSync(join(ROOT, 'jsr.json'), 'utf8')).exports;

describe('exports', () => {
  it('package.json exposes _blake and _u64 internals', () => {
    for (const sub of INTERNALS) ok(sub in pkgExports, `package.json exports map is missing ${sub}`);
  });
  it('jsr.json exposes _blake and _u64 internals', () => {
    for (const sub of INTERNALS) ok(sub in jsrExports, `jsr.json exports map is missing ${sub}`);
  });
});

it.runWhen(import.meta.url);
