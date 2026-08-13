import { it } from '@paulmillr/jsbt/test.js';
import { pathToFileURL } from 'node:url';
import { testSlow as testSlowArgon } from './argon2.test.ts';
import { testUltra } from './slow-big.test.ts';

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  testUltra();
  testSlowArgon();
}

it.runWhen(import.meta.url);
