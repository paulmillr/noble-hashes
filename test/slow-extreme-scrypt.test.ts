import { it } from '@paulmillr/jsbt/test.js';
import { pathToFileURL } from 'node:url';
import { testExtremeScrypt } from './slow-big.test.ts';

// These tests really allocate and touch 9-17GiB. Run only on explicitly provisioned machines.
if (import.meta.url === pathToFileURL(process.argv[1]).href) testExtremeScrypt();
it.runWhen(import.meta.url);
