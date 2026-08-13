import { it } from '@paulmillr/jsbt/test.js';
import { acvpTests } from './acvp.test.ts';

// does big tests (LDT) (some like 17gb hash), takes ~14min with parallel execution
acvpTests(true);

it.runWhen(import.meta.url);
