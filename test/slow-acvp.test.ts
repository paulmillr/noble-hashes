import { avcpTests } from './acvp.test.ts';

// does big tests (LDT) (some like 17gb hash), takes ~14min with parallel execution
avcpTests();
avcpTests(true);

it.runWhen(import.meta.url);
