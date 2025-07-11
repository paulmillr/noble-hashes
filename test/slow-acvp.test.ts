import { should } from 'micro-should';
import { avcpTests } from './acvp.test.ts';

// does big tests (LDT) (some like 17gb hash), takes ~14min with parallel execution
avcpTests(true);

should.runWhen(import.meta.url);
