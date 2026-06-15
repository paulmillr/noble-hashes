import { should } from '@paulmillr/jsbt/test.js';
import { pathToFileURL } from 'node:url';
import { PLATFORMS } from './platform.ts';

const variant = 'noble';
const platform = PLATFORMS[variant] || Object.values(PLATFORMS)[0];
const PHASE_ENV = 'NOBLE_HASHES_TEST_PHASE';

async function registerFastTests() {
  const [{ init }, { avcpTests }, { test: blake }, { test: hmac }] =
    await Promise.all([
      import('./hashes.test.ts'),
      import('./acvp.test.ts'),
      import('./blake.test.ts'),
      import('./hmac.test.ts'),
    ]);
  const [{ test: kdf }, { executeKDFTests }, { test: clone }, { test: info }] = await Promise.all([
    import('./kdf.test.ts'),
    import('./generator.ts'),
    import('./clone.test.ts'),
    import('./info.test.ts'),
    import('./eskdf.test.ts'),
    import('./noble-hashes-only.test.ts'),
    import('./u64.test.ts'),
    import('./utils.test.ts'),
  ]);
  init(variant, platform);
  avcpTests(false, variant, platform);
  blake(variant, platform);
  hmac(variant, platform);
  kdf(variant, platform);
  executeKDFTests(variant, platform, true);
  clone(variant, platform);
  info(variant, platform);
}

async function registerAsyncTests() {
  const { test: asyncKdf } = await import('./async.test.ts');
  asyncKdf(variant, platform);
}

async function registerKeccakTests() {
  const { test: keccak } = await import('./keccak.test.ts');
  keccak(variant, platform);
}

const PHASES = {
  fast: { register: registerFastTests, forceSequential: false },
  async: { register: registerAsyncTests, forceSequential: true },
  keccak: { register: registerKeccakTests, forceSequential: true },
};

async function runPhase(name) {
  const phase = PHASES[name];
  if (!phase) throw new Error(`unknown test phase: ${name}`);
  process.env[PHASE_ENV] = name;
  try {
    await phase.register();
    await should.run(phase.forceSequential);
  } finally {
    delete process.env[PHASE_ENV];
  }
}

async function run() {
  const phaseName = process.env[PHASE_ENV];
  if (phaseName) {
    const phase = PHASES[phaseName];
    if (!phase) throw new Error(`unknown test phase: ${phaseName}`);
    await phase.register();
    await should.run(phase.forceSequential);
    return;
  }
  for (const phase of ['fast', 'async', 'keccak']) await runPhase(phase);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) await run();
