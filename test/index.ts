import it from '@paulmillr/jsbt/test.js';
import { pathToFileURL } from 'node:url';
import { PLATFORMS } from './platform.ts';

const variant = 'noble';
const platform = PLATFORMS[variant] || Object.values(PLATFORMS)[0];

async function run() {
  const [
    { init },
    { acvpTests },
    { test: argon2 },
    { test: blake },
    { test: hmac },
    { test: keccak },
    { test: asyncKdf },
  ] = await Promise.all([
    import('./hashes.test.ts'),
    import('./acvp.test.ts'),
    import('./argon2.test.ts'),
    import('./blake.test.ts'),
    import('./hmac.test.ts'),
    import('./keccak.test.ts'),
    import('./async.test.ts'),
  ]);
  const [{ test: kdf }, { executeKDFTests }, { test: clone }, { test: info }] = await Promise.all([
    import('./kdf.test.ts'),
    import('./generator.ts'),
    import('./clone.test.ts'),
    import('./info.test.ts'),
  ]);
  // These modules register suites through top-level side effects. Their order must be stable when
  // jsbt replays this entrypoint in workers, so don't load them concurrently with Promise.all().
  await import('./eskdf.test.ts');
  await import('./noble-hashes-only.test.ts');
  await import('./u64.test.ts');
  await import('./utils.test.ts');
  init(variant, platform);
  acvpTests(false, variant, platform);
  argon2(variant, platform);
  blake(variant, platform);
  keccak(variant, platform);
  hmac(variant, platform);
  kdf(variant, platform);
  executeKDFTests(variant, platform, true);
  asyncKdf(variant, platform);
  clone(variant, platform);
  info(variant, platform);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  await run();
  it.run();
}
