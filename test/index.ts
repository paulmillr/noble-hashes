import it from '@paulmillr/jsbt/test.js';
import { pathToFileURL } from 'node:url';
import { PLATFORMS } from './platform.ts';

const variant = 'noble';
const platform = PLATFORMS[variant] || Object.values(PLATFORMS)[0];

async function run() {
  const [
    { init },
    { avcpTests },
    { test: blake },
    { test: hmac },
    { test: keccak },
    { test: asyncKdf },
  ] = await Promise.all([
    import('./hashes.test.ts'),
    import('./acvp.test.ts'),
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
    import('./eskdf.test.ts'),
    import('./noble-hashes-only.test.ts'),
    import('./u64.test.ts'),
    import('./utils.test.ts'),
  ]);
  init(variant, platform);
  avcpTests(false, variant, platform);
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
