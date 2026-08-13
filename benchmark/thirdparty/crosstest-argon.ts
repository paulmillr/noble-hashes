// Regenerate test/vectors/argon2.json with an independent native implementation.
import * as argon from '@node-rs/argon2';
import { writeFileSync } from 'node:fs';
import { ARGON2_CASES, argon2Inputs } from '../../test/argon2-cases.ts';

const algorithms = {
  argon2d: argon.Algorithm.Argon2d,
  argon2i: argon.Algorithm.Argon2i,
  argon2id: argon.Algorithm.Argon2id,
};
const versions = {
  '0x10': argon.Version.V0x10,
  '0x13': argon.Version.V0x13,
};

const results = [];
for (const algorithmName in algorithms) {
  for (const versionName in versions) {
    for (const c of ARGON2_CASES) {
      const { password, salt, secret } = argon2Inputs(c);
      const opts = {
        algorithm: algorithms[algorithmName],
        version: versions[versionName],
        parallelism: c.p,
        memoryCost: c.m,
        timeCost: c.t,
        outputLen: c.dkLen,
        secret,
        salt,
      };
      results.push(argon.hashRawSync(password, opts).toString('hex'));
    }
  }
}

const output = new URL('../../test/vectors/argon2.json', import.meta.url);
writeFileSync(output, JSON.stringify(results, null, 2) + '\n');
console.log(`Wrote ${results.length} Argon2 vectors to ${output.pathname}`);
