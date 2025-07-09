import { should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';

import { oid } from 'micro-key-producer/pgp.js';
import { md5, sha1 } from '../src/legacy.ts';
import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from '../src/sha2.ts';
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } from '../src/sha3.ts';

const hashAlgs = '2.16.840.1.101.3.4.2.'; // hashAlgs OBJECT IDENTIFIER ::= { nistAlgorithms 2 }
const OIDS = [
  // hashAlg: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
  { hash: sha256, oid: hashAlgs + '1' },
  { hash: sha384, oid: hashAlgs + '2' },
  { hash: sha512, oid: hashAlgs + '3' },
  { hash: sha224, oid: hashAlgs + '4' },
  { hash: sha512_224, oid: hashAlgs + '5' },
  { hash: sha512_256, oid: hashAlgs + '6' },
  { hash: sha3_224, oid: hashAlgs + '7' },
  { hash: sha3_256, oid: hashAlgs + '8' },
  { hash: sha3_384, oid: hashAlgs + '9' },
  { hash: sha3_512, oid: hashAlgs + '10' },
  { hash: shake128, oid: hashAlgs + '11' },
  { hash: shake256, oid: hashAlgs + '12' },
  // https://www.rfc-editor.org/rfc/rfc3370.txt
  // md5 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 5 }
  { hash: md5, oid: '1.2.840.113549.2.5' },
  //   sha-1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) oiw(14) secsig(3) algorithm(2) 26 }
  { hash: sha1, oid: '1.3.14.3.2.26' },
];
// verify: https://stackoverflow.com/questions/3713774/c-sharp-how-to-calculate-asn-1-der-encoding-of-a-particular-hash-algorithm

should('info', () => {
  for (const { hash, oid: hashOid } of OIDS) {
    eql(hash.oid.subarray(2), oid.encode(hashOid)); // full DER encoding vs just oid
  }
});

should.runWhen(import.meta.url);
