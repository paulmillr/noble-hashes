import { describe, should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';
import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from '../src/sha2.ts';
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128_32, shake256_64 } from '../src/sha3.ts';
import { sha1, md5 } from '../src/legacy.ts';

const hashAlgs = '2.16.840.1.101.3.4.2.'; // hashAlgs OBJECT IDENTIFIER ::= { nistAlgorithms 2 }
const OIDS = [
  // hashAlg: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
  { hash: sha256, oid: hashAlgs + '1', collision: 128, preimage: 256 },
  { hash: sha384, oid: hashAlgs + '2', collision: 192, preimage: 384 },
  { hash: sha512, oid: hashAlgs + '3', collision: 256, preimage: 512 },
  { hash: sha224, oid: hashAlgs + '4', collision: 112, preimage: 224 },
  { hash: sha512_224, oid: hashAlgs + '5', collision: 112, preimage: 224 },
  { hash: sha512_256, oid: hashAlgs + '6', collision: 128, preimage: 256 },
  { hash: sha3_224, oid: hashAlgs + '7', collision: 112, preimage: 224 },
  { hash: sha3_256, oid: hashAlgs + '8', collision: 128, preimage: 256 },
  { hash: sha3_384, oid: hashAlgs + '9', collision: 192, preimage: 384 },
  { hash: sha3_512, oid: hashAlgs + '10', collision: 256, preimage: 512 },

  { hash: shake128_32, oid: hashAlgs + '11', collision: 128, preimage: 256 },
  { hash: shake256_64, oid: hashAlgs + '12', collision: 256, preimage: 512 },
  // https://www.rfc-editor.org/rfc/rfc3370.txt
  // md5 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 5 }
  { hash: md5, oid: '1.2.840.113549.2.5' },
  //   sha-1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) oiw(14) secsig(3) algorithm(2) 26 }
  { hash: sha1, oid: '1.3.14.3.2.26' },
];
// verify: https://stackoverflow.com/questions/3713774/c-sharp-how-to-calculate-asn-1-der-encoding-of-a-particular-hash-algorithm

// First two elements: [i0 * 40 + i1].
// Others: split in groups of 7 bit chunks, add 0x80 every byte except last(stop flag), like utf8.
const OID_MSB = 2 ** 7; // mask for 8 bit
const OID_NO_MSB = 2 ** 7 - 1; // mask for all bits except 8

function encodeOid(value: string) {
  const items = value.split('.').map((i) => +i);
  let oid = [items[0] * 40];
  if (items.length >= 2) oid[0] += items[1];
  for (let i = 2; i < items.length; i++) {
    const item = [];
    for (let n = items[i], mask = 0x00; n; n >>= 7, mask = OID_MSB)
      item.unshift((n & OID_NO_MSB) | mask);
    oid = oid.concat(item);
  }
  return new Uint8Array(oid);
}

function encodeOidDER(oidStr: string): Uint8Array {
  const body = encodeOid(oidStr);
  const length = body.length;
  const header = [0x06];
  if (length < 0x80) {
    header.push(length);
  } else {
    // Support long-form length if necessary
    const lenBytes = [];
    let len = length;
    while (len > 0) {
      lenBytes.unshift(len & 0xff);
      len >>= 8;
    }
    header.push(0x80 | lenBytes.length, ...lenBytes);
  }

  return new Uint8Array([...header, ...body]);
}

should('info', () => {
  for (const { hash, oid: hashOid, collision, preimage } of OIDS) {
    if (hash.oid) eql(hash.oid, encodeOidDER(hashOid));
    // Verify that our calculations are same as NIST ones
    const preimageResistence = hash.outputLen * 8;
    const collisionResistance = (hash.outputLen * 8) / 2;
    if (collision) eql(collisionResistance, collision);
    if (preimage) eql(preimageResistence, preimage);
  }
});

should.runWhen(import.meta.url);
