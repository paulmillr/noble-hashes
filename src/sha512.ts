import { SHA2 } from './_sha2';
import * as u64 from './_u64';
import { _n, wrapConstructor } from './utils';

// Round contants (first 32 bits of the fractional parts of the cube roots of the first 80 primes 2..409):
// prettier-ignore
const [SHA512_Kh, SHA512_Kl] = u64.split([
  _n('0x428a2f98d728ae22'), _n('0x7137449123ef65cd'), _n('0xb5c0fbcfec4d3b2f'), _n('0xe9b5dba58189dbbc'),
  _n('0x3956c25bf348b538'), _n('0x59f111f1b605d019'), _n('0x923f82a4af194f9b'), _n('0xab1c5ed5da6d8118'),
  _n('0xd807aa98a3030242'), _n('0x12835b0145706fbe'), _n('0x243185be4ee4b28c'), _n('0x550c7dc3d5ffb4e2'),
  _n('0x72be5d74f27b896f'), _n('0x80deb1fe3b1696b1'), _n('0x9bdc06a725c71235'), _n('0xc19bf174cf692694'),
  _n('0xe49b69c19ef14ad2'), _n('0xefbe4786384f25e3'), _n('0x0fc19dc68b8cd5b5'), _n('0x240ca1cc77ac9c65'),
  _n('0x2de92c6f592b0275'), _n('0x4a7484aa6ea6e483'), _n('0x5cb0a9dcbd41fbd4'), _n('0x76f988da831153b5'),
  _n('0x983e5152ee66dfab'), _n('0xa831c66d2db43210'), _n('0xb00327c898fb213f'), _n('0xbf597fc7beef0ee4'),
  _n('0xc6e00bf33da88fc2'), _n('0xd5a79147930aa725'), _n('0x06ca6351e003826f'), _n('0x142929670a0e6e70'),
  _n('0x27b70a8546d22ffc'), _n('0x2e1b21385c26c926'), _n('0x4d2c6dfc5ac42aed'), _n('0x53380d139d95b3df'),
  _n('0x650a73548baf63de'), _n('0x766a0abb3c77b2a8'), _n('0x81c2c92e47edaee6'), _n('0x92722c851482353b'),
  _n('0xa2bfe8a14cf10364'), _n('0xa81a664bbc423001'), _n('0xc24b8b70d0f89791'), _n('0xc76c51a30654be30'),
  _n('0xd192e819d6ef5218'), _n('0xd69906245565a910'), _n('0xf40e35855771202a'), _n('0x106aa07032bbd1b8'),
  _n('0x19a4c116b8d2d0c8'), _n('0x1e376c085141ab53'), _n('0x2748774cdf8eeb99'), _n('0x34b0bcb5e19b48a8'),
  _n('0x391c0cb3c5c95a63'), _n('0x4ed8aa4ae3418acb'), _n('0x5b9cca4f7763e373'), _n('0x682e6ff3d6b2b8a3'),
  _n('0x748f82ee5defb2fc'), _n('0x78a5636f43172f60'), _n('0x84c87814a1f0ab72'), _n('0x8cc702081a6439ec'),
  _n('0x90befffa23631e28'), _n('0xa4506cebde82bde9'), _n('0xbef9a3f7b2c67915'), _n('0xc67178f2e372532b'),
  _n('0xca273eceea26619c'), _n('0xd186b8c721c0c207'), _n('0xeada7dd6cde0eb1e'), _n('0xf57d4f7fee6ed178'),
  _n('0x06f067aa72176fba'), _n('0x0a637dc5a2c898a6'), _n('0x113f9804bef90dae'), _n('0x1b710b35131c471b'),
  _n('0x28db77f523047d84'), _n('0x32caab7b40c72493'), _n('0x3c9ebe0a15c9bebc'), _n('0x431d67c49c100d4c'),
  _n('0x4cc5d4becb3e42b6'), _n('0x597f299cfc657e2a'), _n('0x5fcb6fab3ad6faec'), _n('0x6c44198c4a475817')
]);

// Temporary buffer, not used to store anything between runs
const SHA512_W_H = new Uint32Array(80);
const SHA512_W_L = new Uint32Array(80);

export class SHA512 extends SHA2<SHA512> {
  // We cannot use array here since array allows indexing by variable which means optimizer/compiler cannot use registers.
  // Also looks cleaner and easier to verify with spec.
  // Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
  // h -- high 32 bits, l -- low 32 bits
  Ah = 0x6a09e667 | 0;
  Al = 0xf3bcc908 | 0;
  Bh = 0xbb67ae85 | 0;
  Bl = 0x84caa73b | 0;
  Ch = 0x3c6ef372 | 0;
  Cl = 0xfe94f82b | 0;
  Dh = 0xa54ff53a | 0;
  Dl = 0x5f1d36f1 | 0;
  Eh = 0x510e527f | 0;
  El = 0xade682d1 | 0;
  Fh = 0x9b05688c | 0;
  Fl = 0x2b3e6c1f | 0;
  Gh = 0x1f83d9ab | 0;
  Gl = 0xfb41bd6b | 0;
  Hh = 0x5be0cd19 | 0;
  Hl = 0x137e2179 | 0;

  constructor() {
    super(128, 64, 16, false);
  }
  // prettier-ignore
  protected get(): [
    number, number, number, number, number, number, number, number,
    number, number, number, number, number, number, number, number
  ] {
    const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
  }
  // prettier-ignore
  protected set(
    Ah: number, Al: number, Bh: number, Bl: number, Ch: number, Cl: number, Dh: number, Dl: number,
    Eh: number, El: number, Fh: number, Fl: number, Gh: number, Gl: number, Hh: number, Hl: number
  ) {
    this.Ah = Ah | 0;
    this.Al = Al | 0;
    this.Bh = Bh | 0;
    this.Bl = Bl | 0;
    this.Ch = Ch | 0;
    this.Cl = Cl | 0;
    this.Dh = Dh | 0;
    this.Dl = Dl | 0;
    this.Eh = Eh | 0;
    this.El = El | 0;
    this.Fh = Fh | 0;
    this.Fl = Fl | 0;
    this.Gh = Gh | 0;
    this.Gl = Gl | 0;
    this.Hh = Hh | 0;
    this.Hl = Hl | 0;
  }
  protected process(view: DataView, offset: number) {
    // Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array
    for (let i = 0; i < 16; i++, offset += 4) {
      SHA512_W_H[i] = view.getUint32(offset);
      SHA512_W_L[i] = view.getUint32((offset += 4));
    }
    for (let i = 16; i < 80; i++) {
      // s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
      const W15h = SHA512_W_H[i - 15] | 0;
      const W15l = SHA512_W_L[i - 15] | 0;
      const s0h = u64.rotrSH(W15h, W15l, 1) ^ u64.rotrSH(W15h, W15l, 8) ^ u64.shrSH(W15h, W15l, 7);
      const s0l = u64.rotrSL(W15h, W15l, 1) ^ u64.rotrSL(W15h, W15l, 8) ^ u64.shrSL(W15h, W15l, 7);
      // s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
      const W2h = SHA512_W_H[i - 2] | 0;
      const W2l = SHA512_W_L[i - 2] | 0;
      const s1h = u64.rotrSH(W2h, W2l, 19) ^ u64.rotrBH(W2h, W2l, 61) ^ u64.shrSH(W2h, W2l, 6);
      const s1l = u64.rotrSL(W2h, W2l, 19) ^ u64.rotrBL(W2h, W2l, 61) ^ u64.shrSL(W2h, W2l, 6);
      // SHA256_W[i] = s0 + s1 + SHA256_W[i - 7] + SHA256_W[i - 16];
      const SUMl = u64.add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
      const SUMh = u64.add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
      SHA512_W_H[i] = SUMh | 0;
      SHA512_W_L[i] = SUMl | 0;
    }
    let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    // Compression function main loop, 80 rounds
    for (let i = 0; i < 80; i++) {
      // S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
      const sigma1h = u64.rotrSH(Eh, El, 14) ^ u64.rotrSH(Eh, El, 18) ^ u64.rotrBH(Eh, El, 41);
      const sigma1l = u64.rotrSL(Eh, El, 14) ^ u64.rotrSL(Eh, El, 18) ^ u64.rotrBL(Eh, El, 41);
      //const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
      const CHIh = (Eh & Fh) ^ (~Eh & Gh);
      const CHIl = (El & Fl) ^ (~El & Gl);
      // T1 = H + sigma1 + Chi(E, F, G) + SHA512_K[i] + SHA512_W[i]
      // prettier-ignore
      const T1ll = u64.add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
      const T1h = u64.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
      const T1l = T1ll | 0;
      // S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
      const sigma0h = u64.rotrSH(Ah, Al, 28) ^ u64.rotrBH(Ah, Al, 34) ^ u64.rotrBH(Ah, Al, 39);
      const sigma0l = u64.rotrSL(Ah, Al, 28) ^ u64.rotrBL(Ah, Al, 34) ^ u64.rotrBL(Ah, Al, 39);
      const MAJh = (Ah & Bh) ^ (Ah & Ch) ^ (Bh & Ch);
      const MAJl = (Al & Bl) ^ (Al & Cl) ^ (Bl & Cl);
      Hh = Gh | 0;
      Hl = Gl | 0;
      Gh = Fh | 0;
      Gl = Fl | 0;
      Fh = Eh | 0;
      Fl = El | 0;
      ({ h: Eh, l: El } = u64.add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
      Dh = Ch | 0;
      Dl = Cl | 0;
      Ch = Bh | 0;
      Cl = Bl | 0;
      Bh = Ah | 0;
      Bl = Al | 0;
      const All = u64.add3L(T1l, sigma0l, MAJl);
      Ah = u64.add3H(All, T1h, sigma0h, MAJh);
      Al = All | 0;
    }
    // Add the compressed chunk to the current hash value
    ({ h: Ah, l: Al } = u64.add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
    ({ h: Bh, l: Bl } = u64.add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
    ({ h: Ch, l: Cl } = u64.add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
    ({ h: Dh, l: Dl } = u64.add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
    ({ h: Eh, l: El } = u64.add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
    ({ h: Fh, l: Fl } = u64.add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
    ({ h: Gh, l: Gl } = u64.add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
    ({ h: Hh, l: Hl } = u64.add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
    this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
  }
  protected roundClean() {
    SHA512_W_H.fill(0);
    SHA512_W_L.fill(0);
  }
  destroy() {
    this.buffer.fill(0);
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
}

class SHA512_256 extends SHA512 {
  // h -- high 32 bits, l -- low 32 bits
  Ah = 0x22312194 | 0;
  Al = 0xfc2bf72c | 0;
  Bh = 0x9f555fa3 | 0;
  Bl = 0xc84c64c2 | 0;
  Ch = 0x2393b86b | 0;
  Cl = 0x6f53b151 | 0;
  Dh = 0x96387719 | 0;
  Dl = 0x5940eabd | 0;
  Eh = 0x96283ee2 | 0;
  El = 0xa88effe3 | 0;
  Fh = 0xbe5e1e25 | 0;
  Fl = 0x53863992 | 0;
  Gh = 0x2b0199fc | 0;
  Gl = 0x2c85b8aa | 0;
  Hh = 0x0eb72ddc | 0;
  Hl = 0x81c52ca2 | 0;

  constructor() {
    super();
    this.outputLen = 32;
  }
}

class SHA384 extends SHA512 {
  // h -- high 32 bits, l -- low 32 bits
  Ah = 0xcbbb9d5d | 0;
  Al = 0xc1059ed8 | 0;
  Bh = 0x629a292a | 0;
  Bl = 0x367cd507 | 0;
  Ch = 0x9159015a | 0;
  Cl = 0x3070dd17 | 0;
  Dh = 0x152fecd8 | 0;
  Dl = 0xf70e5939 | 0;
  Eh = 0x67332667 | 0;
  El = 0xffc00b31 | 0;
  Fh = 0x8eb44a87 | 0;
  Fl = 0x68581511 | 0;
  Gh = 0xdb0c2e0d | 0;
  Gl = 0x64f98fa7 | 0;
  Hh = 0x47b5481d | 0;
  Hl = 0xbefa4fa4 | 0;

  constructor() {
    super();
    this.outputLen = 48;
  }
}

export const sha512 = wrapConstructor(() => new SHA512());
export const sha512_256 = wrapConstructor(() => new SHA512_256());
export const sha384 = wrapConstructor(() => new SHA384());
