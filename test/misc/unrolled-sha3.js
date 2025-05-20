// u64.ts
const U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
const _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le) return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
  return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}

// sha3.ts
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _7n = BigInt(7);
const _256n = BigInt(256);
const _0x71n = BigInt(0x71);
const SHA3_PI = [];
const SHA3_ROTL = [];
const _SHA3_IOTA = [];
for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
  // Pi
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  // Rotational
  SHA3_ROTL.push((((round + 1) * (round + 2)) / 2) % 64);
  // Iota
  let t = _0n;
  for (let j = 0; j < 7; j++) {
    R = ((R << _1n) ^ ((R >> _7n) * _0x71n)) % _256n;
    if (R & _2n) t ^= _1n << ((_1n << /* @__PURE__ */ BigInt(j)) - _1n);
  }
  _SHA3_IOTA.push(t);
}
// const IOTAS = split(_SHA3_IOTA, true);
// const SHA3_IOTA_H = IOTAS[0];
// const SHA3_IOTA_L = IOTAS[1];

export const keccakP = (() => {
  const rotlHs = (h, l, s) =>
    s > 32 ? `(${l} << ${s - 32}) | (${h} >>> ${64 - s})` : `(${h} << ${s}) | (${l} >>> ${32 - s})`;
  const rotlLs = (h, l, s) =>
    s > 32 ? `(${h} << ${s - 32}) | (${l} >>> ${64 - s})` : `(${l} << ${s}) | (${h} >>> ${32 - s})`;
  let out = 'let h, l, s = state;\n';
  const vars = [];
  for (let i = 0; i < 200 / 4; i++) vars.push(`s${i} = s[${i}]`);
  out += `let ${vars.join(', ')};\n`;
  out += `for (let round = 24 - rounds; round < 24; round++) {\n`;
  // Theta θ
  out += '\n// Theta θ\n';
  for (let x = 0; x < 10; x++)
    out += `let B${x} = s${x} ^ s${x + 10} ^ s${x + 20} ^ s${x + 30} ^ s${x + 40};\n`;
  for (let x = 0; x < 10; x += 2) {
    const B0 = `B${(x + 2) % 10}`;
    const B1 = `B${((x + 2) % 10) + 1}`;
    out += `h = (${rotlHs(B0, B1, 1)}) ^ B${(x + 8) % 10}; `;
    out += `l = (${rotlLs(B0, B1, 1)}) ^ B${((x + 8) % 10) + 1};\n`;
    for (let y = 0; y < 50; y += 10) out += `s${x + y} ^= h; s${x + y + 1} ^= l; `;
    out += '\n';
  }
  // Rho (ρ) and Pi (π)
  out += '\n// Rho (ρ) and Pi (π)\n';
  out += `let sh = s${2}, sl = s${3}; `;
  for (let t = 0; t < 24; t++) {
    const shift = SHA3_ROTL[t];
    out += `h = ${rotlHs('sh', 'sl', shift)}; `;
    out += `l = ${rotlLs('sh', 'sl', shift)};\n`;
    const PI = SHA3_PI[t];
    out += `sh = s${PI}; sl = s${PI + 1}; `;
    out += `s${PI} = h; s${PI + 1} = l;\n`;
  }
  // Chi (χ)
  out += '\n// Chi (χ)\n';
  for (let y = 0; y < 50; y += 10) {
    for (let x = 0; x < 10; x++) out += `B${x} = s${y + x}; `;
    out += '\n';
    for (let x = 0; x < 10; x++) out += `s${y + x} ^= ~B${(x + 2) % 10} & B${(x + 4) % 10}; `;
    out += '\n';
  }
  // Iota (ι)
  out += `\n// Iota (ι)\n`;
  out += `s0 ^= SHA3_IOTA_H[round];\n`;
  out += `s1 ^= SHA3_IOTA_L[round];\n`;
  out += '}\n';
  for (let i = 0; i < 200 / 4; i++) out += `s[${i}] = s${i}; `;
  return new Function('state', 'rounds', 'SHA3_IOTA_H', 'SHA3_IOTA_L', out);
})();

console.log(keccakP.toString());
