const rotlHs = (h: string, l: string, s: number) =>
  s > 32 ? `(${l} << ${s - 32}) | (${h} >>> ${64 - s})` : `(${h} << ${s}) | (${l} >>> ${32 - s})`;
const rotlLs = (h: string, l: string, s: number) =>
  s > 32 ? `(${h} << ${s - 32}) | (${l} >>> ${64 - s})` : `(${l} << ${s}) | (${h} >>> ${32 - s})`;

export const keccakP = (() => {
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
