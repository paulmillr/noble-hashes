// // u32 * u32 = u64
// function mul(a, b) {
//   const aL = a & 0xffff;
//   const aH = a >>> 16;
//   const bL = b & 0xffff;
//   const bH = b >>> 16;
//   const ll = Math.imul(aL, bL);
//   const hl = Math.imul(aH, bL);
//   const lh = Math.imul(aL, bH);
//   const hh = Math.imul(aH, bH);
//   const carry = (ll >>> 16) + (hl & 0xffff) + lh;
//   const high = (hh + (hl >>> 16) + (carry >>> 16)) | 0;
//   const low = (carry << 16) | (ll & 0xffff);
//   return { h: high, l: low };
// }

// function mul2(a, b) {
//   // 2 * a * b (via shifts)
//   const { h, l } = mul(a, b);
//   return { h: ((h << 1) | (l >>> 31)) & 0xffff_ffff, l: (l << 1) & 0xffff_ffff };
// }

// // A + B + (2 * u32(A) * u32(B))
// function blamka(Ah, Al, Bh, Bl) {
//   const { h: Ch, l: Cl } = mul2(Al, Bl);
//   // A + B + (2 * A * B)
//   const Rll = add3L(Al, Bl, Cl);
//   return { h: add3H(Rll, Ah, Bh, Ch), l: Rll | 0 };
// }

// // Temporary block buffer
// const A2_BUF = new Uint32Array(256); // 1024

// function G(a, b, c, d) {
//   let Al = A2_BUF[2*a], Ah = A2_BUF[2*a + 1]; // prettier-ignore
//   let Bl = A2_BUF[2*b], Bh = A2_BUF[2*b + 1]; // prettier-ignore
//   let Cl = A2_BUF[2*c], Ch = A2_BUF[2*c + 1]; // prettier-ignore
//   let Dl = A2_BUF[2*d], Dh = A2_BUF[2*d + 1]; // prettier-ignore

//   ({ h: Ah, l: Al } = blamka(Ah, Al, Bh, Bl));
//   ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
//   ({ Dh, Dl } = { Dh: rotr32H(Dh, Dl), Dl: rotr32L(Dh, Dl) });

//   ({ h: Ch, l: Cl } = blamka(Ch, Cl, Dh, Dl));
//   ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
//   ({ Bh, Bl } = { Bh: rotrSH(Bh, Bl, 24), Bl: rotrSL(Bh, Bl, 24) });

//   ({ h: Ah, l: Al } = blamka(Ah, Al, Bh, Bl));
//   ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
//   ({ Dh, Dl } = { Dh: rotrSH(Dh, Dl, 16), Dl: rotrSL(Dh, Dl, 16) });

//   ({ h: Ch, l: Cl } = blamka(Ch, Cl, Dh, Dl));
//   ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
//   ({ Bh, Bl } = { Bh: rotrBH(Bh, Bl, 63), Bl: rotrBL(Bh, Bl, 63) });

//   (A2_BUF[2 * a] = Al), (A2_BUF[2 * a + 1] = Ah);
//   (A2_BUF[2 * b] = Bl), (A2_BUF[2 * b + 1] = Bh);
//   (A2_BUF[2 * c] = Cl), (A2_BUF[2 * c + 1] = Ch);
//   (A2_BUF[2 * d] = Dl), (A2_BUF[2 * d + 1] = Dh);
// }

// // prettier-ignore
// function P(
//   v00, v01, v02, v03, v04, v05, v06, v07,
//   v08, v09, v10, v11, v12, v13, v14, v15,
// ) {
//   G(v00, v04, v08, v12);
//   G(v01, v05, v09, v13);
//   G(v02, v06, v10, v14);
//   G(v03, v07, v11, v15);
//   G(v00, v05, v10, v15);
//   G(v01, v06, v11, v12);
//   G(v02, v07, v08, v13);
//   G(v03, v04, v09, v14);
// }

// function block(x, xPos, yPos, outPos, needXor) {
//   for (let i = 0; i < 256; i++) A2_BUF[i] = x[xPos + i] ^ x[yPos + i];
//   // columns
//   for (let i = 0; i < 128; i += 16) {
//     // prettier-ignore
//     P(
//       i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7,
//       i + 8, i + 9, i + 10, i + 11, i + 12, i + 13, i + 14, i + 15
//     );
//   }
//   // rows
//   for (let i = 0; i < 16; i += 2) {
//     // prettier-ignore
//     P(
//       i, i + 1, i + 16, i + 17, i + 32, i + 33, i + 48, i + 49,
//       i + 64, i + 65, i + 80, i + 81, i + 96, i + 97, i + 112, i + 113
//     );
//   }
//   if (needXor) for (let i = 0; i < 256; i++) x[outPos + i] ^= A2_BUF[i] ^ x[xPos + i] ^ x[yPos + i];
//   else for (let i = 0; i < 256; i++) x[outPos + i] = A2_BUF[i] ^ x[xPos + i] ^ x[yPos + i];
//   A2_BUF.fill(0);
// }

const num = (i) => `${i}`.padStart(2, '0');

function genP() {
  let res = `function P(
   v00: number, v01: number, v02: number, v03: number, v04: number, v05: number, v06: number, v07: number,
   v08: number, v09: number, v10: number, v11: number, v12: number, v13: number, v14: number, v15: number,
) {
`;
  for (let i = 0; i < 16; i++) {
    res += `let V${num(i)}l = A2_BUF[2*v${num(i)}], V${num(i)}h = A2_BUF[2*v${num(i)} + 1]; // prettier-ignore\n`;
  }
  const G = (a, b, c, d) => {
    res += `// A: ${a} B: ${b} C: ${c} D: ${d}\n`;
    const Ah = `V${num(a)}h`, Al = `V${num(a)}l`; // prettier-ignore
    const Bh = `V${num(b)}h`, Bl = `V${num(b)}l`; // prettier-ignore
    const Ch = `V${num(c)}h`, Cl = `V${num(c)}l`; // prettier-ignore
    const Dh = `V${num(d)}h`, Dl = `V${num(d)}l`; // prettier-ignore

    res += `
    ({ h: ${Ah}, l: ${Al} } = blamka(${Ah}, ${Al}, ${Bh}, ${Bl}));
    ({ ${Dh}, ${Dl} } = { ${Dh}: ${Dh} ^ ${Ah}, ${Dl}: ${Dl} ^ ${Al} });
    ({ ${Dh}, ${Dl} } = { ${Dh}: rotr32H(${Dh}, ${Dl}), ${Dl}: rotr32L(${Dh}, ${Dl}) });
    ({ h: ${Ch}, l: ${Cl} } = blamka(${Ch}, ${Cl}, ${Dh}, ${Dl}));
    ({ ${Bh}, ${Bl} } = { ${Bh}: ${Bh} ^ ${Ch}, ${Bl}: ${Bl} ^ ${Cl} });
    ({ ${Bh}, ${Bl} } = { ${Bh}: rotrSH(${Bh}, ${Bl}, 24), ${Bl}: rotrSL(${Bh}, ${Bl}, 24) });
    ({ h: ${Ah}, l: ${Al} } = blamka(${Ah}, ${Al}, ${Bh}, ${Bl}));
    ({ ${Dh}, ${Dl} } = { ${Dh}: ${Dh} ^ ${Ah}, ${Dl}: ${Dl} ^ ${Al} });
    ({ ${Dh}, ${Dl} } = { ${Dh}: rotrSH(${Dh}, ${Dl}, 16), ${Dl}: rotrSL(${Dh}, ${Dl}, 16) });
    ({ h: ${Ch}, l: ${Cl} } = blamka(${Ch}, ${Cl}, ${Dh}, ${Dl}));
    ({ ${Bh}, ${Bl} } = { ${Bh}: ${Bh} ^ ${Ch}, ${Bl}: ${Bl} ^ ${Cl} });
    ({ ${Bh}, ${Bl} } = { ${Bh}: rotrBH(${Bh}, ${Bl}, 63), ${Bl}: rotrBL(${Bh}, ${Bl}, 63) });
    
    
`;
  };

  G(0, 4, 8, 12);
  G(1, 5, 9, 13);
  G(2, 6, 10, 14);
  G(3, 7, 11, 15);
  G(0, 5, 10, 15);
  G(1, 6, 11, 12);
  G(2, 7, 8, 13);
  G(3, 4, 9, 14);

  for (let i = 0; i < 16; i++) {
    res += `(A2_BUF[2 * v${num(i)}] = V${num(i)}l), (A2_BUF[2 * v${num(i)} + 1] = V${num(i)}h);\n`;
  }
  res += `
}`;
  return res;
}

function genBlock() {
  let res = `function block(x: Uint32Array, xPos: number, yPos: number, outPos: number, needXor: boolean) {
`;
  for (let i = 0; i < 256; i++) res += `let A2_BUF${num(i)} = x[xPos + ${i}] ^ x[yPos + ${i}];\n`;

  function G(a, b, c, d) {
    res += `
    {
      let Al = A2_BUF${num(2 * a)}, Ah = A2_BUF${num(2 * a + 1)}; // prettier-ignore
      let Bl = A2_BUF${num(2 * b)}, Bh = A2_BUF${num(2 * b + 1)}; // prettier-ignore
      let Cl = A2_BUF${num(2 * c)}, Ch = A2_BUF${num(2 * c + 1)}; // prettier-ignore
      let Dl = A2_BUF${num(2 * d)}, Dh = A2_BUF${num(2 * d + 1)}; // prettier-ignore

      ({ h: Ah, l: Al } = blamka(Ah, Al, Bh, Bl));
      ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
      ({ Dh, Dl } = { Dh: rotr32H(Dh, Dl), Dl: rotr32L(Dh, Dl) });

      ({ h: Ch, l: Cl } = blamka(Ch, Cl, Dh, Dl));
      ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
      ({ Bh, Bl } = { Bh: rotrSH(Bh, Bl, 24), Bl: rotrSL(Bh, Bl, 24) });

      ({ h: Ah, l: Al } = blamka(Ah, Al, Bh, Bl));
      ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
      ({ Dh, Dl } = { Dh: rotrSH(Dh, Dl, 16), Dl: rotrSL(Dh, Dl, 16) });

      ({ h: Ch, l: Cl } = blamka(Ch, Cl, Dh, Dl));
      ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
      ({ Bh, Bl } = { Bh: rotrBH(Bh, Bl, 63), Bl: rotrBL(Bh, Bl, 63) });

      (A2_BUF${num(2 * a)} = Al), (A2_BUF${num(2 * a + 1)} = Ah);
      (A2_BUF${num(2 * b)} = Bl), (A2_BUF${num(2 * b + 1)} = Bh);
      (A2_BUF${num(2 * c)} = Cl), (A2_BUF${num(2 * c + 1)} = Ch);
      (A2_BUF${num(2 * d)} = Dl), (A2_BUF${num(2 * d + 1)} = Dh);
    }
    `;
  }

  function P(v00, v01, v02, v03, v04, v05, v06, v07, v08, v09, v10, v11, v12, v13, v14, v15) {
    G(v00, v04, v08, v12);
    G(v01, v05, v09, v13);
    G(v02, v06, v10, v14);
    G(v03, v07, v11, v15);
    G(v00, v05, v10, v15);
    G(v01, v06, v11, v12);
    G(v02, v07, v08, v13);
    G(v03, v04, v09, v14);
  }
  // columns (8)
  for (let i = 0; i < 128; i += 16) {
    // prettier-ignore
    P(
      i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7,
      i + 8, i + 9, i + 10, i + 11, i + 12, i + 13, i + 14, i + 15
    );
  }
  // rows (8)
  for (let i = 0; i < 16; i += 2) {
    // prettier-ignore
    P(
      i, i + 1, i + 16, i + 17, i + 32, i + 33, i + 48, i + 49,
      i + 64, i + 65, i + 80, i + 81, i + 96, i + 97, i + 112, i + 113
    );
  }

  res += `  if (needXor) {\n`;
  for (let i = 0; i < 256; i++)
    res += `    x[outPos + ${i}] ^= A2_BUF${num(i)} ^ x[xPos + ${i}] ^ x[yPos + ${i}];\n`;
  res += `  } else {\n`;
  for (let i = 0; i < 256; i++)
    res += `    x[outPos + ${i}] = A2_BUF${num(i)} ^ x[xPos + ${i}] ^ x[yPos + ${i}];\n`;
  res += '  }';
  res += `
}`;
  return res;
}

// console.log(genBlock());

function genBlock2() {
  let res = `function block(x: Uint32Array, xPos: number, yPos: number, outPos: number, needXor: boolean) {
  for (let i = 0; i < 256; i++) A2_BUF[i] = x[xPos + i] ^ x[yPos + i];
`;
  // columns (8)
  for (let i = 0; i < 128; i += 16) {
    res += ` // prettier-ignore
  P(
    ${i}, ${i + 1}, ${i + 2}, ${i + 3}, ${i + 4}, ${i + 5}, ${i + 6}, ${i + 7},
    ${i + 8}, ${i + 9}, ${i + 10}, ${i + 11}, ${i + 12}, ${i + 13}, ${i + 14}, ${i + 15}
  );
`;
  }
  // rows (8)
  for (let i = 0; i < 16; i += 2) {
    res += ` // prettier-ignore
  P(
    ${i}, ${i + 1}, ${i + 16}, ${i + 17}, ${i + 32}, ${i + 33}, ${i + 48}, ${i + 49},
    ${i + 64}, ${i + 65}, ${i + 80}, ${i + 81}, ${i + 96}, ${i + 97}, ${i + 112}, ${i + 113}
  );
`;
  }
  res += `
  if (needXor) for (let i = 0; i < 256; i++) x[outPos + i] ^= A2_BUF[i] ^ x[xPos + i] ^ x[yPos + i];
  else for (let i = 0; i < 256; i++) x[outPos + i] = A2_BUF[i] ^ x[xPos + i] ^ x[yPos + i];
  A2_BUF.fill(0);`;
  res += `
}`;
  return res;
}

console.log(genBlock2());
