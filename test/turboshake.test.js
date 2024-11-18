// https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/
// https://eprint.iacr.org/2023/342.pdf
const { deepStrictEqual, throws } = require('assert');
const { describe, should } = require('micro-should');
const { turboshake128, turboshake256, k12 } = require('../sha3-addons');
const { pattern, bytesToHex: toHex, hexToBytes } = require('./utils');

const fromHex = (hex) => hexToBytes(hex.replace(/ |\n/gm, ''));

const VECTORS_TURBO = [
  {
    hash: turboshake128,
    msg: new Uint8Array(0),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `5A 22 3A D3 0B 3B 8C 66 A2 43 04 8C FC ED 43 0F
       54 E7 52 92 87 D1 51 50 B9 73 13 3A DF AC 6A 2F`
    ),
  },
  {
    hash: turboshake128,
    msg: new Uint8Array(0),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `5A 22 3A D3 0B 3B 8C 66 A2 43 04 8C FC ED 43 0F
        54 E7 52 92 87 D1 51 50 B9 73 13 3A DF AC 6A 2F
        FE 27 08 E7 30 61 E0 9A 40 00 16 8B A9 C8 CA 18
        13 19 8F 7B BE D4 98 4B 41 85 F2 C2 58 0E E6 23`
    ),
  },
  {
    hash: turboshake128,
    msg: new Uint8Array(0),
    dkLen: 10032,
    D: 0x07,
    last: 32,
    exp: fromHex(
      `75 93 A2 80 20 A3 C4 AE 0D 60 5F D6 1F 5E B5 6E
      CC D2 7C C3 D1 2F F0 9F 78 36 97 72 A4 60 C5 5D`
    ),
  },
  {
    hash: turboshake128,
    msg: pattern(0xfa, 1),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `1A C2 D4 50 FC 3B 42 05 D1 9D A7 BF CA 1B 37 51
      3C 08 03 57 7A C7 16 7F 06 FE 2C E1 F0 EF 39 E5`
    ),
  },
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `AC BD 4A A5 75 07 04 3B CE E5 5A D3 F4 85 04 D8
      15 E7 07 FE 82 EE 3D AD 6D 58 52 C8 92 0B 90 5E`
    ),
  },
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 2),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `7A 4D E8 B1 D9 27 A6 82 B9 29 61 01 03 F0 E9 64
      55 9B D7 45 42 CF AD 74 0E E3 D9 B0 36 46 9E 0A`
    ),
  },
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 3),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `74 52 ED 0E D8 60 AA 8F E8 E7 96 99 EC E3 24 F8
      D9 32 71 46 36 10 DA 76 80 1E BC EE 4F CA FE 42`
    ),
  },
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 4),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `CA 5F 1F 3E EA C9 92 CD C2 AB EB CA 0E 21 67 65
      DB F7 79 C3 C1 09 46 05 5A 94 AB 32 72 57 35 22`
    ),
  },
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 5),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `E9 88 19 3F B9 11 9F 11 CD 34 46 79 14 E2 A2 6D
      A9 BD F9 6C 8B EF 07 6A EE AD 1A 89 7B 86 63 83`
    ),
  },
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 6),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `9C 0F FB 98 7E EE ED AD FA 55 94 89 87 75 6D 09
      0B 67 CC B6 12 36 E3 06 AC 8A 24 DE 1D 0A F7 74`
    ),
  },
  {
    hash: turboshake128,
    msg: new Uint8Array(0),
    dkLen: 32,
    D: 0x0b,
    exp: fromHex(
      `8B 03 5A B8 F8 EA 7B 41 02 17 16 74 58 33 2E 46
      F5 4B E4 FF 83 54 BA F3 68 71 04 A6 D2 4B 0E AB`
    ),
  },
  {
    hash: turboshake128,
    msg: new Uint8Array(0),
    dkLen: 32,
    D: 0x06,
    exp: fromHex(
      `C7 90 29 30 6B FA 2F 17 83 6A 3D 65 16 D5 56 63
      40 FE A6 EB 1A 11 39 AD 90 0B 41 24 3C 49 4B 37`
    ),
  },
  {
    hash: turboshake128,
    msg: fromHex('FF'),
    dkLen: 32,
    D: 0x06,
    exp: fromHex(
      `8E C9 C6 64 65 ED 0D 4A 6C 35 D1 35 06 71 8D 68
      7A 25 CB 05 C7 4C CA 1E 42 50 1A BD 83 87 4A 67`
    ),
  },
  {
    hash: turboshake128,
    msg: fromHex('FF FF FF'),
    dkLen: 32,
    D: 0x06,
    exp: fromHex(
      `3D 03 98 8B B5 9E 68 18 51 A1 92 F4 29 AE 03 98
      8E 8F 44 4B C0 60 36 A3 F1 A7 D2 CC D7 58 D1 74`
    ),
  },
  {
    hash: turboshake128,
    msg: fromHex('FF FF FF FF FF FF FF'),
    dkLen: 32,
    D: 0x06,
    exp: fromHex(
      `05 D9 AE 67 3D 5F 0E 48 BB 2B 57 E8 80 21 A1 A8
      3D 70 BA 85 92 3A A0 4C 12 E8 F6 5B A1 F9 45 95`
    ),
  },
  {
    hash: turboshake256,
    msg: new Uint8Array(0),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `4A 55 5B 06 EC F8 F1 53 8C CF 5C 95 15 D0 D0 49
      70 18 15 63 A6 23 81 C7 F0 C8 07 A6 D1 BD 9E 81
      97 80 4B FD E2 42 8B F7 29 61 EB 52 B4 18 9C 39
      1C EF 6F EE 66 3A 3C 1C E7 8B 88 25 5B C1 AC C3`
    ),
  },
  {
    hash: turboshake256,
    msg: new Uint8Array(0),
    dkLen: 10032,
    last: 32,
    D: 0x07,
    exp: fromHex(
      `40 22 1A D7 34 F3 ED C1 B1 06 BA D5 0A 72 94 93
      15 B3 52 BA 39 AD 98 B5 B3 C2 30 11 63 AD AA D0`
    ),
  },
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `66 D3 78 DF E4 E9 02 AC 4E B7 8F 7C 2E 5A 14 F0
      2B C1 C8 49 E6 21 BA E6 65 79 6F B3 34 6E 6C 79
      75 70 5B B9 3C 00 F3 CA 8F 83 BC A4 79 F0 69 77
      AB 3A 60 F3 97 96 B1 36 53 8A AA E8 BC AC 85 44`
    ),
  },
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 2),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `C5 21 74 AB F2 82 95 E1 5D FB 37 B9 46 AC 36 BD
      3A 6B CC 98 C0 74 FC 25 19 9E 05 30 42 5C C5 ED
      D4 DF D4 3D C3 E7 E6 49 1A 13 17 98 30 C3 C7 50
      C9 23 7E 83 FD 9A 3F EC 46 03 FF 57 E4 22 2E F2`
    ),
  },
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 3),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `62 A5 A0 BF F0 64 26 D7 1A 7A 3E 9E 3F 2F D6 E2
      52 FF 3F C1 88 A6 A5 36 EC A4 5A 49 A3 43 7C B3
      BC 3A 0F 81 49 C8 50 E6 E7 F4 74 7A 70 62 7F D2
      30 30 41 C6 C3 36 30 F9 43 AD 92 F8 E1 FF 43 90`
    ),
  },
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 4),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `52 3C 06 47 18 2D 89 41 F0 DD 5C 5C 0A B6 2D 4F
      C2 95 61 61 53 96 BB 5B 9A 9D EB 02 2B 80 C5 BF
      2D 83 A3 BB 36 FF C0 4F AC 58 CF 11 49 C6 6D EC
      4A 59 52 6E 51 F2 95 96 D8 24 42 1A 4B 84 B4 4D`
    ),
  },
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 5),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `D1 14 A1 C1 A2 08 FF 05 FD 49 D0 9E E0 35 46 5D
      86 54 7E BA D8 E9 AF 4F 8E 87 53 70 57 3D 6B 7B
      B2 0A B9 60 63 5A B5 74 E2 21 95 EF 9D 17 1C 9A
      28 01 04 4B 6E 2E DF 27 2E 23 02 55 4B 3A 77 C9`
    ),
  },
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 6),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `1E 51 34 95 D6 16 98 75 B5 94 53 A5 94 E0 8A E2
      71 CA 20 E0 56 43 C8 8A 98 7B 5B 6A B4 23 ED E7
      24 0F 34 F2 B3 35 FA 94 BC 4B 0D 70 E3 1F B6 33
      B0 79 84 43 31 FE A4 2A 9C 4D 79 BB 8C 5F 9E 73`
    ),
  },
  {
    hash: turboshake256,
    msg: new Uint8Array(0),
    dkLen: 64,
    D: 0x0b,
    exp: fromHex(
      `C7 49 F7 FB 23 64 4A 02 1D 35 65 3D 1B FD F7 47
      CE CE 5F 97 39 F9 A3 44 AD 16 9F 10 90 6C 68 17
      C8 EE 12 78 4E 42 FF 57 81 4E FC 1C 89 87 89 D5
      E4 15 DB 49 05 2E A4 3A 09 90 1D 7A 82 A2 14 5C`
    ),
  },
  {
    hash: turboshake256,
    msg: new Uint8Array(0),
    dkLen: 64,
    D: 0x06,
    exp: fromHex(
      `FF 23 DC CD 62 16 8F 5A 44 46 52 49 A8 6D C1 0E
      8A AB 4B D2 6A 22 DE BF 23 48 02 0A 83 1C DB E1
      2C DD 36 A7 DD D3 1E 71 C0 1F 7C 97 A0 D4 C3 A0
      CC 1B 21 21 E6 B7 CE AB 38 87 A4 C9 A5 AF 8B 03`
    ),
  },
  {
    hash: turboshake256,
    msg: fromHex('FF'),
    dkLen: 64,
    D: 0x06,
    exp: fromHex(
      `73 8D 7B 4E 37 D1 8B 7F 22 AD 1B 53 13 E3 57 E3
      DD 7D 07 05 6A 26 A3 03 C4 33 FA 35 33 45 52 80
      F4 F5 A7 D4 F7 00 EF B4 37 FE 6D 28 14 05 E0 7B
      E3 2A 0A 97 2E 22 E6 3A DC 1B 09 0D AE FE 00 4B`
    ),
  },
  {
    hash: turboshake256,
    msg: fromHex('FF FF FF'),
    dkLen: 64,
    D: 0x06,
    exp: fromHex(
      `E5 53 8C DD 28 30 2A 2E 81 E4 1F 65 FD 2A 40 52
      01 4D 0C D4 63 DF 67 1D 1E 51 0A 9D 95 C3 7D 71
      35 EF 27 28 43 0A 9E 31 70 04 F8 36 C9 A2 38 EF
      35 37 02 80 D0 3D CE 7F 06 12 F0 31 5B 3C BF 63`
    ),
  },
  {
    hash: turboshake256,
    msg: fromHex('FF FF FF FF FF FF FF'),
    dkLen: 64,
    D: 0x06,
    exp: fromHex(
      `B3 8B 8C 15 F4 A6 E8 0C D3 EC 64 5F 99 9F 64 98
      AA D7 A5 9A 48 9C 1D EE 29 70 8B 4F 8A 59 E1 24
      99 A9 6F 89 37 22 56 FE 52 2B 1B 97 47 2A DD 73
      69 15 BD 4D F9 3B 21 FF E5 97 21 7E B3 C2 C6 D9`
    ),
  },
  // Additional vectors for default dkLen
  {
    hash: turboshake128,
    msg: fromHex('FF FF FF FF FF FF FF'),
    // dkLen: 32,
    D: 0x06,
    exp: fromHex(
      `05 D9 AE 67 3D 5F 0E 48 BB 2B 57 E8 80 21 A1 A8
      3D 70 BA 85 92 3A A0 4C 12 E8 F6 5B A1 F9 45 95`
    ),
  },
  {
    hash: turboshake256,
    msg: fromHex('FF FF FF FF FF FF FF'),
    D: 0x06,
    // dkLen: 64,
    exp: fromHex(
      `B3 8B 8C 15 F4 A6 E8 0C D3 EC 64 5F 99 9F 64 98
      AA D7 A5 9A 48 9C 1D EE 29 70 8B 4F 8A 59 E1 24
      99 A9 6F 89 37 22 56 FE 52 2B 1B 97 47 2A DD 73
      69 15 BD 4D F9 3B 21 FF E5 97 21 7E B3 C2 C6 D9`
    ),
  },
];

const VECTORS_K12 = [
  {
    hash: k12,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `1A C2 D4 50 FC 3B 42 05 D1 9D A7 BF CA 1B 37 51
      3C 08 03 57 7A C7 16 7F 06 FE 2C E1 F0 EF 39 E5`
    ),
  },
  {
    hash: k12,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `1A C2 D4 50 FC 3B 42 05 D1 9D A7 BF CA 1B 37 51
      3C 08 03 57 7A C7 16 7F 06 FE 2C E1 F0 EF 39 E5
      42 69 C0 56 B8 C8 2E 48 27 60 38 B6 D2 92 96 6C
      C0 7A 3D 46 45 27 2E 31 FF 38 50 81 39 EB 0A 71`
    ),
  },
  {
    hash: k12,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 10032,
    last: 32,
    exp: fromHex(
      `E8 DC 56 36 42 F7 22 8C 84 68 4C 89 84 05 D3 A8
      34 79 91 58 C0 79 B1 28 80 27 7A 1D 28 E2 FF 6D`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 1),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `2B DA 92 45 0E 8B 14 7F 8A 7C B6 29 E7 84 A0 58
      EF CA 7C F7 D8 21 8E 02 D3 45 DF AA 65 24 4A 1F`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 17),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `6B F7 5F A2 23 91 98 DB 47 72 E3 64 78 F8 E1 9B
      0F 37 12 05 F6 A9 A9 3A 27 3F 51 DF 37 12 28 88`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 17 ** 2),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `0C 31 5E BC DE DB F6 14 26 DE 7D CF 8F B7 25 D1
      E7 46 75 D7 F5 32 7A 50 67 F3 67 B1 08 EC B6 7C`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 17 ** 3),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `CB 55 2E 2E C7 7D 99 10 70 1D 57 8B 45 7D DF 77
      2C 12 E3 22 E4 EE 7F E4 17 F9 2C 75 8F 0D 59 D0`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 17 ** 4),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `87 01 04 5E 22 20 53 45 FF 4D DA 05 55 5C BB 5C
      3A F1 A7 71 C2 B8 9B AE F3 7D B4 3D 99 98 B9 FE`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 17 ** 5),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `84 4D 61 09 33 B1 B9 96 3C BD EB 5A E3 B6 B0 5C
      C7 CB D6 7C EE DF 88 3E B6 78 A0 A8 E0 37 16 82`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 17 ** 6),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `3C 39 07 82 A8 A4 E8 9F A6 36 7F 72 FE AA F1 32
      55 C8 D9 58 78 48 1D 3C D8 CE 85 F5 8E 88 0A F8`
    ),
  },
  {
    hash: k12,
    msg: new Uint8Array(0),
    C: pattern(0xfa, 1),
    dkLen: 32,
    exp: fromHex(
      `FA B6 58 DB 63 E9 4A 24 61 88 BF 7A F6 9A 13 30
      45 F4 6E E9 84 C5 6E 3C 33 28 CA AF 1A A1 A5 83`
    ),
  },
  {
    hash: k12,
    msg: fromHex('FF'),
    C: pattern(0xfa, 41),
    dkLen: 32,
    exp: fromHex(
      `D8 48 C5 06 8C ED 73 6F 44 62 15 9B 98 67 FD 4C
      20 B8 08 AC C3 D5 BC 48 E0 B0 6B A0 A3 76 2E C4`
    ),
  },
  {
    hash: k12,
    msg: fromHex('FF FF FF'),
    C: pattern(0xfa, 41 ** 2),
    dkLen: 32,
    exp: fromHex(
      `C3 89 E5 00 9A E5 71 20 85 4C 2E 8C 64 67 0A C0
      13 58 CF 4C 1B AF 89 44 7A 72 42 34 DC 7C ED 74`
    ),
  },
  {
    hash: k12,
    msg: fromHex('FF FF FF FF FF FF FF'),
    C: pattern(0xfa, 41 ** 3),
    dkLen: 32,
    exp: fromHex(
      `75 D2 F8 6A 2E 64 45 66 72 6B 4F BC FC 56 57 B9
      DB CF 07 0C 7B 0D CA 06 45 0A B2 91 D7 44 3B CF`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 8191),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `1B 57 76 36 F7 23 64 3E 99 0C C7 D6 A6 59 83 74
      36 FD 6A 10 36 26 60 0E B8 30 1C D1 DB E5 53 D6`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 8192),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `48 F2 56 F6 77 2F 9E DF B6 A8 B6 61 EC 92 DC 93
      B9 5E BD 05 A0 8A 17 B3 9A E3 49 08 70 C9 26 C3`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 8192),
    C: pattern(0xfa, 8189),
    dkLen: 32,
    exp: fromHex(
      `3E D1 2F 70 FB 05 DD B5 86 89 51 0A B3 E4 D2 3C
      6C 60 33 84 9A A0 1E 1D 8C 22 0A 29 7F ED CD 0B`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 8192),
    C: pattern(0xfa, 8190),
    dkLen: 32,
    exp: fromHex(
      `6A 7C 1B 6A 5C D0 D8 C9 CA 94 3A 4A 21 6C C6 46
      04 55 9A 2E A4 5F 78 57 0A 15 25 3D 67 BA 00 AE`
    ),
  },
];

describe('TurboSHAKE', () => {
  // Pattern for a length of 17 bytes:
  should('pattern', () => {
    deepStrictEqual(
      pattern(0xfa, 17),
      fromHex(`00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10`)
    );
    deepStrictEqual(
      pattern(0xfa, 17 ** 2),
      fromHex(`00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
            10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
            20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F
            30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F
            40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
            50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
            60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F
            70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F
            80 81 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F
            90 91 92 93 94 95 96 97 98 99 9A 9B 9C 9D 9E 9F
            A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF
            B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF
            C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA CB CC CD CE CF
            D0 D1 D2 D3 D4 D5 D6 D7 D8 D9 DA DB DC DD DE DF
            E0 E1 E2 E3 E4 E5 E6 E7 E8 E9 EA EB EC ED EE EF
            F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA
            00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
            10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
            20 21 22 23 24 25`)
    );
  });
  should('vectors: turboshake (cross test)', () => {
    deepStrictEqual(
      toHex(
        turboshake128(
          fromHex(
            '437eb3035217e99baea4232ea2f06c2bea1c2c49e58cc0d59762b53887bc69e952dbcfb7a43cc7c817c2d42ae68633fc0f6a9120d02b6616e52cf1074fd8d471'
          )
        )
      ),
      '8e2e8cec4b4056b7810d78da12751029ad4a5b1694d5ca82ebf8b4de9cb4596a'
    );
    deepStrictEqual(
      toHex(
        turboshake256(
          fromHex(
            '51a668f743e40bdafa26502aafaf149dfec1d1780344b3a6286f6e74523c4575a057504d1508d30d326a308f149cd6faedc0a31c164faf514911020c754fef26'
          )
        )
      ),
      'f344b591079f09bc0d6e3f6277b1aab5354cfab81caf4afd37b7e7de6497632a2c4108f23331ce11de41e6a2ace2d7dcd5d8a7aef1a1c0c1c389e7dc26e0ca65'
    );
  });
  should('vectors: turboshake', () => {
    for (const v of VECTORS_TURBO) {
      let res = v.hash(v.msg, { dkLen: v.dkLen, D: v.D });
      if (v.last) res = res.subarray(-v.last);
      deepStrictEqual(res, v.exp);
    }
  });
  should('vectors: k12', () => {
    for (const v of VECTORS_K12) {
      let res = v.hash(v.msg, { personalization: v.C, dkLen: v.dkLen });
      if (v.last) res = res.subarray(-v.last);
      deepStrictEqual(res, v.exp);
    }
  });
  should('domain separation byte', () => {
    for (const h of [turboshake128, turboshake256]) {
      throws(() => h('', { D: 0 }));
      throws(() => h('', { D: 0x80 }));
      h('', { D: 1 }); // doesn't throw
      h('', { D: 0x7f }); // doesn't throw
    }
  });
});

if (require.main === module) should.run();
