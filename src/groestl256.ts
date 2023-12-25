import { wrapConstructor } from './utils.js';
import { GROESTL } from './_groestl512';

// returns the first 256 bits of Groestl512
export class GROESTL256 extends GROESTL<GROESTL256> {
  constructor() {
    super(32, 128, false);
  }
}

export const groestl256 = /* @__PURE__ */ wrapConstructor(() => new GROESTL256());
