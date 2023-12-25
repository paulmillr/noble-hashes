import { wrapConstructor } from './utils.js';
import { GROESTL } from './_groestl512';

export class GROESTL512 extends GROESTL<GROESTL512> {
  constructor() {
    super(64, 128, false);
  }
}

export const groestl512 = /* @__PURE__ */ wrapConstructor(() => new GROESTL512());
