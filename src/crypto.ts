// Global symbol available in browsers only, node.js 19+, deno and others
declare const globalThis: Record<string, any> | undefined;
export const crypto: { node?: any; web?: any } = {
  node: undefined,
  web: typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined,
};
