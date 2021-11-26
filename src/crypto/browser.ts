export const crypto: { node?: any; web?: any } = {
  node: undefined,
  web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
};
