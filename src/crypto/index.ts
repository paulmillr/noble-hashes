export const crypto: { node?: any; web?: any } = (() => {
	// This path will never be followed
	throw new Error(
		'noble-hashes/lib/crypto has no entry-point. Export maps are used.'
	);
})();
