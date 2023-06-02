(async () => {
  await require('./hashes.js').main();
  await require('./kdf.js').main();
})();
