/* SQLCipher's entropy hook, giving its LibTomCrypt RNG the harness's deterministic getentropy. */
long sqlcipher_wasm_no_clock(void) { abort(); }

/* Fails closed so rng_get_bytes never falls through to the clock. */
static unsigned long sqlcipher_wasm_rng(unsigned char *out, unsigned long len, void (*callback)(void)) {
  (void)callback;
  if (getentropy(out, len) != 0) abort();
  return len;
}

int sqlcipher_wasm_extra_init(const char *arg) {
  ltc_rng = sqlcipher_wasm_rng;
  return sqlcipher_extra_init(arg);
}
