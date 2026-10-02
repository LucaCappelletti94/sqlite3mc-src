//! Replaces libc's `getentropy`, the call SQLCipher's RNG makes directly (`sqlcipher_wasm_rng` in
//! `WASM_SOURCE_FILE`), with a deterministic stream reset once per [`run`](crate::run::run) call, so
//! the same [`Case`](crate::Case) produces the same salts and IVs on every repeat, not just the same
//! workload. SQLite3MC's own RNG reads `/dev/urandom` first and falls back to `getentropy` only if
//! that open fails, so this does not make SQLite3MC's own writes deterministic; it is enough for any
//! divergence whose randomness comes from SQLCipher's own side, which is where it is drawn from.

use std::cell::Cell;

thread_local! {
    static STATE: Cell<u64> = const { Cell::new(0x9e37_79b9_7f4a_7c15) };
}

/// Reseeds the deterministic stream `getentropy` below draws from. Call once per [`run`] invocation,
/// before anything that might key or write a page, with a seed derived from the case itself so two
/// different cases draw different streams but the same case always draws the same one.
pub(crate) fn reset(seed: u64) {
    STATE.with(|state| state.set(seed | 1));
}

/// xorshift64*, fast and good enough to stand in for real entropy in a replay-friendly harness.
fn next(state: &Cell<u64>) -> u64 {
    let mut x = state.get();
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    state.set(x);
    x.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

/// # Safety
/// `buf` must be valid for `len` writable bytes for the duration of this call, the same contract
/// libc's own `getentropy` has; the caller owns and allocates the buffer, this function only fills it.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getentropy(buf: *mut u8, len: usize) -> i32 {
    STATE.with(|state| {
        let mut filled = 0usize;
        while filled < len {
            let word = next(state).to_le_bytes();
            let take = word.len().min(len - filled);
            // SAFETY: `buf..buf+len` is valid for writes for the whole call per this function's own
            // caller contract, `u8` has no alignment requirement so `buf.add(filled)` needs no
            // alignment check, `filled + take <= len` by construction so the destination range
            // stays in bounds, `word` is a local stack array with no aliasing to `buf` possible,
            // and `take <= word.len()` so the source read stays in bounds too.
            unsafe {
                std::ptr::copy_nonoverlapping(word.as_ptr(), buf.add(filled), take);
            }
            filled += take;
        }
    });
    0
}
