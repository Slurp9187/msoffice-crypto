//! How much non-zero memory this crate abandons to the allocator, measured.
//!
//! **This is a measurement, not a gate**, and it is `#[ignore]`d for that reason. Run it
//! deliberately:
//!
//! ```text
//! cargo test --no-default-features --features crypto-ops --test heap_residue \
//!     -- --ignored --nocapture --test-threads=1
//! ```
//!
//! # Why it is not an assertion
//!
//! It was built to demonstrate the defect class in `docs/design/heap-residue.md` — a `Vec`
//! that grows frees its old block unwiped, and the wrapper is by then holding the new one
//! and is perfectly correct about it. The obvious next step is to assert a budget and call
//! it a regression guard. **Measured, that does not work.** Reverting
//! `standard_encrypt::generate` to its pre-fix `to_vec()` + `resize` form moves the numbers
//! by exactly one block:
//!
//! | `encrypt_ooxml_standard` | blocks | dirty | 20-byte dirty |
//! |---|---|---|---|
//! | pre-fix (defective)      | 521    | 516   | 23            |
//! | as shipped (fixed)       | 520    | 515   | 22            |
//!
//! One block in 520, against counts that already move with the optimization level (520 at
//! `opt-level 0`, 404 at `--release`, because the optimizer elides allocations outright)
//! and with the randomised verifier. The signal is below the noise, so a threshold here
//! would be decoration — it would pass with and without the thing it claims to guard,
//! which CLAUDE.md § Testing Rules names as the anti-pattern.
//!
//! What it asserts instead is only that **the instrument works**: blocks were released and
//! some carried non-zero bytes. That fails loudly if the probe stops observing, which is
//! the one way a measurement can lie while looking healthy.
//!
//! # What the numbers are, and are not
//!
//! `dirty_bytes` counts every non-zero byte in every released block. Most of the
//! `encrypt_ooxml_standard` figure is **document data** — the package, the ciphertext, ZIP
//! and CFB buffers — not key material. Do not read it as a secret-exposure number.
//!
//! The agile figure is different in kind: ~100 000 of its released blocks are `spin_hash`'s
//! per-round intermediates, which *are* key-derived, and which
//! `.claude/skills/msoffice-crypto-secure-gate/SKILL.md` names as a case a wrapper cannot
//! economically reach.
//!
//! # The other half of this test does not exist yet
//!
//! `docs/design/heap-residue.md` records the subject half: the same probe with a zeroizing
//! global allocator installed underneath, where every one of these blocks comes back clean.
//! That half is **not committed** because it needs `secure-gate-zalloc`, which is
//! unpublished — and a Cargo dev-dependency cannot be optional or feature-gated, so a path
//! dependency on it would always resolve and would break every CI job by construction.
//!
//! When it publishes, the subject half is this file with two changes: a
//! `secure-gate-zalloc` dev-dependency, and
//! `#[global_allocator] static A: ZeroizingAlloc<Spy> = ZeroizingAlloc(Spy);` in place of
//! the bare `Spy` below. `Spy::realloc` must keep mirroring the wrapper's rather than
//! forwarding to `System` — see the note on it.
#![cfg(feature = "crypto-ops")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Count only while the workload runs; otherwise the harness's own allocations dominate.
static ARMED: AtomicBool = AtomicBool::new(false);
static BLOCKS: AtomicUsize = AtomicUsize::new(0);
static DIRTY_BLOCKS: AtomicUsize = AtomicUsize::new(0);
static DIRTY_BYTES: AtomicUsize = AtomicUsize::new(0);
static LARGEST_DIRTY: AtomicUsize = AtomicUsize::new(0);

struct Spy;

// SAFETY: every method forwards to `System` with the layout it was given. The counting
// path reads only within `layout.size()` of a block the caller is releasing, before
// `System` is told about it, and allocates nothing itself.
unsafe impl GlobalAlloc for Spy {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    /// Deliberately **not** `System.realloc`.
    ///
    /// libc's `realloc` releases the old block inside the C allocator, so it never passes
    /// through `dealloc` and this probe cannot see it — which silently hides exactly the
    /// reallocation-abandoned blocks the measurement is about. Measured: forwarding here
    /// reported zero 20-byte dirty blocks for a defect whose pointers `CHANGELOG.md`
    /// records. Allocating, copying and releasing through `self.dealloc` keeps every
    /// abandoned block observable, and matches what a zeroizing allocator does, so the two
    /// halves stay comparable.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let new_ptr = unsafe { self.alloc(new_layout) };
        if !new_ptr.is_null() {
            let copy = core::cmp::min(layout.size(), new_size);
            unsafe { core::ptr::copy_nonoverlapping(ptr, new_ptr, copy) };
            unsafe { self.dealloc(ptr, layout) };
        }
        new_ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) {
            let len = layout.size();
            let mut nonzero = 0usize;
            // Volatile: this is a measurement of a block the program has finished with,
            // and a non-volatile read would be entitled to disappear.
            for i in 0..len {
                if unsafe { core::ptr::read_volatile(ptr.add(i)) } != 0 {
                    nonzero += 1;
                }
            }
            BLOCKS.fetch_add(1, Ordering::Relaxed);
            if nonzero > 0 {
                DIRTY_BLOCKS.fetch_add(1, Ordering::Relaxed);
                DIRTY_BYTES.fetch_add(nonzero, Ordering::Relaxed);
                LARGEST_DIRTY.fetch_max(len, Ordering::Relaxed);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Spy = Spy;

/// Run `f` counting, report, and return `(blocks, dirty_blocks, dirty_bytes)`.
///
/// `--test-threads=1` is required and documented at the top of this file: the counters are
/// process-wide, so a concurrent test would be measured into them.
fn measure(label: &str, f: impl FnOnce()) -> (usize, usize, usize) {
    for c in [&BLOCKS, &DIRTY_BLOCKS, &DIRTY_BYTES, &LARGEST_DIRTY] {
        c.store(0, Ordering::Relaxed);
    }
    ARMED.store(true, Ordering::SeqCst);
    f();
    ARMED.store(false, Ordering::SeqCst);

    let (blocks, dirty, bytes, largest) = (
        BLOCKS.load(Ordering::Relaxed),
        DIRTY_BLOCKS.load(Ordering::Relaxed),
        DIRTY_BYTES.load(Ordering::Relaxed),
        LARGEST_DIRTY.load(Ordering::Relaxed),
    );
    println!(
        "{label}: released {blocks} blocks, {dirty} carrying non-zero bytes, \
         {bytes} non-zero bytes total, largest dirty block {largest} B"
    );
    (blocks, dirty, bytes)
}

/// The instrument works: something was released, and some of it was not already zero.
fn assert_instrument_live(what: &str, blocks: usize, dirty: usize, bytes: usize) {
    assert!(
        blocks > 0,
        "{what}: no block was released -- the workload did not run"
    );
    assert!(
        dirty > 0 && bytes > 0,
        "{what}: {blocks} blocks released and none carried a non-zero byte. That is not a \
         clean result, it means this probe is no longer observing what it believes it is."
    );
}

/// `encrypt_ooxml_standard` -- the path whose pre-fix form abandoned `SHA1(verifier)`.
#[test]
// Unconditional: both fixtures below are in Cargo.toml's `include` allowlist, so they are
// always present and `include_bytes!` would be a compile error rather than a skip if they
// were not. The ignore is about this being a measurement, not about the corpus.
#[ignore = "a measurement, not a gate -- run with --ignored --nocapture --test-threads=1"]
fn measure_standard_encrypt_residue() {
    let package = include_bytes!("fixtures/plain.docx");
    let (blocks, dirty, bytes) = measure("standard encrypt", || {
        let sealed = msoffice_crypto::encrypt_ooxml_standard(package, "testpass")
            .expect("encrypt_ooxml_standard");
        std::hint::black_box(&sealed);
    });
    assert_instrument_live("standard encrypt", blocks, dirty, bytes);
}

/// `decrypt_ooxml` -- ~100 000 `spin_hash` intermediates, the heaviest allocation workload
/// in the crate and the one whose released bytes really are key-derived.
#[test]
// Unconditional: both fixtures below are in Cargo.toml's `include` allowlist, so they are
// always present and `include_bytes!` would be a compile error rather than a skip if they
// were not. The ignore is about this being a measurement, not about the corpus.
#[ignore = "a measurement, not a gate -- run with --ignored --nocapture --test-threads=1"]
fn measure_agile_decrypt_residue() {
    let data = include_bytes!("fixtures/agile_encrypted.docx");
    let (blocks, dirty, bytes) = measure("agile decrypt", || {
        let plain = msoffice_crypto::decrypt_ooxml(data, "testpass").expect("decrypt_ooxml");
        std::hint::black_box(&plain);
    });
    assert_instrument_live("agile decrypt", blocks, dirty, bytes);
}
