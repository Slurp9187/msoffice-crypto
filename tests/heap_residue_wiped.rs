//! SUBJECT: nothing this crate abandons survives a zeroizing global allocator.
//!
//! The same probe as `heap_residue.rs`, composed under `zeroizing-alloc`. `ZeroAlloc::dealloc`
//! wipes and then forwards, so the spy beneath it observes each block after the wipe and
//! before the system allocator is told about it.
//!
//! **This asserts zero, and that is only meaningful because of the two controls.**
//! `heap_residue.rs` establishes the residue exists; `heap_residue_nowipe.rs` establishes
//! the probe sees it in *this* position. Read all three or none.
//!
//! # What this does not test
//!
//! Whether the wipe survives an optimizer. The volatile read that makes the measurement
//! possible is exactly what stops a compiler removing the store it observes, and
//! `cargo test` is opt-level 0 besides. That question was answered separately, under PGO
//! and fat LTO, and the result is recorded in `docs/design/heap-residue.md` — 0 of 16
//! pattern bytes recoverable from a freed block, against 16 of 16 with no allocator.
#![cfg(feature = "crypto-ops")]

mod residue_support;

use residue_support::{measure, workload_agile_decrypt, workload_standard_encrypt, Spy};
use zeroizing_alloc::ZeroAlloc;

#[global_allocator]
static ALLOC: ZeroAlloc<Spy> = ZeroAlloc(Spy);

#[test]
fn standard_encrypt_abandons_nothing_non_zero() {
    let (blocks, dirty, bytes) = measure("wiped / standard encrypt", workload_standard_encrypt);
    assert!(blocks > 0, "no block released -- the workload did not run");
    assert_eq!(
        (dirty, bytes),
        (0, 0),
        "{dirty} of {blocks} released blocks still carried {bytes} non-zero bytes"
    );
}

#[test]
fn agile_decrypt_abandons_nothing_non_zero() {
    let (blocks, dirty, bytes) = measure("wiped / agile decrypt", workload_agile_decrypt);
    assert!(blocks > 0, "no block released -- the workload did not run");
    assert_eq!(
        (dirty, bytes),
        (0, 0),
        "{dirty} of {blocks} released blocks still carried {bytes} non-zero bytes"
    );
}
