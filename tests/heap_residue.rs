//! CONTROL: how much non-zero memory this crate abandons with no wiping allocator.
//!
//! One of three binaries that differ only in their `#[global_allocator]`:
//!
//! | binary | allocator | asserts |
//! |---|---|---|
//! | `heap_residue.rs` | bare `Spy` | residue **is** released |
//! | `heap_residue_nowipe.rs` | `NoWipe<Spy>` | the probe sees it *in the composed position* |
//! | `heap_residue_wiped.rs` | `ZeroAlloc<Spy>` | none of it survives |
//!
//! This one establishes that there is something to wipe. Without it the subject's clean
//! result is equally consistent with the wipe working, the blocks never being released, or
//! the workload never running — which is why it asserts rather than reports.
//!
//! What the numbers are **not**: `dirty_bytes` counts every non-zero byte in every released
//! block, and most of the standard-encrypt figure is document data — the package, the
//! ciphertext, ZIP and CFB buffers. It is not a secret-exposure number. The agile figure is
//! different in kind: ~100 000 of its blocks are `spin_hash`'s per-round intermediates,
//! which are key-derived, and which the secure-gate skill names as a case no wrapper can
//! economically reach. See `docs/design/heap-residue.md`.
#![cfg(feature = "crypto-ops")]

mod residue_support;

use residue_support::{measure, workload_agile_decrypt, workload_standard_encrypt, Spy};

#[global_allocator]
static ALLOC: Spy = Spy;

#[test]
fn standard_encrypt_abandons_non_zero_blocks() {
    let (blocks, dirty, bytes) = measure("control / standard encrypt", workload_standard_encrypt);
    assert!(blocks > 0, "no block released -- the workload did not run");
    assert!(
        dirty > 0 && bytes > 0,
        "{blocks} blocks released and none carried a non-zero byte: this probe is no longer \
         observing what it believes it is, so the wiped build's result would be UNTESTED"
    );
}

#[test]
fn agile_decrypt_abandons_non_zero_blocks() {
    let (blocks, dirty, bytes) = measure("control / agile decrypt", workload_agile_decrypt);
    assert!(blocks > 0, "no block released -- the workload did not run");
    assert!(
        dirty > 0 && bytes > 0,
        "{blocks} blocks released, none dirty -- probe broken"
    );
}
