//! CONTROL 2: the wrapper's composition with **no wipe**, so a clean subject means something.
//!
//! `NoWipe<Spy>` has `ZeroAlloc`'s shape and its `realloc` route and does not wipe. It
//! therefore differs from `heap_residue_wiped.rs` by exactly one thing, and it is what
//! distinguishes "the wipe worked" from "the probe was not looking".
//!
//! A spy reading the wrong memory, or reading after something else had cleared it, would
//! report clean under the wiped build **and** clean here. It must report dirty here.
//!
//! Contributed by the author of `secure-gate-zalloc` while independently reproducing this
//! measurement: a two-configuration version of this harness cannot tell a working wipe from
//! a broken instrument, and this is the third leg that can.
#![cfg(feature = "crypto-ops")]

mod residue_support;

use residue_support::{measure, workload_agile_decrypt, workload_standard_encrypt, NoWipe, Spy};

#[global_allocator]
static ALLOC: NoWipe<Spy> = NoWipe(Spy);

#[test]
fn the_composed_position_still_sees_residue_when_nothing_wipes() {
    let (blocks, dirty, bytes) = measure("nowipe / standard encrypt", workload_standard_encrypt);
    assert!(blocks > 0, "no block released -- the workload did not run");
    assert!(
        dirty > 0 && bytes > 0,
        "composed under a non-wiping wrapper, {blocks} blocks released and none was dirty. \
         The probe is not observing the position it claims to, so a clean result from \
         heap_residue_wiped.rs proves nothing."
    );
}

#[test]
fn the_composed_position_sees_agile_residue_too() {
    let (blocks, dirty, bytes) = measure("nowipe / agile decrypt", workload_agile_decrypt);
    assert!(blocks > 0, "no block released -- the workload did not run");
    assert!(
        dirty > 0 && bytes > 0,
        "{blocks} blocks released, none dirty -- probe broken"
    );
}
