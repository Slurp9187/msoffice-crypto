//! The spy allocator and workloads shared by the three residue tests, so the subject and
//! its controls cannot drift apart.
//!
//! `heap_residue.rs`, `heap_residue_nowipe.rs` and `heap_residue_wiped.rs` differ from each
//! other in exactly one line — the `#[global_allocator]` — and everything measured lives
//! here. A `#[global_allocator]` is process-wide, so each is its own binary; Cargo builds
//! one per `tests/*.rs`, and a subdirectory like this one is not built as a test.
//!
//! # Why the spy reads from offset 0
//!
//! Composed as `ZeroAlloc<Spy>`, the order is
//! `ZeroAlloc::dealloc` → wipe → `Spy::dealloc` → **read here** → `System::dealloc`. The
//! system allocator has not been told about the block yet, so nothing has written free-list
//! links into its first bytes and the whole block is honest to read. A probe that inspects
//! a block *after* free must skip a prefix — two words in a small glibc bin, four once it
//! is sorted into a large one — and a skipped prefix is where residue could hide.
//!
//! # The spy must not allocate
//!
//! Anything allocating inside `dealloc` re-enters the allocator. Counting into atomics
//! allocates nothing.

#![allow(unreachable_pub, dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Count only while the workload runs, or the harness's own allocations dominate.
pub static ARMED: AtomicBool = AtomicBool::new(false);
pub static BLOCKS: AtomicUsize = AtomicUsize::new(0);
pub static DIRTY_BLOCKS: AtomicUsize = AtomicUsize::new(0);
pub static DIRTY_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Observes each block at the moment it is released, after any wrapper above has had it.
pub struct Spy;

// SAFETY: every method forwards to `System` with the layout it was given; the counting path
// reads only within `layout.size()` of a block the caller is releasing, and allocates nothing.
unsafe impl GlobalAlloc for Spy {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    /// Deliberately **not** `System.realloc`.
    ///
    /// libc's `realloc` releases the old block inside the C allocator, so it never reaches
    /// `dealloc` and this probe cannot see it — which hides precisely the
    /// reallocation-abandoned blocks the measurement is about. Measured: forwarding here
    /// reported zero dirty 20-byte blocks for a defect whose pointers `CHANGELOG.md`
    /// records under v0.1.0-rc.2.
    ///
    /// The general rule, which cost an afternoon to learn: **a control must release memory
    /// by the same route as the subject.** `zeroizing-alloc` does not implement `realloc`
    /// at all, taking `GlobalAlloc`'s default — allocate, copy, release through `dealloc` —
    /// so mirroring that here keeps the wipe as the only difference between the binaries.
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
            // Volatile: this reads a block the program has finished with, and a plain read
            // would be entitled to disappear.
            for i in 0..len {
                if unsafe { core::ptr::read_volatile(ptr.add(i)) } != 0 {
                    nonzero += 1;
                }
            }
            BLOCKS.fetch_add(1, Ordering::Relaxed);
            if nonzero > 0 {
                DIRTY_BLOCKS.fetch_add(1, Ordering::Relaxed);
                DIRTY_BYTES.fetch_add(nonzero, Ordering::Relaxed);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// A wrapper with `zeroizing-alloc`'s composition and **no wipe**.
///
/// The control that turns the subject's `0 dirty` from a silence into a measurement.
/// `blocks > 0` shows the counter ran; it does not show the spy reads the bytes it claims
/// to *in the position it claims to*. A spy observing the wrong memory would report clean
/// under the subject and nothing would contradict it — but it would also report clean here,
/// and this must report dirty. Contributed by the author of `secure-gate-zalloc`, who
/// pointed out that a two-configuration version of this harness cannot tell a working wipe
/// from a broken probe.
pub struct NoWipe<A: GlobalAlloc>(pub A);

// SAFETY: a pure forwarder; every method passes the caller's arguments through unchanged.
unsafe impl<A: GlobalAlloc> GlobalAlloc for NoWipe<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { self.0.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { self.0.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.0.dealloc(ptr, layout) }
    }
    // `realloc` deliberately left to the `GlobalAlloc` default -- allocate, copy, release
    // through `dealloc` -- which is exactly what `zeroizing-alloc` relies on.
}

/// Run `f` with the spy counting. Returns `(blocks, dirty_blocks, dirty_bytes)`.
pub fn measure(label: &str, f: impl FnOnce()) -> (usize, usize, usize) {
    for c in [&BLOCKS, &DIRTY_BLOCKS, &DIRTY_BYTES] {
        c.store(0, Ordering::Relaxed);
    }
    ARMED.store(true, Ordering::SeqCst);
    f();
    ARMED.store(false, Ordering::SeqCst);

    let out = (
        BLOCKS.load(Ordering::Relaxed),
        DIRTY_BLOCKS.load(Ordering::Relaxed),
        DIRTY_BYTES.load(Ordering::Relaxed),
    );
    println!(
        "{label}: released {} blocks, {} carrying non-zero bytes, {} non-zero bytes",
        out.0, out.1, out.2
    );
    out
}

/// `encrypt_ooxml_standard` — the path whose pre-fix form abandoned `SHA1(verifier)`.
pub fn workload_standard_encrypt() {
    let package = include_bytes!("../fixtures/plain.docx");
    let sealed = msoffice_crypto::encrypt_ooxml_standard(package, "testpass")
        .expect("encrypt_ooxml_standard");
    std::hint::black_box(&sealed);
}

/// `decrypt_ooxml` — `spin_hash` runs ~100 000 rounds, each allocating and dropping a fresh
/// intermediate. The heaviest allocation workload here, and the one whose released bytes
/// really are key-derived.
pub fn workload_agile_decrypt() {
    let data = include_bytes!("../fixtures/agile_encrypted.docx");
    let plain = msoffice_crypto::decrypt_ooxml(data, "testpass").expect("decrypt_ooxml");
    std::hint::black_box(&plain);
}
