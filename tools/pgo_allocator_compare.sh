#!/usr/bin/env bash
# Does a zeroizing allocator's wipe survive PGO with fat LTO?
#
# This is the question `tests/heap_residue*.rs` cannot answer and must not be read as
# answering. Those tests observe each block through a volatile read, and that read is
# exactly what stops a compiler removing the store it is observing -- so a runtime probe of
# that shape is not merely silent about dead-store elimination, it is structurally
# incapable of detecting it. This script answers it the only way that works: build the same
# program under `-Cprofile-use` with `lto = "fat"`, then try to read a freed block back.
#
# Linux only, and glibc specifically: the readout depends on the allocator handing the
# just-freed block straight back, which glibc does and the Windows heap does not. On Windows
# the question is unanswerable for a different reason -- `HeapFree` is not a deallocation
# function LLVM recognises, so a fill before it is never proven dead and never eliminated,
# whether or not the wipe mechanism is sound.
#
#   bash tools/pgo_allocator_compare.sh
#
# Needs `llvm-profdata` (rustup component add llvm-tools) and network access for crates.io.
#
# ---------------------------------------------------------------------------------------
# Measured 2026-09-18, rustc 1.96.1, WSL2 Ubuntu 24.04, glibc 2.39, x86-64.
# Pattern bytes recovered out of 16 from a freed block; `same=true` in every row, so the
# same block really did come back.
#
#     configuration                                     64 B     4096 B
#     none (no allocator)                              16/16     16/16     <- probe verified
#     fn-pointer wipe, no volatile read of the ptr     16/16     16/16     <- ELIMINATED
#     zeroizing-alloc 0.1.1                             0/16      0/16
#
# The middle row is the finding worth keeping: a function-pointer wipe that loads its
# callee through `read_volatile` and marks it `#[used]` is *still* completely eliminated by
# PGO + fat LTO. As recoverable as having no allocator at all.
#
# `zeroizing-alloc` survives because it carries a second barrier the middle row omits -- a
# volatile read of the block pointer itself in `dealloc`, whose comment in that crate says
# it exists "to prevent optimizers (such as PGO) from observing that there is a dead store".
# That single line is the whole difference between 16/16 and 0/16.
#
# The `none` row is not decoration. A clean result from a probe nobody has shown can see
# residue is worth nothing, and this arrangement has produced exactly that mistake before.
# ---------------------------------------------------------------------------------------
set -u

CARGO=${CARGO:-cargo}
RUSTC=${RUSTC:-rustc}
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

"$RUSTC" -vV | grep -q '^host: x86_64-unknown-linux-gnu' || {
    echo "refusing: not a Linux toolchain -- this measurement is meaningless elsewhere"
    "$RUSTC" -vV | grep '^host:'
    exit 1
}

PROFDATA=$(find "$("$RUSTC" --print sysroot)" -name llvm-profdata -type f 2>/dev/null | head -1)
[ -n "$PROFDATA" ] || { echo "FATAL: llvm-profdata not found (rustup component add llvm-tools)"; exit 1; }
echo "toolchain: $("$RUSTC" -vV | grep '^release')"
echo

# The wipe shape that loses: callee behind a volatile-loaded `#[used]` static, but no
# volatile read of the block pointer. Its own crate, so the callee crosses a crate boundary
# the way a real dependency's would.
mkdir -p "$ROOT/_fnptr/src"
cat > "$ROOT/_fnptr/Cargo.toml" <<'EOF'
[package]
name = "fnptr_wipe"
version = "0.0.0"
edition = "2021"
EOF
cat > "$ROOT/_fnptr/src/lib.rs" <<'EOF'
#![no_std]
use core::alloc::{GlobalAlloc, Layout};
pub struct Wrap<A: GlobalAlloc>(pub A);
unsafe fn clear_bytes(ptr: *mut u8, len: usize) { ptr.write_bytes(0, len); }
#[used]
static WIPER: unsafe fn(*mut u8, usize) = clear_bytes;
#[inline]
unsafe fn zero(ptr: *mut u8, len: usize) {
    let wipe = core::ptr::read_volatile(&raw const WIPER);
    wipe(ptr, len);
}
unsafe impl<A: GlobalAlloc> GlobalAlloc for Wrap<A> {
    #[inline] unsafe fn alloc(&self, l: Layout) -> *mut u8 { self.0.alloc(l) }
    #[inline] unsafe fn dealloc(&self, p: *mut u8, l: Layout) { zero(p, l.size()); self.0.dealloc(p, l) }
    #[inline] unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 { self.0.alloc_zeroed(l) }
}
EOF

probe_main() {
cat <<EOF
use std::alloc::{alloc, dealloc, Layout};
$1
#[inline(never)]
fn churn_small(pat: u8) { let v = vec![pat; 64]; std::hint::black_box(&v); }
#[inline(never)]
fn churn_bulk(pat: u8) { let v = vec![pat; 4096]; std::hint::black_box(&v); }

/// Plant a pattern, release the block, take the same size class back, and count pattern
/// bytes among bytes 16..32 of what returned. The iteration count is what makes the
/// deallocation site hot enough for PGO to act on.
#[inline(never)]
fn recover(size: usize, iters: usize) -> (u32, bool) {
    let layout = Layout::from_size_align(size, 16).unwrap();
    let mut last = (0u32, false);
    for _ in 0..iters {
        unsafe {
            let p = alloc(layout);
            assert!(!p.is_null());
            core::ptr::write_bytes(p, 0xA5u8, size);
            std::hint::black_box(p);
            dealloc(p, layout);
            let q = alloc(layout);
            assert!(!q.is_null());
            let a = (q.add(16) as *const u64).read_volatile();
            let b = (q.add(24) as *const u64).read_volatile();
            let hits = a.to_ne_bytes().iter().chain(b.to_ne_bytes().iter())
                .filter(|&&x| x == 0xA5).count() as u32;
            last = (hits, q == p);
            core::ptr::write_bytes(q, 0u8, size);
            dealloc(q, layout);
        }
    }
    last
}

fn main() {
    for _ in 0..100_000 { churn_small(0xA5); churn_bulk(0x5A); }
    let iters = std::hint::black_box(300_000usize);
    for size in [64usize, 4096] {
        let (hits, same) = recover(size, iters);
        println!("  size={size:<5} recovered={hits}/16  same_block={same}");
    }
}
EOF
}

measure() {
    local name="$1" dep="$2" decl="$3"
    local d="$ROOT/run_$name"
    mkdir -p "$d/src"
    printf '[package]\nname = "p_%s"\nversion = "0.0.0"\nedition = "2021"\n\n[dependencies]\n%s\n\n[profile.release]\nlto = "fat"\ncodegen-units = 1\n' \
        "$name" "$dep" > "$d/Cargo.toml"
    probe_main "$decl" > "$d/src/main.rs"

    local prof="$d/prof"; mkdir -p "$prof"
    RUSTFLAGS="-Cprofile-generate=$prof" "$CARGO" build --release \
        --manifest-path "$d/Cargo.toml" --target-dir "$d/t1" >/dev/null 2>&1 \
        || { echo "$name: instrumented build FAILED"; return; }
    "$d/t1/release/p_$name" >/dev/null 2>&1
    "$PROFDATA" merge -o "$d/merged.profdata" "$prof" >/dev/null 2>&1 \
        || { echo "$name: profdata merge FAILED"; return; }
    RUSTFLAGS="-Cprofile-use=$d/merged.profdata" "$CARGO" build --release \
        --manifest-path "$d/Cargo.toml" --target-dir "$d/t2" >/dev/null 2>&1 \
        || { echo "$name: optimized build FAILED"; return; }
    echo "$name:"
    "$d/t2/release/p_$name" 2>&1
}

echo "### PGO (-Cprofile-use) + fat LTO + codegen-units=1"
echo
measure none "" ""
measure fnptr_no_ptr_barrier \
    "fnptr_wipe = { path = \"$ROOT/_fnptr\" }" \
    'use fnptr_wipe::Wrap;
#[global_allocator] static A: Wrap<std::alloc::System> = Wrap(std::alloc::System);'
measure zeroizing_alloc \
    'zeroizing-alloc = "0.1.1"' \
    'use zeroizing_alloc::ZeroAlloc;
#[global_allocator] static A: ZeroAlloc<std::alloc::System> = ZeroAlloc(std::alloc::System);'

echo
echo "`none` must recover 16/16 or the probe is not observing anything and no other row means anything."
