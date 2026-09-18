# Heap residue: what a wrapper cannot reach, and what an allocator can

This crate wraps key material in `secure-gate` types so it zeroizes on drop. That covers
what the wrapper *holds*. It does not cover what a `Vec` **abandons**, and this document
is about the difference, because the gap is invisible from inside the library and this
crate has walked into it twice.

## The defect class

A `Vec` that grows past its capacity allocates a new block, copies, and frees the old one.
**The freed block is not wiped.** If it held key-derived bytes, a copy of them is now on
the heap and nothing will ever zeroize it — including the wrapper, which by then is
holding the *new* block and is perfectly correct about it.

The property that makes this hard to notice: from outside, everything looks right. The
value is wrapped, it zeroizes on drop, and an audit asking "is this wrapped?" gets a yes.
The gap is *where* the wrapping happens relative to the growth.

### The two instances in this repository

Both are recorded in `CHANGELOG.md` under v0.1.0-rc.2.

**`standard_encrypt::generate`** built `SHA1(verifier)` with `to_vec()` — capacity exactly
20 — then `resize`d to the 32-byte blob. 32 does not fit in 20, so the `Vec` reallocated
and freed the block holding the digest unwiped. Measured at the time, and the only such
figure in the repository:

```
before resize: ptr=0x2d5556d0600 len=20 cap=20
after  resize: ptr=0x2d5556ce670 len=32 cap=40
```

It was in the **default `crypto-ops` build**.

**`rc4_cryptoapi`**'s 40-bit key had the same shape — `extend_from_slice` then `resize`
inside `Dynamic::new_with`, which at the time handed the closure an empty buffer to grow.

### Why it stopped being writable

`secure-gate` 0.9.0-rc.12 changed `Dynamic::new_with` to take a length and hand the closure
a pre-zeroed `&mut [u8]` of exactly that size. There is no growable buffer to reallocate,
so the discipline became the type's rather than this crate's. That closes the *wrapped*
case. It does not close the general one: any plain `Vec` holding secret-derived bytes,
anywhere in the crate or in a dependency, can still abandon a block.

## What a zeroizing global allocator closes, and what it does not

A zero-on-deallocate allocator wipes every block before releasing it, so the abandoned
block is clean whoever abandoned it and whether or not they knew.

**It wipes every heap block that actually reaches the allocator** — without the library's
cooperation, and regardless of what the type was. That is precisely the part a library
provably cannot reach from the inside, and it extends to third-party buffers whose authors
have never heard of `zeroize`.

**"Every block that reaches the allocator" is not the same as "every allocation in the
source", and the measurement below demonstrates the difference.** `GlobalAlloc`'s contract
says you may not rely on an allocation actually happening: the optimizer may elide it, or
move it to the stack, and then the allocator never runs for it. At `--release` the
standard-encrypt path releases **405 blocks where the unoptimized build releases 521** —
116 allocations did not happen. Whatever would have lived in them went somewhere the
allocator does not see, and nothing reports that. The wipe did not fail; it was never
reached. So whether a given `Vec` is covered is a property of the **build**, not of the
source.

**What it never covers is memory that never reaches it**, and the deciding question is
*where the bytes live*, not what the type implements:

- **Stack-spilled state.** `sha2::compress512` spills its message schedule, and `W[0..16]`
  of that schedule *is* the message block verbatim — raw password bytes, on the stack.
- **Anything held by value rather than behind a pointer**, such as `hmac`'s opad/ipad. A
  fixed-size array lives on the stack and never passes through the allocator. Note the
  reason carefully: **not** because it lacks a `Drop` impl — the allocator does not care
  about `Drop` at all. Put that same state behind a `Box` and it would be wiped on release.
- **Hasher buffers** holding raw password bytes until `finalize`, for the same reason.
- **Memory that is never freed** — `mem::forget`, `Box::leak`, or a process exiting without
  unwinding.
- **Live allocations**, which are not wiped while they are live; the allocator says nothing
  about how long a secret sits resident. Swap, core dumps, DMA and cache are outside its
  claims entirely.

(The first three are recorded in `.claude/skills/msoffice-crypto-secure-gate/SKILL.md`
§ "Residual the wrapper cannot reach".)

So an allocator **narrows** this problem. It does not retire the reserve-exact discipline,
and a future reader who takes it as permission to stop caring where a secret is built has
read this document backwards — 405 against 521 is the number to re-read before deciding
otherwise.

## Measured: `secure-gate-zalloc` against this crate

Run 2026-09-18 in WSL2 (Ubuntu 24.04, glibc 2.39, kernel 6.18 WSL2), rustc **1.96.1**,
against `secure-gate-zalloc` at `2ceb92c`. `standard_encrypt::generate` was reverted to the
defective `to_vec()` + `resize` form so the measurement was taken against the real defect
rather than a synthetic one.

A spy allocator composed *underneath* the wrapper — `ZeroizingAlloc<Spy>` — counted every
block released during the workload and how many carried a non-zero byte at release.

| workload | build | blocks released | dirty | non-zero bytes | 20-byte dirty |
|---|---|---|---|---|---|
| `decrypt_ooxml` (agile) | control | 100,251 | 100,238 | 6,634,209 | 4 |
| `decrypt_ooxml` (agile) | allocator | 100,251 | **0** | **0** | **0** |
| `encrypt_ooxml_standard` | control | 521 | 516 | 298,383 | 23 |
| `encrypt_ooxml_standard` | allocator | 521 | **0** | **0** | **0** |

**The released-block counts are identical between control and subject**, which is what
makes this a measurement rather than an anecdote: the allocator did not change what was
allocated, and the two runs did the same work. One variable moved.

The same probes on Windows 11 / x86-64, for portability rather than mechanism (see below):

| workload | build | blocks released | dirty | non-zero bytes | 20-byte dirty |
|---|---|---|---|---|---|
| `decrypt_ooxml` (agile) | control | 100,251 | 100,238 | 6,635,255 | 4 |
| `decrypt_ooxml` (agile) | allocator | 100,251 | **0** | **0** | **0** |
| `encrypt_ooxml_standard` | control | 520 | 514 | 295,797 | 22 |
| `encrypt_ooxml_standard` | allocator | 520 | **0** | **0** | **0** |

The small differences against Linux — 520 blocks rather than 521, 22 twenty-byte blocks
rather than 23 — are the randomised verifier, not a platform difference in behaviour.

Repeated at `--release` (opt-level 3) on Linux, because the figures above were taken at
cargo test's default opt-level 0:

| workload | build | blocks released | dirty | non-zero bytes | 20-byte dirty |
|---|---|---|---|---|---|
| `decrypt_ooxml` (agile) | control | 100,251 | 100,238 | 6,634,209 | 4 |
| `decrypt_ooxml` (agile) | allocator | 100,251 | **0** | **0** | **0** |
| `encrypt_ooxml_standard` | control | 405 | 400 | 297,030 | 12 |
| `encrypt_ooxml_standard` | allocator | 405 | **0** | **0** | **0** |

`encrypt_ooxml_standard` falls from 521 blocks to 405, and its 20-byte blocks from 23 to
12, because the optimizer removes some allocations entirely. The ones that survive are
still released clean. Note what this does and does not add: the *workload* is optimized
here, but the wipe itself is still observed by the probe, so this is not evidence about
dead-store elimination either — see below.

`20-byte dirty` is the reverted defect itself — 23 abandoned `SHA1(verifier)` blocks per
`encrypt_ooxml_standard`. The 100,238 dirty blocks in the agile control are `spin_hash`'s
abandoned intermediates, ~100,000 per decrypt, which the secure-gate skill names as a case
a wrapper cannot economically reach.

### The control was wrong first, in the direction that flattered the allocator

Worth recording because the next person composing a spy will hit it.

The spy's `realloc` initially forwarded to `System.realloc`. libc's `realloc` releases the
old block **inside** the C allocator — it never passes through the spy's `dealloc`. So the
control could not observe realloc-abandoned blocks at all, while the subject could, because
`ZeroizingAlloc::realloc` never forwards: it allocates, copies, and releases the old block
through its own `dealloc`.

The tell was `20-byte dirty 0` in the control, when the changelog says that block is
certainly there. Before the fix, the pair would have read as a clean pass **on a block the
control never looked at**. The cure is to mirror the wrapper's realloc in the spy, so the
wipe is the only difference between the two builds.

### What this probe does *not* test, which is the allocator's central claim

The allocator's own documents are about a narrower and harder property: that the wipe
**survives optimization** — that PGO and LTO do not delete a fill whose result nothing
reads. That is what its IR-shape tests and its PGO recovery test exist to establish.

This probe does not test that, and cannot, for two reasons:

1. The spy performs a **volatile read of the block immediately after the wipe**. That makes
   the wipe observed, so no compiler would be entitled to remove it. The instrument that
   makes the measurement possible is the same thing that removes the question.
2. `cargo test` builds at **opt-level 0** by default, where dead-store elimination does not
   happen at all.

So what is established here is that `ZeroizingAlloc` **functionally** clears blocks before
releasing them, across a real cryptographic workload. Whether that clearing survives an
aggressive optimizer is a different claim, tested elsewhere, and nothing in this document
should be read as evidence for it.

### Why this cannot be measured on Windows

`HeapFree` is not a deallocation function LLVM recognises, so a fill before it is never
proven dead and never eliminated — whether or not the wipe mechanism is sound. A green
Windows result is therefore consistent with the mechanism working *and* with it not
working, and cannot distinguish them. Windows' heap also does not reliably hand the
just-freed block straight back, which a residue readout depends on.

Windows is a portability check. The mechanism is observable on Linux/glibc, and that is
where the number above was taken.

### Is reading before `System::dealloc` weaker than reading after free?

No, and it is stricter in one respect. Raised with the allocator's author and resolved:
nothing can write the secret back between the spy's read and `System::dealloc`, so "clean
when handed to the system allocator" implies "clean once the system allocator has it",
minus the allocator's own metadata.

`secure-gate-zalloc`'s own `PinSpy` reads at the same point. Its *additional* heap readout
— allocate the same size class back and inspect what returns — is the attacker's-eye view,
observing through the interface an adversary would actually use. It is rhetorically
stronger and materially weaker: it must skip the first 64 bytes, because a freed glibc
chunk carries free-list links there, so it cannot see residue confined to the prefix. The
probe used here skips nothing.

## Environment traps, for whoever repeats this

All four cost real time and every one produces a *confident wrong answer* rather than an
error, which is the failure shape worth writing down.

- **`pwd` inside `wsl -- bash -lc` command substitution reports a stale inherited
  `$PWD`.** It reported the Windows working tree while the command was operating on the
  WSL clone. Use `git -C <absolute path>` and do not trust `pwd` across the boundary.
- **A Git Bash `cd` leaks into the next `wsl.exe` invocation's working directory**, so a
  later WSL command silently runs somewhere else.
- **The toolchain differs inside and outside a checkout.** `rust-toolchain.toml` applies
  only when the working directory is inside the repository, so a script that builds from
  elsewhere silently uses a different compiler — 1.85.1 against 1.96.1 here. Assert it:
  `rustc -vV | grep -q '^host: x86_64-unknown-linux-gnu'`, and check `release:` too if the
  version matters to the claim.
- **A Windows `cargo.exe` on the WSL `PATH` is *not* reachable as bare `cargo`**, because
  Linux does not append `.exe`. This one is a trap in the other direction: it is widely
  assumed to be a silent-corruption risk and it is not — it fails loudly.

## Reading the result honestly

What it shows: at the moment the system allocator takes a block back, that block is clean,
across ~100,000 blocks of real key-derivation work, including a real defect this crate
shipped and fixed.

What it does not show: anything about the stack, anything about `hmac`, and anything about
Windows. It is the heap half, on one platform, on one toolchain — and a newer one than the
allocator's own evidence, which makes it a harder test rather than a reproduction of it.
