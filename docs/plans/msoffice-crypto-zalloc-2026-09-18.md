<!-- Copied from the working plan on 2026-09-18, after execution. -->

> **Outcome: executed, and it passed.** The measurements and the caveats live in
> [`docs/design/heap-residue.md`](../design/heap-residue.md); this file is the design that
> produced them and is not updated to match. Two things it did not anticipate are worth
> knowing before reading it: the naive control was wrong in the direction that flattered
> the allocator (a spy forwarding to `System.realloc` cannot see realloc-abandoned blocks
> at all), and the probe cannot test the wipe's survival under optimization, because the
> volatile read that makes it observable is what would stop an optimizer removing it.
>
> The experimental code was never merged and no longer exists: a throwaway WSL clone with
> `standard_encrypt::generate` reverted to its pre-fix form.
>
> **The one test that did land has since moved out.** `tests/heap_residue.rs` reached `main`
> and was removed again: every assertion in it was a property of the allocator rather than
> of this crate, and it went to `secure-gate` along with the rest of the harness and the raw
> captures. The design document records where.

---

# Testing `secure-gate-zalloc` against msoffice-crypto

## Context

The ask was "secure-gate-zalloc is brand new and I haven't figured out how to use it or
test it yet; would you test it here?" Two corrections shape everything below.

**1. The crate is not new or unproven.** 74 commits, 18 merged PRs, ~3,400 lines of tests
across 12 files, two adversarial review rounds, 25 applied mutations with every
non-equivalent one caught, IR-level checks on eight architectures, Miri, and a successful
`cargo package`. The build agent's own framing: *"try to break something that already
works"*. So this is not a bring-up exercise.

**2. It is unpublished on purpose, and this workload is the gate in front of publication.**
The maintainer wants it tested before `cargo publish`. A defect found here gets fixed
before anyone can depend on it.

### What is already proven — do not rebuild it

`tests/secure_gate_shape.rs` already grows a `Dynamic<Vec<u8>>` through `with_secret_mut`
with a `PinSpy` between `ZeroizingAlloc` and `System`, and pairs it with a no-allocator
control that must find all 4032 pattern bytes intact. The "does it wipe an abandoned
buffer" question is answered. Read that file first; it has the pin-one-pointer spy, the
control, and the readout offsets already solved.

### What is genuinely missing

- **No third-party workload.** Every existing test is a synthetic probe or that one
  `secure-gate` integration. No real cryptographic library has run under it.
- **No demonstration against a real, dated defect.** The build agent: *"reverting the fix
  and showing the residue gone anyway is precisely the demonstration this crate has
  lacked."*

### Why msoffice-crypto, specifically

`CHANGELOG.md:342-371` records a defect with the only measured pointer pair in the repo:

```
before resize: ptr=0x2d5556d0600 len=20 cap=20
after  resize: ptr=0x2d5556ce670 len=32 cap=40
```

`standard_encrypt::generate` built `SHA1(verifier)` with `to_vec()` (capacity exactly 20)
then `resize`d to 32. The `Vec` reallocated and freed the block holding the digest
**unwiped**. It is in the **default `crypto-ops` build**, the fix is one line, and
reverting it recreates the defect exactly.

Two properties make it the right specimen. It is a **plain `Vec` realloc in ordinary
library code**, not a `secure-gate` wrapper growth — a different shape from what
`secure_gate_shape.rs` covers. And at **20 → 32 bytes it sits below the 512-byte
`BULK_THRESHOLD`**, so it takes the word-at-a-time volatile path, whose guarantee rests on
LangRef's prohibition on removing volatile operations rather than on inline-asm semantics.
That is the categorical arm, and the stronger one to test from.

## Where each measurement runs, and why

**The residue measurement runs in WSL2, not Windows.** On Windows, `HeapFree` is not a
deallocation function LLVM recognises, so a fill before it is never proven dead and never
eliminated — a green Windows result is consistent with the mechanism working *or* not
working. The crate's own benchmark reports "0 of 9 sizes resolvable" there and calls it
untested rather than passed. Windows' heap also does not reliably hand the just-freed
block back, which a readout depends on.

Verified available: **WSL2 Ubuntu 24.04, glibc 2.39, cargo/rustc 1.96.1** — i.e. the
`cfg!(all(target_os = "linux", target_env = "gnu"))` that
`tests/common/residue.rs::readout_is_specified_here()` requires.

Windows keeps a real but narrower job: **portability and workload**, not mechanism.

## Where things are built — C: is nearly full

Measured, because it changes the layout rather than being a preference:

| Drive | Free | Role |
|---|---|---|
| **C:** | **20.4 GB** | the repo lives here; **write nothing large to it**. Its existing `target/` is already **7.2 GB** |
| F: | 381 GB | already holds `F:\wsl\Ubuntu` — the WSL disk |
| **O:** | **11 TB** | worktrees, target dirs, gate artifacts |

Rust target directories run to several GB per feature configuration, and this plan builds
five of them twice over. So:

- **Worktrees go in `O:\Projects\Worktrees\`**, one per experiment, never under `C:`.
- **`CARGO_TARGET_DIR` points into `O:`** for every Windows build, per worktree, which also
  keeps the runs isolated from each other — the discipline this project already uses for
  parallel cargo.
- **`MSOFFICE_CRYPTO_ARTIFACT_DIR` points into `O:`**, not the system temp directory, which
  is on C: and is the shared path CLAUDE.md § Build and verify warns about anyway.
- **Claude's scratchpad is on C:**, so it holds notes and small outputs only.

**The WSL half does not build on `O:`.** `/mnt/o` is a drvfs mount, and cargo on drvfs is
slow enough to distort a measurement and occasionally trips on case sensitivity and
permissions. WSL work happens inside the WSL filesystem under `$HOME`, whose vhdx already
sits on `F:` with 381 GB free — so it costs C: nothing. The Windows repo is reached
read-only through `/mnt/c` for the initial clone, and nothing is written back across the
boundary.

## The work

### 0. Confirm WSL actually boots — it just failed

`wsl -d Ubuntu` answered fine once and then timed out after 300 seconds with
`Wsl/Service/CreateInstance/CreateVm/0x800705b4`. Since WSL is the only venue where the
central measurement is meaningful, this gets settled before anything is built rather than
discovered halfway through.

If it cannot be made reliable, say so and stop: the honest outcome is then the workload
result on Windows plus a written statement that the mechanism check was **not** performed,
never a Windows green reported as a pass. Reclaiming the 7.2 GB `target/` on C: is one
plausible remedy if the failure is memory or disk pressure.

### A. Walkthrough (the "teach me to use it" half)

Written as prose for you, not as code. Covers: what the crate is, the one install pattern,
why a library must never declare one, what it does and does not protect, and what the
`[unverified]` items in its own docs actually mean. Key points already established:

```rust
use secure_gate_zalloc::ZeroizingAlloc;
#[global_allocator]
static ALLOC: ZeroizingAlloc<std::alloc::System> = ZeroizingAlloc(std::alloc::System);
```

Applications only — only one `#[global_allocator]` may exist per program, and a second
anywhere in the graph is a hard compile error naming a crate the consumer never wrote
down. One wrinkle the build agent measured: a declaration in `src/main.rs` does **not**
reach `tests/` integration binaries; `src/lib.rs` reaches all three.

### B. msoffice-crypto's suite under the allocator — Windows and WSL

A new `tests/heap_residue.rs`, modelled on the existing `tests/legacy_allocation.rs`,
which is the precedent: it already installs a `#[global_allocator]` and its header states
the rule — *"a `#[global_allocator]` is process-wide… One test, one binary, one
measurement."* Cargo builds one binary per `tests/*.rs`, so there is no conflict.

Then the five-config matrix from CLAUDE.md § Build and verify. This answers "is it
harmless against real code", which is worth knowing but is **not** a pass.

Worth including as a stress case: `spin_hash` runs ~100,000 rounds per decrypt, each
allocating and dropping a fresh 64-byte `Vec` — named in the secure-gate skill as
~100,000 abandoned buffers per decrypt that the crate deliberately does *not* wrap. Under
a zeroizing allocator they are wiped for free, and it is a far heavier allocation
workload than the crate's own benchmark exercises.

### C. The residue demonstration — WSL only

1. Isolated worktree at `O:\Projects\Worktrees\msoffice-residue`, cloned into WSL's own
   filesystem for the build. Revert `src/standard_encrypt.rs:216-220` to the `to_vec()` +
   `resize` form the changelog records.
2. Compose a recorder **underneath** the wrapper — `ZeroizingAlloc<Spy>` — because
   `dealloc` wipes *before* forwarding inward, so the spy observes post-wipe bytes. This is
   direct observation, not inference from a later allocation landing on the same address.
   The crate deliberately exposes no self-check hook; composition is the supported answer.
3. Three constraints, all learned the hard way by the build agent and not to be
   rediscovered: **the spy must not allocate** (fixed array under a Mutex) or it re-enters
   the allocator; **pin one specific pointer** and record that block's fate, or "wiped" and
   "never reached the allocator" pass identically; and **sample from offset 64, not 16** —
   a freed glibc chunk carries free-list links in its first bytes, two words in a small bin
   and four once sorted into a large bin.
4. **The control is mandatory.** Same code, same build, allocator not installed: the
   digest bytes must be measurably **present**. A run with only the "with" half proves
   nothing, because a clean read is equally consistent with the wipe working, the block
   never being returned, or the growth never reallocating.

**Reporting rules, agreed with the build agent in advance so they cannot be rationalised
after the fact:**

- Residue present without / absent with, one variable changed → **pass**.
- Residue survives under the allocator → **the most valuable outcome available**. Report
  raw, do not tidy, do not assume the harness is at fault.
- Growth extends in place, or the block is never returned → **"untested", never "clean"**.

## Footprint — the experiment is scratch, the findings are not

**The code is scratch; nothing of it merges.** A `path` dev-dependency breaks
msoffice-crypto's CI outright — the runner checks out this repository alone, so
`cargo metadata` fails and with it `clippy` (5 legs), `test` (5 legs), `supply-chain` and
`package`. The worktree, the reverted `standard_encrypt.rs`, the spy allocator and the
`Cargo.toml` edit all die with the worktree.

**The knowledge is durable and lands as a real commit**, on its own branch and PR, because
a scratch experiment that leaves nothing behind has to be re-run by the next person who
wonders. Three artifacts, following this repository's existing conventions:

| Artifact | Convention it follows |
|---|---|
| `docs/plans/msoffice-crypto-zalloc-2026-09-18.md` | `docs/plans/` is dated files — `msoffice-crypto-cli-2026-09-11.md`, `…-foundation-2026-09-04.md` |
| `docs/design/heap-residue.md` | `docs/design/` is topical and undated — `development-record.md`, `msoffice-crypto-format-history.md` |
| A `CHANGELOG.md` Evidence entry | **Only if** there are measurements; the changelog protocol says a measurement carries a date because a reader needs to know how stale the observation is |

`docs/design/heap-residue.md` is the one that matters in five years. It should record the
things that are true regardless of how the experiment turns out:

- **The class of defect**, with the two dated instances this repository already has and the
  measured pointer pair — a `Vec` realloc abandons an unwiped block, and no amount of
  wrapper discipline inside the library can reach it.
- **What a zeroizing allocator does and does not close**: heap only. It does nothing for
  the stack spills the secure-gate skill lists — `sha2::compress512`'s message schedule,
  where `W[0..16]` *is* the password block verbatim — nor for `hmac`'s opad/ipad state,
  which has no `Drop`. Recording that boundary is what stops the allocator being read later
  as having retired the reserve-exact discipline. It narrows the problem; it does not
  close it.
- **Why the measurement cannot be taken on Windows**, which is the least obvious finding
  here and the one most likely to be rediscovered painfully: `HeapFree` is not a
  deallocation function LLVM recognises, so a green Windows run is consistent with the
  mechanism working *or* not.
- **The result**, in whatever direction it goes, with the reporting rules above applied.

If nothing conclusive comes out, that document still gets written and says so — an
"untested, and here is precisely why" is worth more than silence, and this repository has
a standing rule against reporting a void run as a pass.

Adding a file to `docs/design/` means adding its line to CLAUDE.md's Layout block, which
is house style rather than a gate (`tools/audit_claims.py` check D covers `src/*.rs` only).

What would *not* break, checked rather than assumed, and relevant if we later decide to
keep any of it: all five `cargo tree` calls in the `no-cipher-in-detection` job use
`-e normal`, which excludes dev-dependencies; `deny.toml` sets `exclude-dev = true` and
already allows `MIT OR Apache-2.0`; the `msrv` job builds without dev-deps and edition 2024
is stable in 1.85; and `tests/*.rs` is outside the `include` allowlist by construction.

## Verification

| Step | Where | Built in | What counts as done |
|---|---|---|---|
| Crate's own suite | WSL | `$HOME` (F:) | Full suite green, matching the committed Linux receipt |
| Crate's own suite | Windows | `O:` target | Portability confirmation; residue tests self-report unspecified |
| msoffice-crypto matrix | Windows | `O:` worktree + target | 5 configs green under the allocator, and the cost noted |
| msoffice-crypto matrix | WSL | `$HOME` (F:) | Same, on the platform where the mechanism is observable |
| Residue control | WSL | `$HOME` (F:) | Digest bytes **present** without the allocator |
| Residue subject | WSL | `$HOME` (F:) | Same build, allocator installed — bytes absent, or reported raw |

Before starting, confirm free space has not moved; and if C: is under pressure at the end,
the worktrees and their target directories on `O:` are the disposable part.

Cost is measured and reported, but is explicitly **not** a pass criterion; the crate
documents its own cost curve.

## Reporting back

The build agent is quiescent at `2ceb92c` and has asked for results either way. Anything
found gets sent there. Two items already worth sending regardless of outcome:

- Their plan file says the `secure_gate_shape` pair is "not wired into CI", but neither
  test is `#[ignore]`d and the `test` job runs bare `cargo test` — so both do run.
- Their `README`/install documentation is drafted but unlanded pending publication; the
  walkthrough in §A is the thing a first-time consumer needs and may be worth landing.
