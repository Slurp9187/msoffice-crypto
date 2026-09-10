Status: In progress — S1–S7 landed; S8 (publish) open (as of 2026-09-05)

# msoffice-crypto — foundation, and the arc to a complete MS-OFFCRYPTO implementation

The crate that was extracted from a private application decrypts two of the five
encryption families [MS-OFFCRYPTO] defines and writes none of them. This plan is the
route from there to detection + decryption + encryption across all of them, and — more
importantly — the record of **which upstream owns which piece and under what licence**,
because that mapping took a full session to establish and would be expensive to redo.

Sibling arc: [`odf-crypto`](https://github.com/Slurp9187/odf-crypto) does the same job for
OpenDocument. The two crates are deliberately shaped alike; where this plan says "as
odf-crypto does", that is a real, readable precedent rather than an aspiration.

---

## 1. Scope

[MS-OFFCRYPTO] — "Office Document Cryptography Structure" — is the single spec covering
every encryption format Microsoft Office has shipped. It is the crate's boundary:

| Family | Spec | Container | Status today |
| --- | --- | --- | --- |
| ECMA-376 Agile | §2.3.4.10+ | CFB | decrypt ✅ · encrypt ✅ (S5) |
| ECMA-376 Standard | §2.3.4.5 | CFB | decrypt ✅ · encrypt ✅ (S6) |
| RC4 CryptoAPI | §2.3.5 | CFB | ❌ `UnsupportedEncryptionVersion` |
| XOR obfuscation | §2.4 | binary | ❌ |
| Binary (doc97 / xls / ppt) | §2.2 | CFB | ❌ |
| DataSpaces | §2.1 | CFB | read: ignored; write: **required** |

**The name follows this table.** The crate was called `ooxml-crypto` when it was
agile+standard only; RC4 CryptoAPI and doc97 operate on binary `.doc`/`.xls`/`.ppt`,
which are not OOXML in any sense. `msoffice-crypto` is the boundary the code actually has.

**Out of scope, permanently.** Password recovery / cracking. herumi's `attack.hpp` is a
capable implementation of it and is deliberately not ported — a vault's dependency tree is
the wrong place for that code, whatever its provenance.

---

## 2. Provenance map — the expensive knowledge

Every piece below was read and licence-checked on 2026-09-04. The licence column is what
constrains reuse. **The authority for this crate is the table below and `CLAUDE.md`
§ *Provenance*** — there is no `docs/LICENSING.md` here, and an earlier version of this
sentence linked one as though there were. The file of that name is the sibling's,
[`odf-crypto/docs/LICENSING.md`](https://github.com/Slurp9187/odf-crypto/blob/main/docs/LICENSING.md),
which is the model this analysis was written from and is worth reading for the fuller
treatment of the same questions.

| Piece | Best source | Licence | Posture |
| --- | --- | --- | --- |
| Agile + standard **decrypt** | this crate (validated vs msoffcrypto KAT) | ours | keep |
| RC4 CryptoAPI, doc97 **decrypt** | [`office-crypto`](https://github.com/Udbhav-Muthakana/office-crypto) `method/rc4.rs`, `format/doc97.rs` | **MIT** | **port**, attribute |
| Agile **encrypt** | [`herumi/msoffice`](https://github.com/herumi/msoffice) `encode.hpp` (221 L) | **BSD-3** | **port**, NOTICE |
| DataSpaces stream contents | herumi `resource.hpp` (4 consts, 452 B) | **BSD-3** | **port**, NOTICE |
| Standard **encrypt** | herumi `standard_encryption.hpp`; [excelize](https://github.com/qax-os/excelize) `crypt.go` | BSD-3 | port |
| CFB container mechanics | [`cfb`](https://github.com/mdsteele/rust-cfb) 0.14 | MIT | **depend** |
| Agile-writer + `cfb` integration | [`ms-offcrypto-writer`](https://github.com/42triangles/ms-offcrypto-writer) 1.0.7 | MIT/Apache | **reference** |
| Differential oracle | [`msoffcrypto-tool`](https://github.com/nolze/msoffcrypto-tool) 6.0.0 | MIT | dev tool |
| Behavioural tie-breaker | LibreOffice `oox/source/crypto/` | **MPL-2.0** | **read only, never copy** |
| — | [`CryptoOffice`](https://github.com/CoreOffice/CryptoOffice) | **Apache-2.0** | **do not open** |

Two entries carry real obligations and one is a trap:

- **herumi/msoffice is BSD-3** (`COPYRIGHT`: Cybozu Labs, Inc. 2007-2015). Porting from it
  requires retaining the copyright, the disclaimer and the no-endorsement clause. `NOTICE`
  in the repo root exists for exactly this and is shipped in the crate tarball.
- **LibreOffice is MPL-2.0**, which is file-level copyleft. Reading it to learn *how the
  format behaves* is fine and is what odf-crypto did; pasting a line of it is not. Cite
  `file:line` in this plan when a decision comes from there.
- **CryptoOffice is Apache-2.0**, which does not sit under the MIT half of a
  `MIT OR Apache-2.0` offer. There is no reason to open it — every fact it holds is
  available from an MIT or BSD source above.

### 2.1 Corrections to earlier belief

Recorded because both were asserted confidently and were wrong:

- **"No Rust crate writes ECMA-376."** False. `ms-offcrypto-writer` 1.0.7 (MIT OR
  Apache-2.0, ~105k downloads) writes agile encryption, emits the full DataSpaces subtree,
  and does it **on top of the `cfb` crate**. It is agile-only and encrypt-only, so it does
  not replace this crate, but it is the closest reference that exists.
- **"Whether `cfb` produces an Office-acceptable container is an open risk."** Largely
  closed by the above: `ms-offcrypto-writer` has shipped `cfb`-built containers at volume,
  and `xlsx_encryptor` is built on it. The residual question is narrow (§5, S4).

### 2.2 Why this crate exists at all

`office-crypto` covers more formats on decrypt than we do. `ms-offcrypto-writer` already
encrypts agile. The honest justification is not "we can do it better":

1. **One API over detect + decrypt + encrypt.** No existing crate spans all three, and
   assembling four crates means four different key-handling postures in one dependency tree.
2. **Key material is wrapped.** `office-crypto`, `ms-offcrypto-writer`, `msoffcrypto-tool`
   and `herumi/msoffice` all hold the spin hash, block keys and session key in bare
   containers. This crate zeroizes them. That is the differentiator, and it belongs in the
   README's first paragraph.

---

## 3. What landed on 2026-09-04 (the extraction)

Split out of the application it began in via `git subtree split`, preserving both
original commits and their messages verbatim.

- `office-ooxml-crypto` → `ooxml-crypto` → **`msoffice-crypto`**; files rebased to repo root.
- **Fixtures vendored** to `tests/fixtures/`. They were read across the old repo boundary
  (a path in the parent repository) and that path dies on extraction.
- **Missing fixtures now fail the suite.** The tests used `let Ok(data) = … else { eprintln!; return }`,
  so a missing fixture produced a **green suite that tested nothing** — precisely what the
  move would have caused. Proven by deleting `agile_encrypted.docx` and watching
  `test_agile_fixture_decrypts_to_zip` fail at `src/lib.rs:108`.
- `cfb` 0.7 → **0.14**, taken now rather than mid-feature: 0.14 adds `create_with_version`
  (CFB v3 512-byte vs v4 4096-byte sectors, which Office distinguishes), `create_new_stream`,
  an internal validate pass, and a fuzz target over the writer.
- `secure-gate` 0.9.0-rc.7 added as a dependency (`default-features = false`, `alloc`).
- `office-crypto` 0.3 added as a **dev-dependency** — the differential oracle.
- 17/17 tests green standalone.

### 3.1 Deliberately NOT done on 2026-09-04, with reasons — and what became of each

*Status as of 2026-09-05, so this section reads as history and not as instruction:* the
feature split landed with `classify` at S1; the boundary move was **withdrawn as a design
error** on 2026-09-04 (handoff §6.2) and is not folded into anything — the boundary stays
plain; and `rand` went on at S5 step 4, with the seeded RNG being `chacha20::ChaCha12Rng`
rather than the `Fixed::from_rng(&mut seeded)` sketched below (D3 has the correction).

- **No `classify` / `crypto-ops` feature split yet.** odf-crypto's default build is
  detection-only, and this crate should end up there. Doing it today would gate everything
  behind a non-default feature while the only detection-capable function is an 8-byte
  memcmp — `cargo add msoffice-crypto` would install something useless. The split lands
  **with** `classify` (S1). In a 0.x crate that reshuffle is cheap and expected.
- **Public API still uses plain types** (`&str` password, `Vec<u8>` out). secure-gate wraps
  *internal* key material; the boundary stays plain, matching the "plain types at the wire
  boundary" rule the consumer already applies to sidecars. Changing the boundary requires the consumer's whole
  call chain to move and is folded into S1 rather than half-done now.
- **`secure-gate`'s `rand` feature is off.** A decrypt-only crate generates no randomness.
  It switches on in S5, where `Fixed::from_random()` serves production and
  `Fixed::from_rng(&mut seeded)` serves tests.

---

## 4. Design commitments

Four decisions that are cheap now and expensive to retrofit.

### D1 — `classify` carries the integrity claim

odf-crypto's `classify` answers "encrypted? which algorithm tuple?". This one must also
answer **"does this file declare `dataIntegrity`?"**, because that is what lets `decrypt`
take an explicit policy — `Require` / `VerifyIfPresent` / `Skip` — instead of silently not
checking. See §6 (F18). `classify` needs `cfb` + `quick-xml` and **zero ciphers**, so the
"detection is free" property survives.

### D2 — one container layer, not three

`office-crypto` hand-rolls OLE (`ole.rs`, 789 L). herumi hand-rolls it (`cfb.hpp`, 789 L).
Both implement FAT chains, DIFAT and a red-black directory tree. `cfb` 0.14 does all of it,
is fuzzed, and is MIT. **Take format logic from both, container mechanics from neither.**
That is ~1,578 lines not written, not reviewed, and not maintained.

### D3 — deterministic encryption from the first commit

Randomness enters via an injected RNG, never a call to a global. secure-gate supplies both
halves already, so no custom trait is needed:

```rust
// production
let salt = Fixed::<[u8; 16]>::from_random();
// tests — byte-exact, reproducible
let salt = Fixed::<[u8; 16]>::from_rng(&mut ChaCha12Rng::from_seed(Default::default()))?;
```

Without this you can only write round-trip tests, which prove the crate agrees with itself.
With it you can commit **golden encrypted output**. herumi reaches for the same trick with
an `#ifdef SAME_KEY`; `ms-offcrypto-writer` uses a seeded ChaCha12 in its own tests.

**The RNG is `chacha20`, not `rand_chacha` — corrected 2026-09-04.** This section
originally named `rand_chacha`'s `ChaCha12Rng::from_seed`, and so did issue #6. Neither
compiles. `Dynamic::from_rng<R: TryRng + TryCryptoRng>` takes those two traits from
**`rand_core 0.10`**, which is what secure-gate 0.9 resolves; `rand_chacha` 0.9 is pinned to
`rand_core 0.9`, so its `ChaCha12Rng` does not satisfy the bound.

`rand::rngs::StdRng` is not the escape hatch either, and this is the trap worth recording:
it *is* ChaCha12 and it *does* take a seed, so it compiles and looks right — but rand
documents it as non-portable, "even with a fixed seed, output is not portable"
(`rand-0.10.1/src/rngs/std.rs:20-21, 36`). A golden committed against it would be valid
until the next rand release quietly changed the bytes, which is precisely the failure a
golden exists to catch.

Use **`chacha20 0.10`** with `features = ["rng"]` — RustCrypto, MIT/Apache-2.0, and the
crate rand's own documentation points at for portability. Its `ChaCha12Rng` implements
`SeedableRng + TryRng + TryCryptoRng` against `rand_core 0.10`
(`chacha20-0.10.0/src/rng.rs:138-168`). It costs **zero added crates**: rand 0.10 already
depends on `chacha20`, so the graph gains nothing once `secure-gate/rand` is on.

### D4 — streaming, because the format already is

Agile encryption is defined in 4096-byte segments with per-segment IVs. herumi's
`EncContent` loops over exactly that; our `agile.rs` already reads `plaintext_size` and runs
`NoPadding` per segment; `ms-offcrypto-writer` exposes `Read + Write + Seek`. The streaming
shape is latent in the spec and every buffer-in/buffer-out API is throwing it away. Build
the segment iterator first — retrofitting is miserable, and the consumer's temp-file discipline
means a 200 MB `.pptx` should not need three copies in RAM.

---

## 5. Slices

One sub-issue per slice, per [`docs/plan-workflow.md`](../plan-workflow.md). Sizes: S =
hours, M = ~a day, L = multiple days, XL = its own arc with its own plan file.

| # | Slice | Size | Blocked on |
| --- | --- | --- | --- |
| S1 | `classify` + feature split + secure-gate at the boundary | M | — |
| S2 | Verify `dataIntegrity` on decrypt (F18) | S | S1 |
| S3 | Port RC4 CryptoAPI + doc97 decrypt from `office-crypto` (GH #4; done 2026-09-05 — `.doc`, `.xls` and `.ppt` under RC4 CryptoAPI, `.xls` under XOR, Office 97/2000 RC4 by known answer, all behind `legacy-binary`) | M | S1 |
| S4 | CFB **writer** spike — does Office accept a `cfb`-built tree? | S | — |
| S5 | Agile **encrypt** | L | S1, S4 |
| S6 | Standard **encrypt** (GH #7; done 2026-09-05 — `encrypt_ooxml_standard`, opened by real Word 16, msoffcrypto-tool and office-crypto, and put through S7's gate) | M | S5 |
| S7 | Four-reader acceptance gate (GH #8; done 2026-09-05 — `tools/acceptance_gate.py`, all four readers accept what both encrypt paths write, LibreOffice's first verdict included) | M | S5 |
| S8 | Publish: crates.io + repo public | S | S1–S7 |
| S9 | Bound every file-controlled parameter (GH #10, closed; its one remaining item rides S5 step 2) | M | — |
| S10 | Agile decrypt honours `hashAlgorithm` (GH #11, closed; the AES-256-only remainder is S12) | S | — |
| S11 | Missing `dataIntegrity` fails closed (GH #12, closed) | S | S2 |
| S12 | AES-128 / AES-192 agile, so three more real-world tuples open (GH #13; done 2026-09-05 — all four tuples decrypt, and real Word 16 opens every fixture) | L | S10 |

S9–S12 were filed as issues on 2026-09-04 without a row here; the rows are added so the
table indexes every slice the parent issue tracks. Their design lives in the issues.

### S1 — `classify`, feature split, secure-gate boundary (M)

**Do.** A `classify(&[u8]) -> Classification` returning container shape, `vMajor`/`vMinor`,
the algorithm tuple (cipher, hash, keyBits, blockSize, spinCount) and **whether
`dataIntegrity` is present** (D1). Move ciphers behind a `crypto-ops` feature; `default = []`.
~~Move the public API onto secure-gate types now that a redesign is happening anyway.~~
**Withdrawn 2026-09-04 as a design error** (handoff §6.2): this crate's own secure-gate
skill and `odf-crypto`'s two published releases both keep the boundary plain, and the one
consumer passes a bare `&str`. The first two parts landed (#2, closed).

**Close when.** `--no-default-features` builds and classifies all four fixtures without
linking a cipher crate (`cargo tree` shows no `aes`). ~~the consumer's call sites compile against
the new signatures.~~ the consumer's handler is switched off until this crate publishes; its
re-enable list is where the new signatures are met.

**Not this slice.** Any new format; any encrypt.

### S2 — Verify `dataIntegrity` (F18) (S)

**Do.** The two missing block keys — `dataIntegrity1 = 5f b2 ad 01 0c b9 e1 f6`,
`dataIntegrity2 = a0 67 7f 02 b2 2c 84 33` — plus `encryptedHmacKey` / `encryptedHmacValue`
handling. Reference: herumi `encode.hpp:53-72` (write side, cites [MS-OFFCRYPTO] 2.3.4.14),
LibreOffice `AgileEngine.cxx:390-451` (read side, behaviour only). Wire the policy enum from D1.

**The detail that is easy to get wrong:** the HMAC covers the whole `EncryptedPackage`
stream *including* its 8-byte little-endian size prefix (herumi `MakeEncryptedPackage`
prepends, then `GenerateIntegrityParameter` HMACs the result).

**Close when.** A fixture with one flipped ciphertext byte is refused under `Require` and
under `VerifyIfPresent`, and the guard is proven by deleting the check and watching the
test fail. Standard encryption has no integrity element by spec — assert it reports
`None`, not a failure.

**Not this slice.** Encrypt-side HMAC generation (that is S5).

### S3 — RC4 CryptoAPI + doc97 decrypt (M)

**Do.** Port `office-crypto`'s `method/rc4.rs` and `format/doc97.rs` (MIT — retain the
notice). Take the format logic, **not** its `ole.rs` (D2). Put both behind a
`legacy-binary` feature, default off, so the default build stays modern-Office.

**Close when.** `msoffcrypto-tool`'s `rc4cryptoapi_password.{doc,xls,ppt}` and
`xor_password_*.xls` fixtures decrypt to bytes identical to what `msoffcrypto-tool -d`
produces. Fixtures regenerated locally, not copied (as odf-crypto's §4 does).

*Met 2026-09-05, with one recorded exception.* The fixtures are this repo's own
Office-16-written `word97_password.doc`, `excel97_password.xls` and
`powerpoint97_password.ppt` plus a generated `excel97_xor.xls` (Excel 16 writes XOR only
into BIFF5, which the oracle cannot read). The `.doc` and both `.xls` are byte-identical
to the oracle's output. The `.ppt` is identical but for one 4-byte word: msoffcrypto
decrements the persist directory's `cPersist` and leaves a dangling entry with
`cPersist = 0`, which [MS-PPT] §2.3.5 forbids and PowerPoint 16 refuses (`0x80048242`);
this crate leaves the directory alone, and the test pins both digests — ours, and ours
with msoffcrypto's edit re-applied equalling msoffcrypto's. The second oracle the slice
grew — real Word, Excel and PowerPoint opening every decrypted output with no password —
is what decided it, as it decided the padding rule in #13. Also read: Office 97/2000 RC4
(§2.3.6), which no fixture can exercise because Office 16 refuses to write it; pinned to
msoffcrypto's known-answer vector and a synthetic container.

**Not this slice.** XOR obfuscation write; any encrypt. Still open after it: Word's XOR
(Method 2), BIFF5 workbooks, the `EncryptedSummary` stream when `fDocProps` is clear,
PowerPoint's `Pictures` stream — each named and refused or left as the oracle leaves it.

### S4 — CFB writer spike (S)

**Do.** Build a `\x06DataSpaces` tree with `cfb` 0.14 — six streams per herumi
`make_dataspace.hpp:44-48` — wrap any valid `EncryptedPackage`, and open it in real Word.
The specific unknown: herumi hardcodes red/black directory-entry colours
(`make_dataspace.hpp:77-87`). Either Office tolerates any valid tree and those are
incidental to their tree-builder, or it does not and `cfb` needs coaxing.
`ms-offcrypto-writer` suggests the former; confirm rather than assume.

**Close when.** Word opens the file, or the required deviation from `cfb`'s default layout
is written down here.

**Not this slice.** Real key derivation — a stub payload is enough to answer the question.

### S5 — Agile encrypt (L)

**Do.** Port herumi `encode.hpp` (BSD-3 — `NOTICE`). Skip `cfb.hpp` entirely (D2). Enable
secure-gate's `rand`; inject the RNG per D3. Build the segment loop as an iterator per D4.

`resource.hpp` is **not** ported: S4 already *generates* those four blobs from their
[MS-OFFCRYPTO] field definitions and proved them byte-identical to a real document's
(`tests/cfb_dataspaces_container.rs`). Generating beats porting here — it keeps the crate
free of anyone's expression for 452 bytes of constants.

#### Six steps, in dependency order

1. **Promote the S4 spike into `src/dataspaces.rs`.** `build_container` and the four blob
   generators live in `tests/` today. Left there, S5's writer becomes a *second* copy of
   the thing that was proven and the byte-identity proof does not cover it. Move them into
   `src/` behind the feature gate and re-point the existing tests at the production code;
   no new evidence is needed, the existing test simply starts testing the right thing.
2. **The segment iterator (D4). — done, `src/segments.rs`.** `decrypt_package` and the
   test-side `encrypt_package` both run on it, so the two directions share one segmentation
   and one IV derivation rather than two that can drift silently. The
   `/EncryptedPackage` read ceiling folded forward from GH #10 landed with it as
   `limits::PAYLOAD_CEILING` (1 GiB, `odf-crypto`'s figure), aliased to
   `ENCRYPTED_PACKAGE_READ_CAP` and applied at both allocation paths.
3. **The `EncryptionInfo` XML writer. — done, `src/encryption_info.rs`.** AES-256 /
   SHA-512 / `spinCount = 100000`, the only tuple Office 16 writes and the only one this
   crate decrypts; widening is #13. **Byte-identical to what Word 16, Excel 16 and
   PowerPoint 16 write** (an identical 1 289-byte stream in all three), which is the test:
   values lifted from a real stream, handed to the writer, compared to the original. The
   layout follows Word rather than herumi, who differs in exactly two places — a bare `
`
   after the declaration, and `xmlns:c` only under `isOffice2013`.
4. **Key generation and the verifier blobs. — done, `src/agile_encrypt.rs`.** herumi
   `encode.hpp:132-190` is the recipe, with **one deliberate departure**: herumi draws the
   session key at `saltSize` (16) bytes and `normalizeKey`s it up to `keyBits / 8` with
   `0x36` filler, giving an AES-256 key with 128 bits of entropy and a constant top half.
   No round-trip test in any implementation can see that, because the key is whatever the
   writer says it is. This crate draws all 32. `ms-offcrypto-writer` agrees
   (`src/lib.rs:474`), which is what makes it herumi's bug rather than the format's.

   Salts are **not** wrapped — written to `EncryptionInfo` in the clear, so public by
   construction — but drawn from the same injected CSPRNG. `rand 0.10` joins `crypto-ops`;
   `chacha20 0.10` is a dev-dependency for the seeded golden.
5. **`dataIntegrity` generation. — done, `integrity::generate` beside `verify`.** The
   self-agreement trap was handled by *not* rewriting the verify tests' own writer to call
   it — that helper stays an independent oracle — and the external check is the one step 3
   had: unwrap Office's HMAC key from a real fixture, hand it back, and both blobs come
   out byte-identical to Office's, on all three fixtures.
6. **Public API. — done.** `encrypt_ooxml(package, password)` is one line over the
   `pub(crate)` seeded `agile_encrypt::encrypt`, exactly as *Determinism without a public
   seam* below asks; the five `cfg(test)` gates flipped in the same commit. The whole
   container is byte-exact under a seeded RNG (41 984 bytes for `plain.docx`), which
   required zeroing the directory timestamps `cfb` stamps with the clock. Opened by real
   Word 16 over COM (wrong password refused with `0x800A1520`), by `msoffcrypto-tool`
   (byte-identical plaintext) and by `office-crypto` in the suite. LibreOffice is the one
   S7 reader not run, and S7 owns it.

#### The payload ceiling, folded forward from GH #10 — landed with step 2

GH #10 closed with four of its five items landed; the fifth — a read ceiling on
`/EncryptedPackage` — moved here because step 2 is what made it answerable, and landed with
it as `limits::PAYLOAD_CEILING = 1 << 30`.

**1 GiB is `odf-crypto`'s figure**, taken rather than invented: same job, same class of file,
and no reason this crate has to differ. It is aliased to `ENCRYPTED_PACKAGE_READ_CAP` and
applied at both allocation paths — `cfb_reader`'s stream read and `decrypt_package`'s output
buffer — per GH #10's pattern 3, with a `const` assertion tying the two together per its
pattern 5.

**What it is not.** Not an anti-amplification bound: `cfb` 0.14 bounds every read by the
directory entry's `stream_len` *and* by the real FAT chain, so a forged length fails the read
rather than allocating, and a file claiming a gigabyte must actually be one. It is a memory
bound — a decrypt holds ciphertext and plaintext at once, so 1 GiB of payload is ~2 GiB of
peak. **If it ever refuses a real document the fix is the streaming API, not a bigger
number**: raising it buys one document and moves the same wall, while `Read + Write + Seek`
over `segments` removes the wall, which is what the rest of D4 is for.

The cheap half of the gap was already closed before this: `agile.rs` rejects a declared
plaintext size larger than the ciphertext carried.

#### Determinism without a public seam

The golden test needs a seeded RNG; the public API must not grow a parameter for it.
`classify_tests.rs` and `malformed_input.rs` already live in `src/`, so the golden lives
there too and calls a `pub(crate)` seeded entry point. A test seam that reaches the public
surface becomes a supported surface we have to keep — for a 0.x crate with one consumer
that is cheap to add and permanently expensive to remove. An `_with_rng` sibling is the
fallback **only** if the test genuinely has to be an integration test, and the reason gets
written down if so.

No `EncryptOptions` builder yet. It would carry two fields, and the tuple choice it
anticipates is #13.

**Close when.** Round-trips through our own decrypt, **and** produces byte-exact output
against a committed golden under a seeded RNG, **and** S7's external readers accept it.
*Met 2026-09-05* on all three, with S7's LibreOffice row explicitly carried by S7.

**On the golden bar** (revised 2026-09-04): this slice originally said "diff against
herumi's and msoffcrypto's bytes for identical inputs". That requires driving both tools
with *our* salt, IV and session key — a `SAME_KEY` rebuild of herumi, and reaching into
msoffcrypto's internals — which is real cost for evidence S7 supplies more directly, since
S7 includes real Word recovering exact content. A bar nobody intends to meet is worse than a
lower one, so the byte-exact requirement is against **our own committed golden**.

The cheap half of the cross-implementation evidence is kept, because it needs none of our
internals: **`msoffcrypto-tool` decrypting our output to byte-identical plaintext** is
genuine agreement with an independent implementation, and `office-crypto` is already a
dev-dependency doing the same job. Both are S7 rows.

**Not this slice.** Standard encrypt (S6). Any tuple but AES-256/SHA-512 (#13).

### S6 — Standard encrypt (M)

**Do.** herumi `standard_encryption.hpp`; excelize `crypt.go` (BSD-3) as the second read —
it is the only permissively-licensed *Go* implementation and hand-rolls its container, so
it is a useful cross-check on stream contents.

**Close when.** Same bar as S5, for Office-2007-format output.

*Met 2026-09-05* (GH #7). Two things this section assumed turned out otherwise, recorded
here so the next reader does not re-discover them: herumi's `standard_encryption.hpp` is a
**decoder** — there is no encrypt side in it to port, and msoffcrypto-tool has none either
— so `src/standard_encrypt.rs` writes the layout that decoder reads, from the spec, with
LibreOffice's `Standard2007Engine.cxx` and excelize's `crypt.go` read for behaviour and
cited by line; and the committed `standard_encrypted.docx` is *non-conforming* in three
header fields (`Flags 0x36`, RC4's `AlgID 0x6801`, a zero `Flags` copy), so the writer
follows the spec there and the fixture everywhere else, byte for byte. The `\x06DataSpaces`
streams were measured identical between the standard fixture and Word 16's agile output,
so `build_container` is shared unchanged. Opened by real Word 16 over COM (wrong password
refused with `0x800A1520`), by `msoffcrypto-tool` (byte-identical plaintext) and by
`office-crypto` in the suite; LibreOffice is S7's row. The public entry point is
`encrypt_ooxml_standard`, named for the format; `encrypt_ooxml` stays agile.

### S7 — Four-reader acceptance gate (M)

**Do.** No upstream has this. herumi's `test_all.py` is `decrypt → encrypt → decrypt`,
which proves only self-consistency; odf-crypto's `validate_encrypt.py` adds the external
leg. Go wider than either — our `encrypt()` output must open in **all four**:

| Reader | Driver | Independent of us? |
| --- | --- | --- |
| Microsoft Word | COM (`Word.Application`, `PasswordDocument`) | shipping product |
| LibreOffice | UNO (`loadComponentFromURL` + `Password`) | shipping product |
| `msoffcrypto-tool` | CLI `-d` | independent impl |
| `office-crypto` | dev-dependency, already wired | independent impl |

**Close when.** All four recover byte-identical plaintext, in CI where the reader allows
and documented as a local gate where it does not (Word COM is Windows-only).

*Met 2026-09-05*, with one refinement to the bar: the two applications parse the package
into a document model and never hand the ZIP back, so "byte-identical" is the bar for the
two implementations (`msoffcrypto-tool`, `office-crypto`, both in CI), and "opens,
content matches, wrong password refused for the password reason" is the bar for Word and
LibreOffice (the local gate). `tools/acceptance_gate.py` runs all four;
`tools/office_com_check.ps1` grew Excel and PowerPoint for the Office-16 controls, and
`tools/libreoffice_uno_check.py` is the UNO driver the 2026-09-04 attempt could not get
working — the changelog entry for the day records how, and what each reader said.

**Not this slice.** ODF — that is odf-crypto's `validate_encrypt.py`.

### S8 — Publish (S)

**Do.** Flip the repo public; `cargo publish`. Verify the `include` allowlist by unpacking
the tarball and running its tests. Confirm `NOTICE` and both `LICENSE-*` are present.

**Close when.** `cargo install --locked` from crates.io builds, and a fresh
`cargo test` inside the unpacked tarball passes.

**Blocked on:** the repo is currently **private**, which also blocks the consumer from consuming it
as a git dependency without credentials — see §7.

---

## 6. Known gaps carried in from the consumer

- **F18 — agile decrypt never verifies the package HMAC.** `src/agile.rs` handles no
  `dataIntegrity`. It verifies the *password* and then decrypts with `NoPadding` and hands
  the bytes on, so a package corrupted or tampered by someone without the password decrypts
  to garbage with `Ok`. Fixed in S2. Confirmed present: the crate has 3 of the 5 block keys
  (`src/agile.rs:21-23`).
- **Password is `&str` at the boundary.** No zeroization on the caller's copy. *By
  design, and staying so* — see S1's withdrawn third part.
- **No streaming.** Whole-file `Vec<u8>` in and out. The segment iterator (D4) landed at
  S5 step 2 and both directions run on it; a `Read + Write + Seek` API over it is still
  open, and is what would let the 1 GiB payload ceiling go.

---

## 7. Consumer integration

The consumer uses this crate through exactly four call sites and two functions
(`is_cfb_office`, `decrypt_ooxml`), behind an optional `ooxml` feature. The seam
is narrow by construction and S1 is free to change the API.

**secure-gate version coupling is the real constraint, and the direction is not obvious.**
The consumer pins `=0.8.0-rc.10`; this crate and odf-crypto are on `0.9.0-rc.7`. Those are
*different types* — the moment a secure-gate type crosses the crate boundary, the versions
must match. Today nothing does, so the two versions coexist harmlessly; S1 is what forces
the decision.

`0.8.0-rc.10` is a **backport of `0.9.0-rc.7`**, not a predecessor: same API, different
MSRV and `rand` line. 0.8 is MSRV 1.70 on rand 0.9; 0.9 is MSRV 1.85 on rand 0.10. That
makes this a compatibility decision, not a currency one:

| Crate | MSRV | secure-gate |
| --- | --- | --- |
| `aescrypt-rs` | 1.70, CI-enforced (`cargo +1.70 test --all-features`) | 0.8 |
| `age-pq-workspace` | 1.70 | 0.8 |
| the consumer | 1.81 | 0.8 (forced by the two above) |
| `odf-crypto` | 1.85 | 0.9 |
| `msoffice-crypto` | 1.85 | 0.9 |

**Bumping the consumer up to 0.9 is not a one-repo change.** `aescrypt-rs` and `age-pq-workspace`
both hand the consumer secure-gate types, so they move first, in that order — and moving them
raises their MSRV to 1.85, discarding the 1.70 promise the 0.8 backport exists to keep.

**Decided (2026-09-04): everything converges on 0.9.** secure-gate 0.8 stops being
maintained once stable ships, so the direction is up, not down. `aescrypt-rs` and
`age-pq-workspace` raise `rust-version` to 1.85 and drop `cargo +1.70` from CI as part of
that migration. **That work belongs to the consumer's own repository and its own
session — do not start it here.**

Two findings from the investigation, kept because they are cheap to lose and expensive to
redo:

- **0.8 is a faithful backport, verified not assumed.** This crate was built and tested
  against `=0.8.0-rc.10` with zero source changes, 17/17 green. `Fixed::from_random`,
  `Fixed::from_rng`, `Dynamic::from_random` and `Dynamic::from_rng` sit at essentially
  identical line numbers in both. The only surface difference is the RNG trait bound —
  0.8 takes `TryRngCore + TryCryptoRng`, 0.9 takes `TryRng + TryCryptoRng`, the
  `rand_core` 0.9→0.10 rename — invisible unless the bound is spelled out. So D3's
  determinism hook is available on either version, and moving between them is a manifest
  edit.
- **Dropping secure-gate to edition 2021 would not have helped and was rejected.**
  `secure-gate-core` does build at edition 2021 (only one trybuild `.stderr` needs
  regenerating; the `Deref`/`AsRef` guarantees still hold, since neither impl exists in
  any edition). But `rand_core 0.10` is *itself* `edition = "2024"`, `rust-version =
  "1.85"`, and `thiserror 2.0`'s no-std path needs `core::error::Error` at 1.81. So
  edition 2021 buys 1.81 for non-`rand` builds and nothing at all for `rand` builds —
  which is the half `aescrypt-rs` and `age-pq-workspace` are in.

**What this means for S1.** Only the *third* part of S1 — moving the public API onto
secure-gate types — waits on that migration. `classify` and the `crypto-ops` feature split
touch no shared type and can land first. Split S1 if the migration is not done when this
arc starts; do not block detection work on a dependency bump.

Note that the "0.8 keeps the graph on rand 0.9" argument does *not* hold for the consumer: it
already resolves rand 0.7.3, 0.8.5, 0.9.2 **and 0.10.0**, the last via `lopdf 0.40`. This
crate contributes no `rand` at all while its feature stays off.

**Until S8, the consumer should keep a relative path dependency** (`../../msoffice-crypto`). The
house pattern for cross-repo is a bare git dep — `age-pq-workspace` and `odf-crypto` are
both public and work unauthenticated. This repo is private, so a git dep needs a credential
helper (or the ssh URL) on every machine and in CI, and the crate was deliberately kept out
of the consumer's workspace so it *could* build on Linux CI. A path dep sidesteps that entirely and
keeps the edit-test loop fast while the interesting work is still ahead.

---

## 8. References

- [MS-OFFCRYPTO] Office Document Cryptography Structure — the primary source. Cite section
  numbers in code comments; herumi already does (`encode.hpp:51`).
- Sibling: [`odf-crypto`](https://github.com/Slurp9187/odf-crypto) —
  `docs/LICENSING.md` is the model for §2's analysis, `tests/goldens/validate_encrypt.py`
  for S7's external leg.
- Origin: the consumer's own `native-encryption-formats` plan, findings F1 and F18,
  slice S06.
