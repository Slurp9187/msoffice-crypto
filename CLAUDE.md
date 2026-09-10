# Project Rules — msoffice-crypto

Microsoft Office document encryption in Rust: detection, decryption and encryption of the
formats [MS-OFFCRYPTO] defines, with key material that zeroizes on drop.

Sibling crate: [`odf-crypto`](https://github.com/Slurp9187/odf-crypto) does the same job for
OpenDocument. The two are shaped alike on purpose — when a rule here is thin, look at how the
sibling solved it before inventing something new.

---

## Project Status — pre-release, nothing published

> **This crate has never been published. Its only consumer is a private application in
> the same hands.**

That fact changes the right answer to a whole class of scoping questions, so state it rather
than assuming either way:

- **Breaking API changes are free.** No deprecation cycle, no compatibility shim, no
  `#[deprecated]` re-export. Change the signature, fix the one caller, fix the tests.
- **Feature reshuffles are free.** Moving items behind `crypto-ops`, changing what `default`
  includes — all fine, and expected, in a 0.x crate with one consumer.
- **The one real constraint is that consumer's Office handler, and it is dormant.** It is
  switched off until this crate publishes, and its own header carries the list for switching
  it back on. When you change the API, say in your report exactly what that re-enable must do
  differently — it will need `features = ["crypto-ops"]` (or `["legacy-binary"]`, its
  superset, to open `.doc`/`.xls`/`.ppt` through `decrypt_binary_office`), the fail-closed
  `IntegrityPolicy` default, and the error variants it currently flattens. That application
  is not edited from here.

Revisit this section the moment `cargo publish` runs (plan slice S8) — at that point the API
becomes a promise.

---

## Design Values

When a decision is not covered by the concrete rules below, fall back on these.

### 1. Every input is hostile

> **This crate's entire job is parsing files that an attacker chose the bytes of.**

That is the defining property and the one that separates it from most Rust crates. A user
opens an untrusted `.docx`; the app calls us before anything else has validated it.
Consequences, all non-negotiable:

- **A panic is a vulnerability.** Any caller not catching unwind is taken down by it. Slice
  indexing, `unwrap`, `expect`, integer casts and subtraction on file-derived numbers are all
  attack surface. Return an error.
- **Unbounded work is a vulnerability.** `spinCount` is a file-controlled iteration count; a
  declared plaintext size is a file-controlled allocation. Both need ceilings. A hang is a
  denial of service that no `Result` can report.
- **`classify` must never fail loudly.** It is the first thing a caller runs on an unknown
  file. Return "unknown", never panic.

Bounds live in one module with MIN and MAX for every field, each carrying a doc comment
citing its provenance and justifying its margin. See `odf-crypto/src/limits.rs` for the shape
and plan slice S9 for the numbers.

### 2. Key material is wrapped — it is why this crate exists

> **`office-crypto`, `ms-offcrypto-writer`, `msoffcrypto-tool` and `herumi/msoffice` all hold
> the spin hash, block keys and session key in bare containers. We do not.**

This is the honest answer to "why not just use `office-crypto`". It is not a claim to
out-implement anyone; it is one property none of them offers. Losing it would remove the
crate's reason to exist, so it is not tradeable for convenience.

Full policy: [`.claude/skills/msoffice-crypto-secure-gate/SKILL.md`](.claude/skills/msoffice-crypto-secure-gate/SKILL.md).
That skill is the authority on secure-gate; this file does not duplicate it.

### 3. Licence discipline is load-bearing

> **One pasted function from the wrong upstream makes the crate undistributable under half
> its own licence.**

This crate is `MIT OR Apache-2.0`. Apache-2.0 material does not sit under the MIT half — a
downstream user choosing MIT would not receive the attribution and patent terms that code
carries. MPL-2.0 material is file-level copyleft and drags the file it lands in with it. See
§ *Provenance* below; it is the most consequential table in this file.

### 4. Evidence over intent

> **"I implemented the check" is not the bar. "I deleted the check and watched the test fail"
> is.**

A guard test that passes with and without the thing it guards is decoration. Every security
check lands with a test proven to fail without it, and the report says what the failure
looked like. This applies to bounds, HMAC verification, password verification, and any future
integrity check.

The same discipline killed a real bug during extraction: four fixture tests used
`let Ok(data) = fs::read(..) else { return }`, so a missing fixture produced a green suite
that tested nothing. Fixtures are not optional; a missing one fails.

---

## Provenance — which upstream, which licence, what you may do

Established 2026-09-04. **Read this before porting a single line.**

| Source | Licence | What you may do |
| --- | --- | --- |
| [herumi/msoffice](https://github.com/herumi/msoffice) | **BSD-3** (Cybozu Labs) | **Port.** Retain copyright, disclaimer, no-endorsement clause. `NOTICE` carries it. |
| [office-crypto](https://github.com/Udbhav-Muthakana/office-crypto) | **MIT** | **Port.** Retain the notice. `NOTICE` carries it. |
| [msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool) | **MIT** (+ its own NOTICE, herumi-derived) | **Port**, carrying both chains. Also the differential oracle. |
| [ms-offcrypto-writer](https://github.com/42triangles/ms-offcrypto-writer) | MIT/Apache | Reference for `cfb` integration. |
| [`cfb`](https://github.com/mdsteele/rust-cfb) | MIT | **Depend.** Do not hand-roll a container layer. |
| **LibreOffice** `oox/source/crypto/` | **MPL-2.0** | **READ ONLY.** Behaviour and constants; cite `file:line` in a comment. **Never copy or transliterate expression.** |
| **CoreOffice/CryptoOffice** | **Apache-2.0** | **DO NOT OPEN.** Incompatible with the MIT half. Every fact it holds is available from an MIT or BSD source. |

**Why LibreOffice is worth reading despite being unusable as code:** it is the only reference
that is a twenty-year-old shipping application hardened against hostile files. Its *algorithm*
is available permissively elsewhere; its *limits* are not. Facts about which values are
acceptable are not copyrightable.

**Local clones** (paths, not URLs, are what agents need):

```
O:/projects-github-clones/msoffice              herumi (BSD-3)
O:/projects-github-clones/office-crypto         MIT
O:/projects-github-clones/msoffcrypto-tool      MIT
O:/projects-github-clones/ms-offcrypto-writer   MIT/Apache
O:/projects-github-clones/LibreOffice/core/oox/source/crypto   MPL — read only
~/Projects/odf-crypto                 sibling crate, house style
~/Projects/secure-gate-workspace      secure-gate source
```

The two `~` paths are home-relative on purpose — `~/Projects/...` resolves in both Git
Bash and PowerShell, and keeps a workstation user name out of a repository that is going
to be public. Do not re-absolutise them. (`C:/~/...` resolves in neither shell: `~`
expands only at the start of a path.)

Prefer the **spec** ([MS-OFFCRYPTO], Microsoft Open Specification Promise) over any
implementation, and cite section numbers in comments where a constant or step is non-obvious.
herumi already does this — `encode.hpp:51` cites 2.3.4.14.

---

## Cryptographic Rules

**Constant-time comparison for anything secret-derived.** A MAC, a password verifier, a key —
compared with `==`, `memcmp`, or slice equality is a timing oracle. `Dynamic<Vec<u8>>` has no
`PartialEq` precisely to make the wrong thing hard; nest `with_secret` closures and let a bool
out, and use secure-gate's `ct-eq` where the comparison is over attacker-influenced data.

**Never put key material in an error, log, panic message, or `format!`.** secure-gate types
print `[REDACTED]` in `Debug`, but anything extracted from them does not. Errors describe the
failure, not the data.

**Distinguish failure modes in the error type.** "Wrong password" and "file tampered" are
different facts and must be different variants — telling a user their password is wrong when
the file was modified is actively misleading.

**Verify before returning plaintext.** The agile package HMAC is computed over ciphertext, so
it can be checked before decrypting at all. Never hand back bytes that failed verification.

**Do not invent format constants.** Every magic byte, block key and salt derivation is in the
spec or in a permissive reference. Cite where it came from.

---

## Testing Rules

- **Fixtures are not optional.** A missing fixture fails the test; it does not skip.
  Fixtures live in `tests/fixtures/` and the password is `testpass`. Of the nineteen, the
  `include` allowlist ships **two** — the ones `classify`'s doc examples pull in with
  `include_bytes!` — because the other seventeen were two thirds of the `.crate`.
- **The corpus tests are `#[ignore]`d where there is no corpus, never skipped silently.**
  `build.rs` sets `cfg(fixture_corpus)` when it finds any of the seventeen withheld
  fixtures, and the thirty corpus-dependent tests carry
  `#[cfg_attr(not(fixture_corpus), ignore = "…")]`. So the published crate's `cargo test` is
  green with them reported as **ignored, with a reason**, while this repository runs all
  thirty. An early `return` on a missing file would be the anti-pattern above wearing a hat.
  **Read the ignored count in both directions:** 0 in a tarball means the corpus leaked into
  the allowlist; anything but 0 here means a fixture is missing. A partial corpus counts as
  present, so the one that is gone still fails by name.
- The verdicts of the external readers are written down in `CHANGELOG.md`; that, and this
  repository, are where the evidence is re-run.
- **Prove every guard.** Delete the check, watch the test fail, restore, and report the
  failure you saw.
- **Assert the specific error variant**, not `is_err()`. An `is_err()` assertion passes when
  the code fails for an unrelated reason.
- **Include a negative control.** A tampered-file test that only ever fails cannot distinguish
  "policy wired correctly" from "always fails" — pair it with a `Skip` case that succeeds.
- **Tamper in the ciphertext body**, not the header or container, or the test passes for the
  wrong reason (parse failure, not MAC mismatch).
- **Use the differential oracles.** `office-crypto` is already a dev-dependency; agreeing with
  an independent implementation is stronger evidence than agreeing with yourself. Where an
  encrypt path exists, real Word and real LibreOffice are the bar, and
  `tools/acceptance_gate.py` is how it is run (plan slice S7; see § *Build and verify*).
- **Generate fixtures, don't copy them.** Program output carries no upstream licence; a copied
  test file might. See `odf-crypto/docs/LICENSING.md` §4.

---

## Layout

```
src/lib.rs             public API: classify, is_cfb_office, decrypt_ooxml, decrypt_ooxml_with_policy, encrypt_ooxml, encrypt_ooxml_standard, decrypt_binary_office
src/classify.rs        detection; NEVER panics, returns Unknown        (+ classify_tests.rs)
src/binary_office.rs   legacy .doc/.xls/.ppt recognition, and the FIB / BIFF / persist-directory readers both probe and decrypt share
src/agile.rs           ECMA-376 agile decrypt: parse, KDF, verifier, package
src/standard.rs        ECMA-376 standard decrypt: parse, KDF, verifier, package — and the ECB helper the writer shares
src/standard_encrypt.rs the Office 2007 writer: salt, derived key, verifier blobs, binary header, and the assembly behind encrypt_ooxml_standard   (+ standard_encrypt_tests.rs)
src/integrity.rs       dataIntegrity HMAC verification + IntegrityPolicy / IntegrityOutcome
src/hash.rs            HashAlgorithm dispatch and IV derivation           (crypto-ops)
src/segments.rs        the 4096-byte segment iterator both directions share (D4)   (+ segments_tests.rs)
src/cfb_reader.rs      capped stream reads
src/limits.rs          every bound, each with cited provenance
src/sensitive.rs       secure-gate aliases — the only place they are declared
src/error.rs           Error -- the crate's single public error type
src/malformed_input.rs hostile-input tests, containers built at runtime
src/dataspaces.rs      the \x06DataSpaces writer and the CFB container, timestamps zeroed   (+ dataspaces_tests.rs)
src/encryption_info.rs the EncryptionInfo serialiser, byte-identical to Office's   (+ encryption_info_tests.rs)
src/agile_encrypt.rs   the agile key schedule, the package encryptor, and the assembly behind encrypt_ooxml   (+ agile_encrypt_tests.rs)
src/rc4.rs             RC4 over a wrapped key, the per-block loop, the verifier check   (legacy-binary, as are the seven below)
src/rc4_cryptoapi.rs   RC4 CryptoAPI: header structure, key generation, password check  ([MS-OFFCRYPTO] 2.3.5)
src/rc4_office97.rs    Office 97/2000 RC4: MD5 key generation, password check           (2.3.6)
src/xor_obfuscation.rs XOR obfuscation Method 1: verifier, array, transformation       (2.3.7)
src/legacy_container.rs the CFB a binary document is decrypted inside: capped reads, in-place rewrites
src/word97.rs          the Word 97 walk: FIB, table stream, Data stream
src/excel97.rs         the Excel 97 walk: FILEPASS, the record set kept in the clear
src/powerpoint97.rs    the PowerPoint 97 walk: persist directory, CryptSession10Container, per-object keys
src/legacy_malformed.rs hostile-input tests for the three walks, on tampered fixtures and synthetic streams
tests/real_office_fixtures.rs   the Office-written fixtures against an independent oracle
tests/legacy_binary_fixtures.rs the binary fixtures, byte for byte against msoffcrypto-tool's output
tests/fixtures/        every fixture, password `testpass`; only two ship in the tarball (see Cargo.toml)
examples/office_crypto_check.rs the office-crypto leg of the acceptance gate: file in, plaintext out
tools/                 the fixture generators (msoffcrypto-tool; Office over COM; gen_xor_fixture.py),
                       the four-reader acceptance gate — acceptance_gate.py over office_com_check.ps1
                       (Word, Excel, PowerPoint), libreoffice_uno_check.py (UNO), msoffcrypto-tool and
                       the example — and office_com_check_binary.ps1, the Office side of the decrypted
                       binary documents
tools/audit_claims.py  reads the prose back against the tree; CI runs it, and so does
                       docs/RELEASING.md step 1 with the clones attached
.github/workflows/ci.yml  the matrix below, on every push
build.rs               sets cfg(fixture_corpus): the corpus tests are #[ignore]d where there is no corpus
deny.toml              the dependency half of the licence rule: what may arrive in the graph
SECURITY.md            the disclosure policy, and what this crate counts as a vulnerability
docs/RELEASING.md      the release runbook; a live procedure, not a dated snapshot
docs/plan-workflow.md  how plans become issues
docs/design/           why the crate is shaped as it is -- development-record.md (what the
                       issues and PRs decided, reversed and deferred, and the #N index) and
                       msoffice-crypto-format-history.md (the formats, and what converts)
docs/audits/           external audit reports; deltas only, dated, not revised after filing
docs/plans/            dated plan files; the arc lives in msoffice-crypto-foundation-2026-09-04.md
.claude/skills/        msoffice-crypto-secure-gate (policy), file-plan-issues (protocol),
                       changelog-protocol (version headings, dates and tags)
```

One module, one job. A module whose purpose needs an "and" to state has two.

---

## Conventions

**Changelog.** Version headings, newest first: `## vX.Y.Z — unreleased` while the work is in
flight, and the ISO date substituted the moment that tag is cut. **The date is the release
marker, not a note about when the work happened** — git already records that, and a typed
date drifts (five entries here were once stamped in UTC on a UTC-7 machine and read a day
into the future). Entries carry a date only when the date is part of the claim: a
measurement against particular versions of external readers needs one, a rename does not.
Full rule and the tagging step: [`.claude/skills/changelog-protocol/SKILL.md`](.claude/skills/changelog-protocol/SKILL.md);
enforced as check G of `tools/audit_claims.py`. The pre-publication changelog was 3,397 lines
of dated entries and stayed with the archived development repository — frozen, not a
violation to tidy.

**Plans and issues.** A plan is a dated file in `docs/plans/`. A parent issue (label `plan`)
with one closeable sub-issue per slice (label `slice`) coordinates it. The file is the design;
the issues are the handles; nothing restates another. Full protocol:
[`docs/plan-workflow.md`](docs/plan-workflow.md). Agents file via the `file-plan-issues` skill.

**Closing issues.** GitHub links only the **first** `#N` after each keyword — `Closes #10, #11`
closes only the first, and `Closes #10-#15` closes nothing at all. One keyword per issue.
Verify with
`gh pr view <n> --json closingIssuesReferences` rather than trusting the prose.

**secure-gate version.** This crate tracks 0.9.x, matching `odf-crypto`, and the
dependency is optional on `crypto-ops` — the detection build holds no key material.
The consumer named above pins `=0.8.0-rc.10` and resolves both side by side, which works
because **no secure-gate type crosses this crate's public API, by design**: the plan to
move the boundary onto its types ("S1 part 3") was withdrawn as a design error on
2026-09-04 and is not coming back without new evidence. The secure-gate skill is the
authority on what is wrapped; it agrees.

---

## Build and verify

```bash
cargo test   --locked --no-default-features
cargo test   --locked --no-default-features --features crypto-ops
cargo test   --locked --no-default-features --features legacy-binary
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo clippy --locked --all-targets --no-default-features --features crypto-ops -- -D warnings
cargo clippy --locked --all-targets --no-default-features --features legacy-binary -- -D warnings
cargo fmt --all --check
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --no-default-features
cargo deny --all-features check licenses advisories bans sources
python tools/audit_claims.py --clones O:/projects-github-clones
```

**One at a time.** Two concurrent `cargo` invocations against this working directory
produce a spurious failure on Windows: on 2026-09-05 a background matrix run and a
foreground `cargo package` collided and reported `could not compile msoffice-crypto
(example "office_crypto_check")`, and the identical command alone was green. A failure
seen while something else was building is not evidence of anything.

**Always run all three feature configurations.** A change can be clean in one and broken
in another, and the detection build is the one people forget. `.github/workflows/ci.yml`
runs this matrix plus an MSRV 1.85 build, the docs.rs nightly build, `cargo package
--locked`, a `cargo deny` job over licences, advisories, bans and sources, a `prose` job
running `tools/audit_claims.py`, a `packaging-invariants` job (build.rs stays in the
`include` allowlist; `rc4` keeps `zeroize` -- both silent failures otherwise), and a job
asserting three graph properties — the detection graph contains no cipher, hash, MAC, RNG
or key-wrapping crate; the `crypto-ops` graph contains neither `rc4` nor `md-5`; and the
`legacy-binary` graph contains both, without which the first two would be vacuous — the
properties, not crate counts. Every module that parses a file
denies `clippy::unwrap_used`, `expect_used` and `panic` on itself — `classify.rs`,
`binary_office.rs`, and under `legacy-binary` the eight `rc4*`/`xor_obfuscation`/
`legacy_container`/`word97`/`excel97`/`powerpoint97` modules; clippy under `-D warnings` is
what enforces it. A file's own `#[cfg(test)]` module carries an inner `allow`, as
`classify_tests.rs` does at file scope: the header is about the parser, not the tests that
drive it. (`classify.rs` was named here before it carried the header — the claim was false
from 2026-09-04 until the legacy-binary work made it true.)

**The local gate, before a change to the encrypt path merges.** CI runs the two
independent-implementation legs of the four-reader acceptance gate, plus its two mutation
runs; the two shipping products need this machine. **Name a private artifact directory** —
every session's `cargo test` writes `msoffice_crypto_encrypt_ooxml.docx` into the shared
system temp directory, so gating that path can gate another build's file and record the
verdict as evidence for yours. **That has actually happened** — a gate run measured another
build's artifact and the verdict was very nearly recorded as evidence for the wrong tree:

```bash
export MSOFFICE_CRYPTO_ARTIFACT_DIR="$(mktemp -d)"
cargo test --locked --no-default-features --features crypto-ops
python tools/acceptance_gate.py "$MSOFFICE_CRYPTO_ARTIFACT_DIR/msoffice_crypto_encrypt_ooxml.docx" \
  --expect-package tests/fixtures/plain.docx --expect-text-file tests/fixtures/plain_content.txt
```

A pass is four lines ending `PASS` — Word (`0x800A1520` on the wrong password),
LibreOffice (a password request, aborted), `msoffcrypto-tool` (byte-identical, and the
only reader here that verifies the `dataIntegrity` HMAC) and `office-crypto`
(byte-identical) — and `GATE: PASS`. Record the lines in the changelog against the
artifact's SHA-256, which the script prints first. It takes any encrypted artifact
(`--expect-sha256` when the plaintext is not committed), and `--tamper --expect-fail` and
`--corrupt-integrity --expect-fail` are the proofs that it fails when it should. Check
`tasklist` for a leaked WINWORD, EXCEL, POWERPNT or soffice afterwards; the drivers stop
their own, but a hung run cannot.

Do not commit or push unless asked.
