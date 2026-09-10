Status: Pre-release — the first published version has not been cut yet

# Changelog

Entries are keyed by version, newest first, and dated on the day the version was published.

**The pre-publication development record is not here.** This crate was built across 14
issues and 12 pull requests in a private repository, whose changelog ran to 3,397 lines of
day-by-day reasoning — the right artifact while the work was happening, and the wrong one
for a reader who has just run `cargo add`. That repository is archived and holds it.

What survives that move is in two places, deliberately:

- **[`docs/development-record.md`](docs/development-record.md)** — the decisions. What was
  settled and then reversed, what was tried and did not work, what was closed without being
  finished, the bugs found in the upstream implementations this crate ports from, and the
  index that makes the archived repository's issue numbers resolvable.
- **The Evidence section below** — the measurements. External readers' verdicts, byte-exact
  goldens, and the differential-oracle results, because
  [`README.md`](README.md) argues that this crate's claims are checkable rather than
  assertable and that argument needs the numbers to be somewhere a consumer can read them.

---

## v0.1.0-rc.1 — unreleased

First public version. Detection, decryption and encryption of the formats [MS-OFFCRYPTO]
defines, with key material held in `secure-gate` wrappers that zeroize on drop.

[`README.md`](README.md) § *Scope* carries the per-format coverage table and is the
authority on it; it is not repeated here.

A pre-release on purpose. Cargo does not match a pre-release from an ordinary requirement,
so `msoffice-crypto = "0.1"` will not resolve to this and a consumer must name the full
version. That is the right shape while the API is still free to move: nothing has yet used
it in anger, and publishing `0.1.0` would make it a promise on the day it landed.

### Evidence

Every figure below was measured, not asserted. The commands that produce them are in
[`docs/RELEASING.md`](docs/RELEASING.md).

#### The four-reader acceptance gate

`encrypt_ooxml`'s output is put in front of two shipping applications and two independent
implementations. The applications parse the package and never hand the ZIP back, so their
bar is *opens, content matches, and a wrong password is refused for the password reason*;
the implementations' bar is byte-identity with the original.

Last recorded run, against artifact SHA-256
`3d0eceb7a0b3b48415c1977c64dff9fc690e50e3e706600418d7111ec0e26637`:

```
office         PASS  Word 16.0.19127: OPENED, content matches; wrong password REFUSED 0x800A1520
libreoffice    PASS  LibreOffice 26.2.1.2: OPENED, content matches; wrong password REFUSED (password request, aborted)
msoffcrypto    PASS  msoffcrypto-tool 6.0.0: byte-identical to plain.docx; dataIntegrity HMAC verifies
office-crypto  PASS  office-crypto 0.3: byte-identical to plain.docx
GATE: PASS (4 of 4 readers ran)
```

`msoffcrypto-tool` is the only reader there that verifies the `dataIntegrity` HMAC, and the
gate drives it through the library rather than the CLI for exactly that reason — the CLI
leaves verification off by default, so a `dataIntegrity` regression would otherwise pass
unnoticed.

**This run predates the final pre-publication changes** (the `quick-xml` bump below among
them) and is recorded as the last measured verdict, not as this release's. `docs/RELEASING.md`
§ 2 requires a fresh run against the released artifact; its four `PASS` lines and hash
replace the block above when the version is cut.

The gate is proven to fail when it should: `--tamper` (one bit in the ciphertext body) and
`--corrupt-integrity` (the `dataIntegrity` blobs rewritten as same-length base64) each drive
it to `GATE: FAIL`, and both run in CI with the exit code inverted.

#### Byte-exact goldens

Encryption is deterministic under an injected RNG, which is what makes a committed golden
possible rather than only a round trip. Under `chacha20::ChaCha12Rng` seed `[0u8; 32]`,
password `testpass`, input `plain.docx`:

| path | output | SHA-256 |
| --- | --- | --- |
| `encrypt_ooxml` (agile, AES-256/SHA-512) | 41,984 bytes | `b4cc009e…2a6b` |
| `encrypt_ooxml_standard` (Office 2007, AES-128/SHA-1) | 40,960 bytes | `491298746ce1…7e42` |

Both are stable across processes. They are whole containers, not just the payload, which is
what caught the one place the writer was nondeterministic: `cfb` stamps the creation clock
into the root entry and each storage, so `build_container` now zeroes every directory
timestamp — [MS-CFB] § 2.6.1's uninitialized value, and what Office itself writes.

#### The 97-2003 binary formats, against an independent oracle

Under the off-by-default `legacy-binary` feature, decrypted output is compared byte for byte
with `msoffcrypto-tool`'s, and the result is opened by the real application with no password:

| fixture | scheme | vs `msoffcrypto-tool -d` | Office 16 on this crate's output |
| --- | --- | --- | --- |
| `word97_password.doc` | RC4 CryptoAPI 128 | byte-identical | Word: opened, full text |
| `excel97_password.xls` | RC4 CryptoAPI 128 | byte-identical | Excel: opened, all 240 cells |
| `powerpoint97_password.ppt` | RC4 CryptoAPI 128 | identical **but for one 4-byte word** | PowerPoint: opened, slide text |
| `excel97_xor.xls` | XOR obfuscation | byte-identical | Excel: opened |

**The PowerPoint word is the oracle's bug, not this crate's.** `msoffcrypto-tool` decrements
the first `PersistDirectoryEntry`'s `cPersist` and leaves a dangling zero entry, which
[MS-PPT] § 2.3.5 forbids — and PowerPoint 16 **refuses its own output** (`0x80048242`) while
opening this crate's. The test pins both digests, ours and ours with the oracle's edit
re-applied, so the differential evidence still holds for every other byte.

Office 97/2000 RC4 (MD5) has no real fixture and says so: Office 16 refuses to write that
provider whatever `SetPasswordEncryptionOptions` asks, so that family is pinned to
`msoffcrypto-tool`'s known-answer vectors and a synthetic container.

#### Tests

| | detection | `crypto-ops` | `legacy-binary` |
| --- | --- | --- | --- |
| lib | 30 | 175 | 205 |
| integration | — | 9 | 12 |
| doc | 15 | 23 | 25 |

All three configurations are clean under `clippy -- -D warnings` and both
`RUSTDOCFLAGS="-D warnings" cargo doc` ends. CI runs the matrix on every push, plus an MSRV
1.85 build, the docs.rs nightly build, `cargo package --locked`, `cargo deny`, the prose
audit, and a job asserting three dependency-graph properties.

**A guard lands with a test proven to fail without it.** Every security check in this crate
was verified by deleting the check, watching the named test fail, and restoring it; the
individual failures are in the archived development record. The practice is stated in
[`CLAUDE.md`](CLAUDE.md) § *Evidence over intent* and is not optional for future work.

### Security posture at this release

- **The default build links no cryptography** — no cipher, hash, MAC, RNG or key-wrapping
  crate. `classify` answers what a file is with a CFB reader and an XML parser and nothing
  else. CI asserts the property, not a crate count.
- **`#![forbid(unsafe_code)]`.** The crate has never contained an `unsafe` block, and
  `forbid` rather than `deny` means an inner `#[allow]` is itself a compile error.
- **`quick-xml` 0.41**, which is the floor that remediates `RUSTSEC-2026-0194` (quadratic
  duplicate-attribute checking, reachable from `classify` on attacker-chosen XML, in the
  default build) and `RUSTSEC-2026-0195`. Found by `cargo deny` on its first run here.
- **`cargo deny`** over licences, advisories, bans and sources on every push, scoped to the
  graph a consumer actually builds.
- **Fail-closed by default.** An agile file whose `dataIntegrity` element has been removed
  is refused rather than decrypted, because deleting ~200 bytes of XML is the cheapest tamper
  available and needs no password. Opting out is possible and must be explicit.
- **Distinct failures.** "Wrong password", "file tampered" and "unsupported algorithm" are
  separate error variants, because telling a user their password is wrong when the file was
  modified is actively misleading.

[`SECURITY.md`](SECURITY.md) states what counts as a vulnerability in a crate whose entire
job is parsing bytes an attacker chose — and, as usefully, what does not.

[MS-OFFCRYPTO]: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/
[MS-CFB]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/
[MS-PPT]: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/
