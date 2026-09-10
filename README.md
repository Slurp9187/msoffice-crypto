# msoffice-crypto

Microsoft Office document encryption in Rust — detection, decryption and encryption of the
formats [MS-OFFCRYPTO] defines, with **key material that zeroizes on drop**.

> **Status: early, unpublished.** Today this crate *detects* every family below;
> *decrypts* ECMA-376 agile (Office 2010+) in all four tuples found in the wild —
> AES-128/SHA-1, AES-128/SHA-384, AES-192/SHA-384 and Office 16's own AES-256/SHA-512 —
> and ECMA-376 standard (Office 2007), AES-128/SHA-1 only; *encrypts* both — agile in the
> Office 16 tuple, and standard in the Office 2007 format — producing files real Word 16,
> real LibreOffice, `msoffcrypto-tool` and `office-crypto` all open, the four-reader gate
> below; and, under the `legacy-binary` feature, *decrypts* the 97-2003 binary formats —
> `.doc`, `.xls` and `.ppt` under RC4 CryptoAPI, `.xls` under XOR obfuscation — to what
> `msoffcrypto-tool` writes and what Word, Excel and PowerPoint 16 open with no password.
> See
> [`docs/plans/msoffice-crypto-foundation-2026-09-04.md`](docs/plans/msoffice-crypto-foundation-2026-09-04.md)
> and the issues it indexes.

## Two builds: detection is free

`classify` answers what a file is — container shape, encryption family, the algorithm
tuple it declares, and whether it carries a `dataIntegrity` element — with **no
cryptographic dependency at all**: the default build links a CFB reader and an XML parser
and no cipher, hash, MAC, RNG or key-wrapping crate, and CI asserts exactly that property
on every push. It returns no `Result` and does not panic: an unreadable file classifies as
`Unknown`, and a malformed one is never called unencrypted.

```rust
use msoffice_crypto::{classify, Family, IntegrityDeclaration};

let data = std::fs::read("protected.docx")?;
let class = classify(&data);

if class.family == Family::Agile && class.data_integrity == IntegrityDeclaration::Declared {
    // ...this file can be decrypted *and* its package HMAC verified
}
```

Decryption is the `crypto-ops` feature, which adds the ciphers and hashes (`aes`, `cbc`,
`ecb`, `sha1`, `sha2`, `hmac`, `base64`), the key-wrapping primitive (`secure-gate`) and,
for the encrypt half, a CSPRNG (`rand`):

```toml
msoffice-crypto = { version = "0.1.0-rc.1", features = ["crypto-ops"] }
```

```rust
use msoffice_crypto::{is_cfb_office, decrypt_ooxml};

let data = std::fs::read("protected.docx")?;
if is_cfb_office(&data) {
    let zip = decrypt_ooxml(&data, "correct horse battery staple")?;
    // `zip` is the original OOXML package — a valid .docx/.xlsx/.pptx
}
```

The other direction is one call, and it writes what Office 16 writes — agile, AES-256/SHA-512,
100 000 rounds, a `dataIntegrity` HMAC — so the result opens in Word:

```rust
use msoffice_crypto::encrypt_ooxml;

let package = std::fs::read("report.docx")?;          // a plain OOXML ZIP
let protected = encrypt_ooxml(&package, "correct horse battery staple")?;
std::fs::write("report-protected.docx", protected)?;
```

For a reader that predates agile encryption there is `encrypt_ooxml_standard`, the Office
2007 format — AES-128-ECB under a SHA-1-derived key, no integrity element. It is named for
the format so that choosing it is a decision: a modified ciphertext decrypts silently to a
modified document, which is what `dataIntegrity` exists to prevent.

Either direction is deterministic: given the same package, password and random draws it is
the same bytes, down to the CFB directory — which is why both encrypt paths can be pinned
by byte-exact goldens at all, and why a file this crate writes records nothing about when
it was written.

`secure-gate` rides on `crypto-ops` too — not because it is a swappable algorithm, but
because the detection build holds no key material and so has nothing to zeroize.

The 97-2003 binary formats are a third build, `legacy-binary`, a superset of `crypto-ops`
that adds the two primitives nothing modern needs — the RC4 stream cipher and MD5 — and
one function. A `.doc`, `.xls` or `.ppt` is decrypted *in place*: the result is the same
CFB container with its encrypted streams replaced, which is what Word, Excel and
PowerPoint open.

```toml
msoffice-crypto = { version = "0.1.0-rc.1", features = ["legacy-binary"] }
```

```rust
use msoffice_crypto::{classify, decrypt_binary_office, Document};

let data = std::fs::read("protected.doc")?;
if classify(&data).document == Document::WordBinary {
    let doc = decrypt_binary_office(&data, "correct horse battery staple")?;
    // `doc` is the same .doc with no password, byte for byte what msoffcrypto-tool writes
}
```

## Why this crate exists

There are good implementations of these formats already, and this crate is not claiming to
out-implement them. It is aimed at callers who handle documents they did not create —
vaults and password managers, backup and archival tools, mail and upload gateways, DLP and
compliance scanners, indexing pipelines that keep hitting files they cannot open. It exists
for five reasons those callers care about and the alternatives do not cover.

**1. One API across detect, decrypt and encrypt.** `office-crypto` decrypts and does not
encrypt. `ms-offcrypto-writer` encrypts agile and does not decrypt. `msoffcrypto-tool` is
Python and `herumi/msoffice` is C++ — neither is reachable from a Rust binary without a
subprocess or an FFI layer. Assembling a complete picture means several dependencies with
several different postures toward the same key bytes.

**2. Key material is wrapped.** `office-crypto`, `ms-offcrypto-writer`, `msoffcrypto-tool`
and `herumi/msoffice` all hold the spin hash, the derived block keys and the session
encryption key in bare `Vec<u8>` / `std::string`. This crate wraps them in
[`secure-gate`](https://crates.io/crates/secure-gate): zeroized on drop, `[REDACTED]` in
`Debug`, reachable only inside a `with_secret` closure, and comparable *only* in constant
time — the wrapper implements `ConstantTimeEq` and no `PartialEq` at all, so the password
verifier and the package HMAC cannot be compared with `==` even by accident. If you are
decrypting documents inside a process that also holds other secrets, that difference is
the point.

**3. Detection costs nothing.** Asking *what is this file, is it encrypted, how strongly*
is the common case — routing, triage, telling a user why an upload was rejected — and it
pulls in no cryptography here, a property CI asserts rather than a claim this file makes.
`classify` also returns no `Result` and never panics, because it runs on files nothing has
validated yet.

**4. It fails closed, and it says which failure happened.** The agile `dataIntegrity` HMAC
is computed over ciphertext, so it is checked *before* any plaintext is returned;
`IntegrityPolicy::Require` is the default and `Skip` is an explicit opt-in that comes back
labelled. `WrongPassword` and `IntegrityCheckFailed` are separate variants, because telling
someone their password is wrong when the file was modified is actively misleading — and
`UnsupportedAlgorithm` is a third, so an unimplemented tuple never masquerades as either.

**5. The claims are checkable rather than assertable.** Every fixture is in the
repository with its generator beside it, so the evidence can be re-run rather than taken on
faith — `git clone` and `cargo test`, not a screenshot in a README. Where an encrypt path
exists, the bar is that real Microsoft Word opens what it wrote
and that independent implementations recover the same bytes — not that it round-trips
against itself. `CHANGELOG.md` records what was run and what each reader answered, against
the artifact's hash; the guard-deletion proof behind each individual check — delete it, watch
the named test fail, restore — is in the archived development record, and the practice is
`CLAUDE.md` § *Evidence over intent*.

Points 3 and 5 are checkable in one command each rather than taken on trust:
`cargo tree --no-default-features` is the dependency claim, and
[`CHANGELOG.md`](CHANGELOG.md) carries the acceptance gate's verdict verbatim, each reader
named and versioned, including how each one refuses a wrong password.

## Scope

[MS-OFFCRYPTO] is the boundary — the single Microsoft specification covering every
encryption format Office has shipped, including the binary-era ones.

| Family | Status |
| --- | --- |
| ECMA-376 Agile (Office 2010+) | detect ✅ · decrypt ✅ AES-128/192/256 with SHA-1/256/384/512 · encrypt ✅ AES-256/SHA-512 — accepted by all four readers of the [acceptance gate](#the-four-reader-acceptance-gate): Word 16, LibreOffice 26.2, `msoffcrypto-tool`, `office-crypto` |
| ECMA-376 Standard (Office 2007) | detect ✅ · decrypt ✅ **AES-128/SHA-1 only** · encrypt ✅ AES-128/SHA-1 — put through the same [acceptance gate](#the-four-reader-acceptance-gate) and accepted by all four |
| RC4 CryptoAPI (Office XP/2003, and what Office 16 writes into a binary file) | detect ✅ · decrypt ✅ `.doc` / `.xls` / `.ppt` under `legacy-binary` — Word and Excel byte-identical to `msoffcrypto-tool`, PowerPoint identical but for the one directory word msoffcrypto gets wrong; all three opened by Word, Excel and PowerPoint 16 with no password |
| Office 97/2000 RC4 (MD5, "Office 97/2000 Compatible") | detect ✅ · decrypt ✅ `.doc` / `.xls` under `legacy-binary` — pinned to msoffcrypto's known-answer vector and a synthetic container; no real fixture, because Office 16 refuses to write it |
| XOR obfuscation | detect ✅ · decrypt ✅ `.xls` under `legacy-binary` — the generated fixture opens in Excel 16 with its password and its decryption opens without; Word's variant (Method 2) is named and refused |
| Binary doc97 / xls / ppt | detect ✅ (named, and unencrypted ones told apart from encrypted) · decrypt ✅ under `legacy-binary`, per the three rows above |

The name follows that table. RC4 CryptoAPI and doc97 operate on binary `.doc`/`.xls`/`.ppt`,
which are not OOXML — so `ooxml-crypto`, which this crate was briefly called, would have
been wrong for roughly half its eventual surface.

**Out of scope, permanently:** password recovery and cracking.

## The four-reader acceptance gate

A round-trip through this crate's own `decrypt` proves only that the crate agrees with
itself. Everything `encrypt_ooxml` writes is instead held to four readers, two of them
shipping products and two of them implementations that share no code with this one:

| Reader | Driver | Bar |
| --- | --- | --- |
| Microsoft Word / Excel / PowerPoint 16 | COM, `tools/office_com_check.ps1` | opens, content matches, wrong password refused for the password reason (Word `0x800A1520`) |
| LibreOffice 26.2 | UNO, `tools/libreoffice_uno_check.py` | opens, content matches, wrong password refused by its verifier (a password request, aborted) |
| `msoffcrypto-tool` | CLI `-p`, and the library for the HMAC | plaintext **byte-identical**; `dataIntegrity` verifies (`verify_integrity=True`); wrong password refused |
| `office-crypto` | `examples/office_crypto_check.rs` | plaintext **byte-identical**; wrong password does not yield it |

`tools/acceptance_gate.py` runs all four and prints one line per reader. The two
implementations run in CI on every push, with two mutation runs beside them —
`--tamper`, one flipped ciphertext bit, and `--corrupt-integrity`, the two
`dataIntegrity` blobs blanked at the same length — that must each produce `GATE: FAIL`,
because a gate that cannot fail is not a gate. `msoffcrypto-tool`'s library call is the
only reader in CI that reads the HMAC at all: its own CLI leaves `verify_integrity` off
and `office-crypto` checks neither that nor the password verifier.

The two applications need an interactive Windows desktop, so they are the local gate, run
before a change to the encrypt path merges and recorded in `CHANGELOG.md` against the
artifact's SHA-256:

```text
export MSOFFICE_CRYPTO_ARTIFACT_DIR="$(mktemp -d)"   # NOT the shared system temp directory:
cargo test --no-default-features --features crypto-ops   # every session writes this same name
python tools/acceptance_gate.py "$MSOFFICE_CRYPTO_ARTIFACT_DIR/msoffice_crypto_encrypt_ooxml.docx" \
    --expect-package tests/fixtures/plain.docx --expect-text-file tests/fixtures/plain_content.txt
```

The directory matters: the test writes one fixed file name, so a gate pointed at the
shared temp directory can measure whichever build wrote it last — that has happened, and
is why the evidence is recorded against a hash rather than a path.

A pass is four lines ending `PASS` and a final `GATE: PASS`. The applications cannot hand
back the ZIP they parsed, so their bar is content, not bytes; the implementations' is
bytes.

## Security

Report privately through **Report a vulnerability** on this repository's Security tab.
[`SECURITY.md`](SECURITY.md) is the policy, and its useful half is not the address — it is
the statement of **what counts as a vulnerability here**, which is not obvious from the
outside. This crate's whole job is parsing bytes an attacker chose, so a panic on a crafted
file, a file-controlled parameter that escapes the bounds in `src/limits.rs`, or key material
reaching an error message are all vulnerabilities, where in most crates they would be bugs.

It also says what is *not*, which is what stops a report wasting a week. The clearest case:
RC4 and XOR obfuscation are broken by any modern standard — XOR is not encryption at all.
They live behind the off-by-default `legacy-binary` feature so that files written in 1997 can
be **read**, and nothing in this crate writes them.

Two properties are enforced rather than claimed: the crate contains no `unsafe`
(`#![forbid(unsafe_code)]` at the crate root, which also refuses an `#[allow]` override), and
`cargo deny` runs over licences, advisories, bans and sources on every push. The first thing
that job found was a reachable quadratic-time denial of service in this crate's XML
parser — `RUSTSEC-2026-0194`, remediated by the `quick-xml` floor in `Cargo.toml`, and
recorded under *Security posture* in [`CHANGELOG.md`](CHANGELOG.md).

## Sibling

[`odf-crypto`](https://github.com/Slurp9187/odf-crypto) does the same job for OpenDocument
— LibreOffice-faithful detection, decryption and encryption. The two crates are shaped
alike on purpose.

## Compatibility note

This crate tracks `secure-gate` 0.9.x, and **no secure-gate type crosses its public
API** — the password is `&str` and the plaintext is `Vec<u8>`, by design. A plan to put
its types on the boundary was withdrawn as a design error, so a consumer on a different
secure-gate version resolves both side by side without conflict.

## Acknowledgements

None of the following is legally required beyond what `NOTICE` records. All of it is here
because the work would have been substantially harder without them.

- **[herumi/msoffice](https://github.com/herumi/msoffice)** (BSD-3, Cybozu Labs) — the
  encryption reference. `encode.hpp` is 221 lines and `resource.hpp` is the entire
  `\x06DataSpaces` subtree in four constants.
- **[office-crypto](https://github.com/Udbhav-Muthakana/office-crypto)** (MIT) — the
  differential oracle in our dev-dependencies, and the source the RC4 families and the
  Word 97 walk were ported from.
- **[ms-offcrypto-writer](https://github.com/42triangles/ms-offcrypto-writer)**
  (MIT/Apache) — proof that the `cfb` crate builds containers Office accepts, and the
  reference for doing it.
- **[msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool)** (MIT) — the fixtures
  and the known-answer vectors that caught two real bugs in this crate's standard-encryption
  key derivation, and the source of the Excel 97 and PowerPoint 97 walks.
- **[LibreOffice](https://www.libreoffice.org/)** (MPL-2.0) — behavioural reference,
  consulted and cited, never copied.
- **[excelize](https://github.com/qax-os/excelize)** (BSD-3) — the second reading of the
  Office 2007 `EncryptionInfo` layout, consulted and cited, not derived from.
- **[cfb](https://github.com/mdsteele/rust-cfb)** (MIT) — the container layer, so that
  this crate does not hand-roll a third implementation of FAT chains and red-black
  directory trees.

## Trademarks

Microsoft, Microsoft Office, Word, Excel and PowerPoint are trademarks of Microsoft
Corporation. This project is not affiliated with, endorsed by, or sponsored by Microsoft.
It is an independent implementation of the [MS-OFFCRYPTO] file formats — published by
Microsoft under the Open Specification Promise, which is a patent promise and grants no
trademark rights — and uses those names only to describe the formats it reads and writes.

## License

`MIT OR Apache-2.0`, at your option. See [`LICENSE-MIT`](LICENSE-MIT),
[`LICENSE-APACHE`](LICENSE-APACHE) and [`NOTICE`](NOTICE).
