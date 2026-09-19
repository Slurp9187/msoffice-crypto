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
msoffice-crypto = { version = "0.1.0-rc.4", features = ["crypto-ops"] }
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
msoffice-crypto = { version = "0.1.0-rc.4", features = ["legacy-binary"] }
```

```rust
use msoffice_crypto::{classify, decrypt_binary_office, Document};

let data = std::fs::read("protected.doc")?;
if classify(&data).document == Document::WordBinary {
    let doc = decrypt_binary_office(&data, "correct horse battery staple")?;
    // `doc` is the same .doc with no password, byte for byte what msoffcrypto-tool writes
}
```

The whole feature surface, and what each one costs:

| Feature | Adds crypto? | What it enables | Dependencies |
| --- | --- | --- | --- |
| *(none — the default)* | no | `classify`, `is_cfb_office` | `cfb`, `quick-xml`, `thiserror` |
| `crypto-ops` | yes | `decrypt_ooxml`, `decrypt_ooxml_with_policy`, `encrypt_ooxml`, `encrypt_ooxml_standard`, and the `IntegrityPolicy` / `IntegrityOutcome` enums | + `aes`, `cbc`, `ecb`, `sha1`, `sha2`, `hmac`, `base64`, `rand`, `secure-gate` |
| `legacy-binary` | yes, a superset of `crypto-ops` | `decrypt_binary_office` — 97-2003 `.doc`, `.xls`, `.ppt` | + `rc4`, `md-5` |
| `cli` | yes (via `crypto-ops`) | the `msoffice-crypto` binary — see [Command line](#command-line) | + `clap`, `serde_json`, `rpassword`/`rtoolbox` (**Apache-2.0-only**) |

`rpassword` and its `rtoolbox` are the only **Apache-2.0-only** crates this crate can put
in a consumer's graph; everything else in it is dual MIT/Apache-2.0 or more permissive.
They arrive with the CLI's non-echoing password prompt, under `cli`, which is opt-in and
which no library consumer enables — `--features crypto-ops` pulls neither, and CI fails if
either reaches the default graph. It is called out because this crate is offered as
`MIT OR Apache-2.0` and the point of a dual offer is that you may take *either*: a consumer
who took the MIT half and then builds the binary still has to satisfy Apache-2.0 for those
two. `deny.toml` records the same finding beside the allow-list. (`zopfli` is
Apache-2.0-only too, but it is dev-only — it reaches `Cargo.lock` through the `zip`
dev-dependency and appears in no `cargo tree -e normal` output — so nothing a consumer
builds contains it.)

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

Scoped honestly, because point 5 below is a promise about claims: this covers the key
material *this crate holds*. Key-derived state inside a dependency is a separate question
with three answers — the `aes`, `cbc` and `rc4` key schedules are wiped because this crate
enables each crate's `zeroize` feature and CI keeps them on; the `HmacSha*` opad/ipad state
is not, because `hmac` 0.12 offers no way to; and hasher buffers hold password bytes until
`finalize` for the same reason. `SECURITY.md` says which is which. And the wrapper property
itself is enforced by construction and review rather than by a test — a test that observes
freed memory is not something this suite can honestly write, so what is checked is that
secrets are reachable only through `with_secret`, never through `expose_secret` or an
owned copy that outlives the closure.

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
against itself. `CHANGELOG.md` **in the repository** — it is not part of the published
crate — records what was run and what each reader answered, against the artifact's hash; the guard-deletion proof behind each individual check — delete it, watch
the named test fail, restore — is in the archived development record, and the practice is
`CLAUDE.md` § *Evidence over intent*.

Points 3 and 5 are checkable in one command each rather than taken on trust:
`cargo tree --no-default-features` is the dependency claim, and
[`CHANGELOG.md`](https://github.com/Slurp9187/msoffice-crypto/blob/main/CHANGELOG.md)
carries the acceptance gate's verdict verbatim, each reader named and versioned, including
how each one refuses a wrong password. It lives in the repository rather than the crate, so
a reader who has only the `.crate` should follow that link.

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

## Command line

The same three operations from a shell. The binary is behind the opt-in `cli` feature, so
no library consumer builds an argument parser to ask whether a file is encrypted:

```text
cargo install msoffice-crypto --features cli
cargo install msoffice-crypto --features cli,legacy-binary   # also opens 97-2003 .doc/.xls/.ppt
```

### `classify` — what is this file?

It cannot fail. An unencrypted package, sixteen bytes of junk and a container this crate has
never seen all exit 0, because all three are answers; only a file that cannot be *read*
exits 2.

```text
$ msoffice-crypto classify protected.docx
container:      cfb
container-read: opened
document:       ooxml-package
version:        4.4
family:         agile
encrypted:      yes
supported:      yes
integrity:      declared
key-cipher:     AES
key-hash:       SHA-512
key-bits:       256
key-block:      16
key-salt:       16
pw-cipher:      AES
pw-hash:        SHA-512
pw-bits:        256
pw-block:       16
pw-salt:        16
pw-spin:        100000
```

`--json` prints one object instead, with the same key set for every input — an unencrypted
file carries `key_data` and `password_key` as `null` rather than dropping them, so a script
can index the result without first checking whether the key is there:

```text
$ msoffice-crypto classify protected.docx --json
{"container":"cfb","container_read":"opened","data_integrity":"declared","document":"ooxml-package","encrypted":true,"family":"agile","key_data":{"block_size":16,"cipher":"AES","hash":"SHA-512","key_bits":256,"salt_size":16,"spin_count":null},"password_key":{"block_size":16,"cipher":"AES","hash":"SHA-512","key_bits":256,"salt_size":16,"spin_count":100000},"supported":true,"version":"4.4"}
```

### `decrypt` — and it says what it verified

The output path is derived from the input unless `-o` gives one, an existing file is never
overwritten without `--force`, and the write is a temporary file renamed over the target so
an interrupted run cannot leave a half-written `.docx` that looks complete. The `integrity:`
line goes to stderr after every successful decrypt, including after `--integrity skip`, so
`-o -` into a pipe is unaffected and nobody holds unauthenticated bytes without being told:

```text
$ msoffice-crypto decrypt protected.docx --password-env MSOFFICE_CRYPTO_PASSWORD
msoffice-crypto: wrote protected.decrypted.docx
integrity: verified
```

`--integrity` takes `require`, `require-where-defined`, `verify-if-present` or `skip`. The
default is not typed into the help text: it is rendered from the library's own
`IntegrityPolicy::default()`, which has already moved once.

A file with nothing to decrypt is refused rather than copied:

```text
$ msoffice-crypto decrypt plain.docx --password-env MSOFFICE_CRYPTO_PASSWORD
msoffice-crypto: plain.docx: not encrypted; there is nothing to decrypt; nothing was written.
$ echo $?
5
```

### `encrypt`

`--format agile` is the default and writes what Office 2010 and later write, `dataIntegrity`
HMAC included. `--format standard` writes the Office 2007 format, which defines no integrity
element at all — and says so rather than leaving it to folklore:

```text
$ msoffice-crypto encrypt report.docx --password-env MSOFFICE_CRYPTO_PASSWORD
msoffice-crypto: wrote report.encrypted.docx
integrity: declared

$ msoffice-crypto encrypt report.docx --format standard -o report-2007.docx --password-env MSOFFICE_CRYPTO_PASSWORD
msoffice-crypto: wrote report-2007.docx
integrity: not-applicable
msoffice-crypto: Office 2007 standard encryption defines no dataIntegrity element: a file modified after it was encrypted decrypts without complaint. `--format agile` writes one.
```

What the binary writes is held to the same
[four-reader acceptance gate](#the-four-reader-acceptance-gate) as the library's output.

### Passwords never come from `argv`

`argv` is world-readable in a process listing for the lifetime of the run — `ps aux` on
Linux, the command-line column in Task Manager on Windows. **There is deliberately no
`--password VALUE` flag, and adding one later would be a regression rather than a feature.**
`--password` is registered hidden, so reaching for it is answered with that reason instead
of clap's generic "unexpected argument". Exactly one source may be given; two is a usage
error rather than a silent precedence win:

| Flag | Source | For |
| --- | --- | --- |
| `--password-env NAME` | that environment variable | scripts, CI |
| `--password-file PATH` | first line of the file, one trailing CR-LF or LF stripped | secret managers, `--password-file /dev/stdin` |
| `--password-stdin` | one line from stdin | pipelines |
| *(none)* | a non-echoing terminal prompt | interactive use |

`--password-env` takes the variable's **name**, so `MSOFFICE_CRYPTO_PASSWORD` is the obvious
argument — and naming it is the only way this tool reads it. A password that applies without
being asked for is how the wrong file gets decrypted in a loop. With no source and no
terminal, the command fails naming the flags that exist rather than blocking on a prompt
nobody can see.

### Exit codes

A CLI that returns 1 for everything cannot be scripted.

| Code | Meaning | Maps from |
| --- | --- | --- |
| 0 | success | — |
| 1 | usage error | bad flags, missing operand, two password sources, output exists without `--force` |
| 2 | I/O error | unreadable input, unwritable output, `Error::Io` |
| 3 | not a Microsoft Office file | `Error::NotACfbFile` on an input `classify` also calls `Container::Unknown` |
| 4 | wrong password | `Error::WrongPassword` |
| 5 | refused: nothing to do | decrypt of an unencrypted file, encrypt of an already-encrypted one, `Error::NotEncrypted` |
| 6 | malformed or hostile file | `MissingStream`, `XmlParse`, `BadParameters`, `CipherError` |
| 7 | internal invariant violated | `RandomSource` |
| 8 | **integrity** | `IntegrityCheckFailed`, `IntegrityElementMissing`, `IntegrityUnavailable` |
| 9 | **unsupported encryption** | `UnsupportedEncryptionVersion`, `UnsupportedAlgorithm`, `Family::Unsupported`, and a legacy family in a build without `legacy-binary` |

8 is not folded into 4 or 6, and 9 is not folded into 5, for the same reason the library
keeps `WrongPassword` and `IntegrityCheckFailed` apart: at a process boundary the number is
all a script gets, and "try again", "this file was changed after it was encrypted" and "this
build cannot do that — rebuild with `--features cli,legacy-binary`" are three different next
steps. One is a retry, one is a support ticket, one is an incident.

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
recorded under *Security posture* in
[`CHANGELOG.md`](https://github.com/Slurp9187/msoffice-crypto/blob/main/CHANGELOG.md).

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
