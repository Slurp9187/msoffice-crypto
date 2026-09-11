Status: Pre-release — the first published version has not been cut yet

# Changelog

Entries are keyed by version, newest first, and dated on the day the version was published.

**The pre-publication development record is not here.** This crate was built across 14
issues and 12 pull requests in a private repository, whose changelog ran to 3,397 lines of
day-by-day reasoning — the right artifact while the work was happening, and the wrong one
for a reader who has just run `cargo add`. That repository is archived and holds it.

What survives that move is in two places, deliberately:

- **[`docs/design/development-record.md`](docs/design/development-record.md)** — the decisions. What was
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

### Release process

Version headings, newest first: `## vX.Y.Z — unreleased` while the work is in flight, and the
ISO date substituted the moment that tag is cut. **The date is the release marker**, not a
note about when the work happened — git records that, and a typed date drifts. This crate's
own evidence: five entries in the archived pre-publication changelog were stamped in UTC on a
UTC-7 machine and read a day into the future.

Entries carry a date only when the date is part of the claim. A gate verdict against
particular versions of four external readers needs one, because it tells you how stale the
observation is; a rename does not, because git already knows.

Both invariants — the top heading matches `Cargo.toml`, and it is dated if and only if that
tag exists — are check G of `tools/audit_claims.py`, which the `prose` CI job runs on every
push. All four of its failure modes were proved by causing them. That job now checks out with
`fetch-depth: 0`, because `actions/checkout` fetches no tags by default and every dated
heading would otherwise look untagged the moment a release was cut.

`docs/RELEASING.md` gained the step that dates the heading and tags the commit; it previously
went from the tarball straight to `cargo publish` and never mentioned a tag at all. That is a
gap for a crate arguing its claims are checkable: the `.crate` is immutable, but without a tag
a consumer has no ref to check out and re-run the suite against.

The rule lives in `.claude/skills/changelog-protocol/SKILL.md`, adapted from a sibling
project's protocol.

### API shape, settled by the first consumer

`decrypt_ooxml_with_policy` returns a `#[non_exhaustive] struct Decrypted { package,
integrity }` rather than the `(Vec<u8>, IntegrityOutcome)` tuple it returned while nothing
had wired against it. Changed on a consumer's evidence rather than on taste: the first crate
to integrate prototyped the call on a branch and reported back what the tuple did at a real
call site.

Two reasons, in the order that decided it.

**Arity.** A tuple freezes the number of facts at publication. There are two here and a
plausible third — which cipher a file actually used, which spec branch it parsed as — and
adding one to a tuple breaks every caller, while adding a field to a `#[non_exhaustive]`
struct does not. `#[non_exhaustive]` is free before the first publish and unavailable
afterwards without that same break, so the window for this was exactly now.

**Prominence.** `IntegrityOutcome` is not a detail attached to the bytes; for a consumer
that stores what it decrypts it is the predicate deciding whether the bytes may be kept.
The reported shape was:

```rust
let (package, outcome) = decrypt_ooxml_with_policy(data, password, IntegrityPolicy::Require)
    .map_err(|e| ProtocolError::Generic(format!("Office decryption failed: {e}")))?;
```

Destructuring and mapping the error in one expression puts the security-relevant binding on
the left of a line whose right-hand side is about error handling, where it is the least
prominent thing in the statement. As a field it reads as `decrypted.integrity` — named at
every call site and in every review diff. This crate's own `decrypt_ooxml` was the
demonstration of the hazard: it is the one place that consumed the tuple, and it discards
the outcome with `|(package, _)|`. Correct *there*, because that wrapper is the "I do not
need to ask" path — which is what made it the wrong default shape for everyone else.

There is deliberately **no** `require_verified()` helper, though one was floated.
`IntegrityPolicy::Require` already refuses unauthenticated plaintext before any work is
done, and a second gate after the fact would have to invent an error variant for "the policy
allowed this but I changed my mind", which is not a fact about the file.

The same consumer reported that a missing `crypto-ops` feature fails as `cannot find type
Error`, on a line that reads as a plumbing mistake rather than a missing feature — `Error`
is gated with the functions that return it. The crate docs now name that error text. A
`compile_error!` was considered and rejected: the condition would be "no cryptography
features", which is the detection-only build — supported, and the default.

### Evidence

Every figure below was measured, not asserted. The commands that produce them are in
[`docs/RELEASING.md`](docs/RELEASING.md).

#### The four-reader acceptance gate

`encrypt_ooxml`'s output is put in front of two shipping applications and two independent
implementations. The applications parse the package and never hand the ZIP back, so their
bar is *opens, content matches, and a wrong password is refused for the password reason*;
the implementations' bar is byte-identity with the original.

Run against this release's own artifact, written into a private directory by this tree's
build — 41,984 bytes, SHA-256
`c279812c8fc0f44bc0d1b7402451c27bcafb71ca1cdc44608483874629abde9c`:

```
office         PASS  Word 16.0 build 16.0.19127: OPENED, content matches plain_content.txt
                     wrong password REFUSED 0x800A1520 (container, header, XML and KDF all accepted)
libreoffice    PASS  LibreOffice 26.2.1.2: OPENED, content matches plain_content.txt
                     wrong password REFUSED -- the verifier rejected it and LibreOffice asked again
msoffcrypto    PASS  msoffcrypto-tool 6.0.0: byte-identical to plain.docx (36,678 bytes)
                     dataIntegrity HMAC verifies; wrong password InvalidKeyError
office-crypto  PASS  office-crypto 0.3: byte-identical to plain.docx (36,678 bytes)
GATE: PASS (4 of 4 readers ran; 0 not selected)
```

Word's `0x800A1520` is worth reading closely: it is *password incorrect*, which means Word
walked the container, the header, the `EncryptionInfo` XML and the key derivation and failed
only at the verifier. A malformed file fails earlier and differently.

`msoffcrypto-tool` is the only reader here that verifies the `dataIntegrity` HMAC, and the
gate drives it through the library rather than the CLI for exactly that reason — the CLI
leaves verification off by default, so a `dataIntegrity` regression would otherwise pass
unnoticed.

**The gate is proven to fail when it should**, and both proofs run in CI on every push with
the exit code inverted. `--tamper` flips one bit in the ciphertext body: both implementations
return the wrong bytes and the gate fails. `--corrupt-integrity` rewrites the `dataIntegrity`
blobs as same-length base64, which is the sharper case — `msoffcrypto-tool` decrypts to
*byte-identical* plaintext and still refuses, `Payload integrity verification failed`, while
`office-crypto` accepts it, because only one of the two checks the tag at all. A gate that
selected only the second reader would have called that file good.

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
- **No dependency's `Display` reaches a message built from the document.**
  `Error::XmlParse` forwarded
  `quick_xml::Error`'s `Display` from four call sites, three of which run on attribute
  *values* — `saltValue`, `encryptedKeyValue` and the two verifier blobs. quick-xml quotes
  the text between `&` and the next `;` of whatever it is unescaping, so a crafted
  `encryptedKeyValue` put its own text into the error, bounded only by the 1 MiB
  `ENCRYPTION_INFO_READ_CAP`. Measured before the fix: an attribute holding a 4608-byte
  entity produced a 4609-byte message quoting all of it. Not key material — the attacker
  supplies the text — but unbounded attacker-chosen content in an error string is precisely
  what `UnsupportedAlgorithm` truncates to 32 characters and says it does. quick-xml and
  base64 failures are now classified into fixed descriptions by exhaustive matches, so a
  variant added upstream is a compile error rather than a silent forward, and `source()` is
  left `None` rather than holding the foreign error, which would reopen the same conduit
  through `source()` and the derived `Debug`. Guarded by
  `a_hostile_entity_in_an_attribute_value_never_reaches_the_error_message`, with a
  well-formed-value control; reverting the classifier fails it.

  Found by the downstream consumer reading this crate's source, the same day they shipped a
  fix for the identical shape in their own tree — `rusqlite::Error::SqlInputError`'s
  `Display` prints the failing SQL, and a `#[from]` variant rendered with `{0}` had carried
  a live SQLCipher key into a UI string. The rule generalised from it, and adopted here: an
  error-hygiene rule governs the strings *this* crate writes, never the strings its
  dependencies write.

  Two variants still forward a foreign `Display`, and the difference from `XmlParse` is the
  reason rather than an oversight. `Error::RandomSource` carries the RNG's sentence because
  it names an *environment* failure — no `getrandom` in the sandbox, an exhausted descriptor
  table — which is the entire diagnostic value of the variant, and because on a failure
  there is nothing generated to disclose; it is truncated to 200 characters all the same,
  since its constructor is generic over any `Display` and the length is therefore a property
  of the caller rather than of anything checked. `Error::Io` carries `std::io::Error`'s,
  audited against the only producers on these paths: `cfb` 0.14.0 interpolates lengths and
  fixed strings and never a stream name or a file byte. Both are stated in the error type's
  own docs as a three-row table, so the next reader does not have to re-derive which of the
  three is which.

[`SECURITY.md`](SECURITY.md) states what counts as a vulnerability in a crate whose entire
job is parsing bytes an attacker chose — and, as usefully, what does not.

[MS-OFFCRYPTO]: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/
[MS-CFB]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/
[MS-PPT]: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/
