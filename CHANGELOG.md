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

## v0.1.0-rc.4 — unreleased

### Evidence for this release

The four-reader acceptance gate, run on this machine 2026-09-20 against artifact SHA-256
`1d9c44ef565692883ca60a72f3fffda08c0b9cd5b0c646a21ef5675e4a04ff6e` (41,984 bytes), written
into a private directory rather than shared system temp:

```
office         PASS  Word 16.0 build 16.0.19127: OPENED, content matches | WRONG PASSWORD REFUSED 0x800A1520
libreoffice    PASS  LibreOffice 26.2.1.2: OPENED, content matches | WRONG PASSWORD REFUSED (verifier)
msoffcrypto    PASS  msoffcrypto-tool 6.0.0: byte-identical to plain.docx | dataIntegrity HMAC verifies
office-crypto  PASS  office-crypto 0.3: byte-identical to plain.docx
GATE: PASS (4 of 4 readers ran; 0 not selected)
```

The standard writer's artifact was gated in the same run — SHA-256
`dbcdf9032ee80c81a87f7a82d18b3f3760498918262d4c79418c512ffe9365c2` (40,960 bytes), also
`GATE: PASS` 4 of 4 — and it is the direct proof of the gate fix below, because its
`msoffcrypto` line now reads `decrypted; NO dataIntegrity element to verify
(verify_integrity is inert here)` where every previous release printed the agile
HMAC-verifies sentence for it.

**Both artifacts are byte-identical to the committed goldens** (41,984 / `b4cc009e…` and
40,960 / `491298746c…`), which is the claim that matters for a release whose headline change
is a new refusal: what this crate writes did not move.

Full matrix green in all five feature columns — `cargo test`, `cargo clippy -D warnings`,
`cargo fmt --check`, both `cargo doc` runs under `RUSTDOCFLAGS="-D warnings"`, `cargo deny`
over licences, advisories, bans and sources, and `tools/audit_claims.py`. Every column
reported **0 ignored**, so no corpus fixture is missing.

### The tuple × reader grid — plan slice 10, and the finding it surfaced

Every writable agile `(hash, keyBits)` tuple, three `saltSize`s at the default tuple (one a
deliberate non-multiple of 16, the case `fit_iv` exists for), the three standard `AlgID`s, and
the default agile tuple over `.xlsx`/`.pptx` — eighteen files, each written into
`artifacts/tuples-2026-09-20/` (a durable, gitignored directory, not the `MSOFFICE_CRYPTO_-
ARTIFACT_DIR` the automated gate consumes and forgets) by a new test beside
`encrypt_ooxml_writes_the_artifact_the_external_readers_are_run_on`, which is untouched. The
default artifact is asserted byte-identical to the 41,984 / `b4cc009e…` golden inside that
test, so the one file the owner is most likely to open by hand also covers the regression.
`MANIFEST.md` in that directory carries, per file, the tuple in words, the password
(`testpass`), the SHA-256, the expected content, and what a refusal would mean.

Run through `tools/acceptance_gate.py` over all four readers. **Word is the reference for this
format, never a reader with a limitation**: its column holds only `PASS`, `FAIL` or `NOT RUN`,
and a refusal there is filed as `FAIL` and blocks — the two-case procedure is our own bug
(the default assumption) or a documented Word divergence, decided by re-deriving the bytes
from the cited clause, never by comparing against another program.

| tuple | Office (Word / Excel / PowerPoint) | LibreOffice | msoffcrypto-tool | office-crypto |
| --- | --- | --- | --- | --- |
| SHA-1 / 128 | PASS | PASS | REFUSED-BY-READER¹ | REFUSED-BY-READER² |
| SHA-256 / 128 | PASS | REFUSED-BY-READER³ | PASS | REFUSED-BY-READER² |
| SHA-256 / 192 | PASS | REFUSED-BY-READER³ | REFUSED-BY-READER⁴ | REFUSED-BY-READER² |
| SHA-256 / 256 | PASS | REFUSED-BY-READER³ | PASS | REFUSED-BY-READER² |
| SHA-384 / 128 | PASS | PASS | PASS | REFUSED-BY-READER² |
| SHA-384 / 192 | PASS | PASS | REFUSED-BY-READER⁴ | REFUSED-BY-READER² |
| SHA-384 / 256 | PASS | REFUSED-BY-READER³ | PASS | REFUSED-BY-READER² |
| SHA-512 / 128 | PASS | REFUSED-BY-READER³ | PASS | NOT RUN⁵ |
| SHA-512 / 192 | PASS | REFUSED-BY-READER³ | REFUSED-BY-READER⁴ | NOT RUN⁵ |
| SHA-512 / 256 (default) | PASS | PASS | PASS | PASS |
| `saltSize` 8/8 | **FAIL** | **FAIL** | REFUSED-BY-READER⁶ | NOT RUN⁵ |
| `saltSize` 17/17 (non-multiple) | **FAIL** | PASS | REFUSED-BY-READER⁶ | NOT RUN⁵ |
| `saltSize` 32/32 | PASS | PASS | REFUSED-BY-READER⁶ | NOT RUN⁵ |
| default tuple, `.xlsx` | PASS | PASS | PASS | PASS |
| default tuple, `.pptx` | PASS | PASS | PASS | PASS |
| standard AES-128 | PASS | PASS | PASS | PASS |
| standard AES-192 | PASS | REFUSED-BY-READER⁷ | PASS | NOT RUN⁸ |
| standard AES-256 | PASS | REFUSED-BY-READER⁷ | PASS | NOT RUN⁸ |

**Office 16/18 PASS, 2 FAIL. LibreOffice 9 PASS, 8 REFUSED-BY-READER, 1 FAIL. msoffcrypto-tool
11 PASS, 7 REFUSED-BY-READER. office-crypto 4 PASS, 7 REFUSED-BY-READER, 7 NOT RUN.** One row —
`saltSize` 8/8 — has zero passes: no reader opens it, not only Word. Recorded as a fact rather
than a reason to stop writing that `saltSize`, per the plan's own rule for a zero-pass row —
though see the finding below for why it should not yet be written at all.

¹ `msoffcrypto/method/ecma376_agile.py:490,493` (installed 6.0.0): `verify_integrity` keys the
HMAC from the **whole** AES-CBC-decrypted `encryptedHmacKey`/`Value` blob, with no truncation
to `hashSize` first — unlike its own writer (`generate_integrity_parameter`, which keys the
HMAC from the pre-pad, `hashSize`-length salt). SHA-1's 20-byte digest pads to a 32-byte AES
block, and the twelve zero bytes it never strips corrupt the comparison. `file.decrypt()` with
no integrity flag recovers the package byte-identical; only the extra `verify_integrity=True`
leg this gate also runs fails. Already named at `docs/design/development-record.md:315-317`
(same function, an older line number).<br>
² `office-crypto/src/lib.rs:29` (`docs/design/msoffice-crypto-format-history.md:107-109`): only
the SHA-512 agile path is implemented; every other hash returns `DecryptError::Unimplemented`,
verbatim in this run's own output (`Unimplemented("SHA1"/"SHA256"/"SHA384")`).<br>
³ `AgileEngine.cxx:574-612` (`docs/design/msoffice-crypto-format-history.md:118`): LibreOffice
accepts exactly four agile tuples — AES-256/SHA-512, AES-128/SHA-1, AES-128/SHA-384,
AES-192/SHA-384 — and refuses every other `(hash, keyBits)` pair outright, independent of
whether the file is well-formed. Predicted by the plan before this run.<br>
⁴ `docs/design/development-record.md:324`, "`msoffcrypto-tool` cannot read its own AES-192
output" — confirmed here on **our** AES-192 output too, at all three hashes:
`InvalidKeyError: The file could not be decrypted with this password`.<br>
⁵ office-crypto 0.3 exits 101 (a panic, not its documented refusal code 3) — the same defect
class already on record below for standard AES-192/256: fixed-length `generic_array` slices
(`office-crypto/src/crypto.rs`) that assume the one key/salt shape its own fixtures ever
varied.<br>
⁶ `msoffcrypto/method/ecma376_agile.py:459` (`verify_password`) hands the raw `saltValue`
straight to `cryptography`'s `modes.CBC(iv)`, which requires an exact 16-byte IV — no pad, no
truncate, so any `saltSize != 16` raises `ValueError: Invalid IV size (N) for CBC` before the
password is even tried. Proven a reader limitation rather than evidence about the file by
`saltSize` 32: Word and LibreOffice both open that file cleanly, and msoffcrypto still refuses
it.<br>
⁷ `Standard2007Engine.cxx:43,319`: "only support key of size 128 bit"; refuses any `algId`
other than `ENCRYPT_ALGO_AES128` outright.<br>
⁸ Same defect class as ⁵, already on record: `generic-array-0.14.7/src/lib.rs:572: assertion
left == right failed, left: 32, right: 16`.

**The finding this run existed for, and it was ours.** `saltSize` 8 and 17 were refused by
**real Word** — `0x800A1520`, "the password is incorrect", on the right password. A Word
refusal is never a reader limitation, so the two-case procedure applies and the default
assumption is our own bug. It was.

The three-artifact spread narrowed it before anyone read the clause: `saltSize` 17's IV is a
clean truncation (17 → 16), the identical operation `saltSize` 32's IV performs, and Word
opens 32 while refusing 17 — so the discriminator is not `fit_iv`. What 8 and 17 share and 32
does not is `roundUp(saltSize, blockSize) != saltSize`: whether the verifier-input blob needs
a `0x00` tail at all.

**The bug: this crate hashed the padded blob.** §2.3.4.13's `encryptedVerifierHashValue`
step 1 says "Obtain the hash value of the random array of bytes generated in step 1 of the
steps for encryptedVerifierHashInput", and that array is `saltSize` bytes; the `0x00` pad to a
block multiple is step 3, applied when the array is *encrypted*, after the hash. The writer
hashed the whole padded buffer, `agile::verify_password` digested the whole decrypted blob to
match, and the synthetic-file helper in `agile.rs`'s own tests built its fixtures the same way.
**Three places agreeing with each other and disagreeing with the format**, which is exactly
why no test here could see it: `a_caller_chosen_tuple_round_trips_through_the_public_reader`
round-trips `saltSize` 8, 9, 24 and 40 through this crate's own decrypt and passes. Invisible
at every multiple of 16 — which was every salt size that existed before this release made it a
caller's choice.

All three are fixed. The new guard,
`the_verifier_hash_covers_the_salt_sized_array_and_not_its_padding`, asserts against a digest
computed **in the test** from the spec's sentence and never through this crate's reader: a test
that decrypted the blob and re-digested it the way `verify_password` does would have agreed
with the bug. It carries the negative too, so a revert fails by meaning rather than by a
number.

**The read half was shipped.** rc.2 and rc.3 refuse a *conforming* file from another writer
whose `saltSize` is not a multiple of `blockSize`, reporting `WrongPassword` on a correct
password. Narrow — no common writer emits such a salt — but it is the same class as the
`spinCount` ceiling above: an owner locked out of their own document by this crate's error, not
the format's.

Worth stating plainly what found it. Not the type system, not 225 tests, not five clippy
columns, not the four-reader gate's automated legs — a human opening files in Word. The
artifacts at non-block-multiple salt sizes have been regenerated since the fix.

This also supersedes, with real measurement, the "Word, LibreOffice and the interactive open
path are not measured at AES-192 or AES-256" sentence under "Standard encryption writes all
three key sizes" below: both now open in real Word, this run, for the first time.

No leaked WINWORD, EXCEL, POWERPNT or soffice from this run's own opens. One stray `EXCEL.EXE`
(`Book1`, already running before this session started) blocked the first Excel pass behind
`office_com_check.ps1`'s own guard clause, verbatim: *"EXCEL is already running; close it
first -- a live instance turns opens into dialogs this script cannot dismiss, and the watcher
would stop it."* Closed, and the row above is the clean re-run.

### The agile write tuple is the caller's, within the range [MS-OFFCRYPTO] defines

`encrypt_ooxml_with_params(package, password, EncryptParams { .. })` joins `encrypt_ooxml`,
which is now one line delegating with `EncryptParams::default()` — so the default path and
the parameterised path are the same code as a fact rather than a claim.

**The reason is fidelity, not a feature request.** §2.3.4.10 defines agile encryption as a
parameter space; this crate wrote one point in it. The read path has honoured four hashes and
three key sizes since GH #11/#13, so the crate could *read* far more of the format than it
could *write*, an asymmetry with no basis in the spec. No consumer asked for this and none is
waiting on it.

**`keyBits` and `saltSize` are two fields each, and that is the spec's shape rather than a
convenience.** §2.3.4.13 step 1 sizes the package key from `Encryptor.KeyData.keyBits`;
§2.3.4.11 sizes the password-derived key-encrypting key from `PasswordKeyEncryptor.keyBits`.
Explicitly namespaced, different quantities, and no sentence anywhere makes them equal. One
field would have encoded a constraint the spec denies and made an AES-256 KEK wrapping an
AES-128 package key inexpressible — a file Word reads. `hash` stays one field because
§2.3.4.10 *does* carry that MUST, and so does `cipherAlgorithm`; that asymmetry is the
evidence the split was derived rather than chosen.

**Ten writable combinations, not twelve.** `keyBits / 8` must fit the named hash's digest, so
SHA-1's 20 bytes admit 128 alone — `(Sha1, 192)` and `(Sha1, 256)` are refused as
`UnusableCombination`. All ten are round-tripped through the public reader under
`IntegrityPolicy::Require`, each with a wrong-password control.

**One length was wrong and is now right.** `encryptedKeyValue` is
`roundUp(keyData.keyBits / 8, blockSize)`, not `keyBits / 8`: AES-192 puts a 24-byte key in a
32-byte blob with a zero tail. The reader has always asserted this (`agile.rs:1160-1170`) and
`agile_aes192_sha384.docx` carries it, so the writer would have refused its own output the
moment a caller chose 192.

**And one step was missing entirely.** The three password blobs' CBC IV is the salt *fitted*
to `blockSize` — padded with `0x36` if short, truncated if long (§2.3.4.12). The reader has
always done this; the writer passed the raw salt. At the only salt size that existed, 16, the
fit is the identity, so the two agreed by coincidence and nothing could see the difference
until the length became a caller's choice.

`EncryptParams` is deliberately **not** `#[non_exhaustive]`: that attribute forbids
struct-expression syntax from another crate, and `..Default::default()` is struct-expression
syntax. The update form is the compatibility contract instead, and
`tests/encrypt_entry_points.rs` — a separate crate — is the compile-time proof.

**Writable is not the same as opened.** A `saltSize` that is not a multiple of 16 changes the
pad on `encryptedVerifierHashInput`, and no external reader has been measured on one. Word is
documented rejecting wrong pad *bytes* twice elsewhere in this format. That gap is recorded in
the rustdoc rather than papered over.

### Standard encryption reads AES-192 and AES-256, which it refused by name

[MS-OFFCRYPTO] §2.3.2 defines three AES `AlgID`s for the Office 2007 format —
`0x0000660E` (AES-128), `0x0000660F` (AES-192), `0x00006610` (AES-256) — and §2.3.4.5
repeats all three against the three `KeySize` values `0x00000080` / `0x000000C0` /
`0x00000100`. `standard::require_aes_128` returned `UnsupportedAlgorithm` for the latter
two before the header had finished parsing, so a conforming document using either was
unopenable: **the owner of that file was locked out by this crate's choice, not by the
format's.** The refusal was then cited as evidence the format offered no choice of key
size, which is the decision restated as its own justification.

The read path now takes all three. `require_aes_128` becomes `aes_key_bits`, which returns
the key length its two cipher fields name, and `parse_encryption_info` requires `KeySize`
to be one of the three §2.3.4.5 enumerates **and** to agree with the `AlgID` beside it —
a header pairing AES-128's identifier with 256 bits describes no cipher the format defines,
and taking either field alone would silently pick a winner. `limits::STANDARD_KEY_BITS_AES128`
becomes `STANDARD_KEY_BITS_AES: [u32; 3]` and moves from the **cipher** row of the
provenance table to the **spec** row: agile's `ST_KeyBits` states `minInclusive="8"` and no
maximum so its set of three comes from AES, while here the format enumerates it.

**Nothing else on the path had to change, and the derivation is the evidence.** §2.3.4.7
fixes `H` at SHA-1 and the iteration count at 50 000, neither of which is a file field, and
the only key-size-dependent step in the whole KDF is step 6 — "the first
`cbRequiredKeyLength` bytes of X3" — with step 1 capping that length at 40, inside which
AES-256's 32 sits. The three keys are prefixes of one 40-byte ladder output, which is now
asserted rather than assumed. The ECB helpers were monomorphised on `Aes128`; they dispatch
on key length now, the same shape `agile::aes_cbc_decrypt` already used. `classify` needed
no change at all — it matched all three `AlgID`s onto `CipherAlgorithm::Aes` and passed
`KeySize` through from the start, which had the detector reporting a supported AES-256 file
that the decryptor then refused by name.

**The default write path is unchanged and still emits AES-128** — what Office writes — so
both goldens are untouched (41,984 / `b4cc009e…` and 40,960 / `491298746c…`). The other two
are now writable through a second entry point, which is the next entry; the interop
measurement against real Office that reading did not need is still owed, and is recorded
there as an evidence gap rather than implied away.

**Tests.** There is no fixture and Office cannot produce one: it writes AES-128 for this
format. So the containers are built at runtime in the style of `malformed_input.rs`, from
the reader's own primitives inverted as §2.3.4.8 describes a writer doing. Deleting the
AES-192/256 arms fails five tests, among them
`all_three_aes_key_lengths_decrypt_end_to_end` ("AES-192 is [MS-OFFCRYPTO] 2.3.2's
0x0000660f and must parse") and `standard_aes192_and_aes256_reach_the_password_check`;
deleting the agreement check fails `key_size_disagreeing_with_the_alg_id_is_refused_by_name`
alone. Deleting the enumeration check failed **nothing** on the first attempt — every row
of that test named an `AlgID` that carries its own key length, so the agreement check
refused the value first. The sweep now includes the shipped fixture's own spec-forbidden
`fAES` + RC4-`AlgID` pair, the one shape where `KeySize` is the file's sole statement of the
key length and this check is therefore the only guard; with it, deleting the check fails at
`KeySize 0 must be refused`.

### Standard encryption writes all three key sizes, and the caller chooses which

`encrypt_ooxml_standard_with_key_bits(package, password, key_bits)` joins
`encrypt_ooxml_standard`, which is now one line delegating with 128 — the same shape
`encrypt_ooxml` took over `encrypt_ooxml_with_params`, and for the same reason: "the
default path and the parameterised path are the same code" is a fact someone can check by
reading one line rather than a claim about two argument lists.

**The read half above was only half the asymmetry.** With it, the crate read all three
`AlgID`s [MS-OFFCRYPTO] §2.3.2 defines for this format and wrote one of them, which is the
same gap the plan opened over the agile writer: a defined parameter space implemented at a
single point. §2.3.4.5's header table enumerates `KeySize` `0x00000080` / `0x000000C0` /
`0x00000100` against the matching `AlgID`, and a conforming writer may emit any row.

**`EncryptParams` was not reused, and no type was added.** This format has exactly one
writer-settable field. `AlgIDHash` is SHA-1 by §2.3.4.5, the 50 000 iterations are fixed by
§2.3.4.7 and are not a field in the file at all, §2.3.3 fixes the salt and verifier
lengths, and AES-ECB fixes the block — so five of `EncryptParams`' six fields name nothing
this header has, and offering them would be an affordance shaped by the other format. A
one-field struct was rejected for the same reason the other way round: it buys
extensibility a format of MUSTs cannot use, and (per the plan's finding 1) it would have to
ship without `#[non_exhaustive]` for `..Default::default()` to work. The argument, with the
table of what fixes each field, is in `src/standard_encrypt.rs`'s header.

**`AlgID` and `KeySize` are written as one statement.** A private `AesKeySize` holds the
pair from a single table over `standard`'s own `AlgID` constants, so the mismatched header
§2.3.2 forbids — and that this crate's reader refuses by name — is not expressible from the
writer, and `write_encryption_info` stays infallible.

**A refused key size is `Error::EncryptParams`, and it names a new `EncryptParam::KeySize`
rather than borrowing `KeyBits`.** They are different fields under different clauses: the
agile `keyBits` is an XML attribute typed by `ST_KeyBits` (§2.3.4.10 — `minInclusive="8"`,
a multiple of 8, **no maximum**), while this is a `u32` in the binary `EncryptionHeader`
that §2.3.4.5 enumerates. The `Display` prints `EncryptionHeader.KeySize`, so a consumer
forwarding the sentence names the field its user would find in the file.

The consequence of that difference is that **every refusal here is
`OutsideSpecRange` and `UnsupportedByCipher` is unreachable on this path**, the opposite of
the agile one where both fire. `ST_KeyBits` is generic across ciphers, so there the format
and AES are two authorities with different reach and 512 satisfies one while failing the
other; §2.3.4.5 names AES for this stream and then enumerates AES's own three sizes, so
here the two sets are one set and the format states it first. Reporting 64 as a cipher
limitation would assert that this header may carry a 64-bit key, which §2.3.4.5 denies —
the typed lie the problem enum's split exists to prevent, pointed the other way. §2.3.2's
RC4 (`0x28`–`0x80`) and `0x00000000` rows are not a counter-example: they are what that
field may hold in *some* `EncryptionHeader`, and §2.3.4.5 governs this one.
`EncryptParamProblem::OutsideSpecRange`'s `Display` consequently stopped naming §2.3.4.10,
which would have cited the agile schema at a caller who never touched it; the section
numbers moved into the per-parameter docs, where they can be right for each.

**Neither golden moved** (41,984 / `b4cc009e…` and 40,960 / `491298746c…`). The default is
`DEFAULT_KEY_BITS = 128`, the salt is 16 bytes at every key size (§2.3.3), and the two
draws and their sizes are unchanged — so the AES-128 byte stream is what it was, and
`the_default_key_size_is_aes_128_and_both_entry_points_write_it` pins the default by name
so a moved default fails there rather than only in a digest.

**Evidence.** Deleting the `Err` arm of `AesKeySize::new` fails two named tests:
`a_key_size_the_format_does_not_define_is_refused_before_the_password` reports
`0 must be (KeySize, OutsideSpecRange) naming 128, got: BadParameters("AES-ECB takes a 16-,
24- or 32-byte key; this file's parameters produced 0")` — the refusal falling through to
the cipher layer as the wrong error type, after the salt was drawn and the 50 000-round KDF
had run — and `a_refused_key_size_consumes_no_rng_draw` fails on the error type for the
same reason. The three sizes round-trip through `decrypt_ooxml_with_policy` with a
wrong-password control each; `classify` reads the `key_bits` back and the `AlgID` is
asserted against the byte offset §2.3.4.5's layout gives it, both against a table typed from
the specification rather than from the writer's own constants.

**One independent implementation reads both new sizes; the shipping readers are not
measured.** Run 2026-09-20 on this machine against artifacts this change wrote
(`--readers msoffcrypto,office-crypto`, plaintext `plain.docx`):

```
AES-192  msoffcrypto    PASS  msoffcrypto-tool 6.0.0: byte-identical to plain.docx (36,678 bytes)
         office-crypto  NOT RUN  office-crypto 0.3 panicked (exit 101)
AES-256  msoffcrypto    PASS  msoffcrypto-tool 6.0.0: byte-identical to plain.docx (36,678 bytes)
         office-crypto  NOT RUN  office-crypto 0.3 panicked (exit 101)
```

The panic is `generic-array-0.14.7/src/lib.rs:572: assertion left == right failed, left:
32, right: 16` — `office-crypto` 0.3 reads `KeySize` out of the header and hands the
resulting 32-byte key to a cipher monomorphised on AES-128. **That is a defect in that
reader, not a verdict on the file**: `msoffcrypto-tool` decrypts the same bytes to
`plain.docx` exactly, and it is the same failure mode this crate's own `check_aes_key`
exists to prevent (`src/standard.rs`) — a length from a file reaching
`GenericArray::from_slice`, which panics rather than refusing. It is recorded here because
a panic on a conforming document is worth a downstream report, and because the gate must
say `NOT RUN` rather than swallow it. `an_independent_implementation_reads_what_…_wrote`
still runs `office-crypto` on the **default** artifact every `cargo test`; no assertion
about that reader is added at the two new sizes, which would freeze its bug into this
suite.

**Word, LibreOffice and the interactive open path are not measured at AES-192 or
AES-256.** The acceptance-gate verdicts above and the byte-exact golden are AES-128
artifacts, because that is what Office 2007 wrote and therefore the only row a fixture can
exist for. Word is the reference for this format, and a refusal from it would be a finding
to work through against §2.3.4.5 rather than a caveat to write down; the suite writes
`msoffice_crypto_encrypt_ooxml_standard_aes192.docx` and `…_aes256.docx` into
`MSOFFICE_CRYPTO_ARTIFACT_DIR` for exactly that check, and asserts nothing about what any
external program does with them.

### `spinCount` is bounded at the spec's number, and was bounded below it on the read path

`limits::SPIN_COUNT_MAX` was `1 << 21`. §2.3.4.10 declares `ST_SpinCount` as
`minInclusive="0"`, `maxInclusive="10000000"`, and the prose says "It MUST NOT be greater than
10,000,000". So a `.docx` declaring any spin count between 2,097,152 and 10,000,000 was
conforming, opened in Word, and was refused here — **on the decrypt path**, which makes it a
defect rather than a conservative default. Encryption must not protect data from its owner.

**The margin was defended with arithmetic that does not hold.** Three figures in the
superseded comment disagreed with each other: `u32::MAX` rounds at ~50 minutes and `1 << 21`
at ~1.5 s both imply ~0.70 µs per round, from which the spec's 10,000,000 is about **7
seconds** — not the "minutes of one core" claimed. "~7 µs per SHA-512 round pair" was ten
times high, and "21x under 10,000,000" was 4.8x. Every error ran in the direction that made
the margin look necessary. `tools/audit_claims.py` cannot catch this: it checks that citations
resolve, not that sums add up.

Where the denial-of-service policy belongs is the caller, which already has what it needs:
`classify` reports `spin_count` unbounded and unvalidated before a single round runs, so any
threshold is one comparison on data this crate hands over free. A ceiling imposed here is one
a caller cannot loosen.

Raised by the downstream consumer asking which bounds were the format's and which were ours —
a question the crate could not answer from its own documentation, which is why `limits.rs` now
opens with a provenance table labelling every bound **spec**, **cipher** or **margin**.

### Two secrets no longer reach a bare `Vec` on the decrypt path

Both were in the default `crypto-ops` build, on every decrypt, in published rc.2 and rc.3.
Neither is attacker-reachable by choice of input; both are heap residue, the class
[`docs/design/heap-residue.md`](docs/design/heap-residue.md) describes — a `Vec` that grows
frees the old block unwiped, and the wrapper cannot reach what was abandoned before it
existed.

The **UTF-16LE password buffer** in `agile::spin_hash` and `standard::derive_standard_key` was
built with `encode_utf16().flat_map(..).collect()`. `EncodeUtf16`'s `size_hint` lower bound is
`len.div_ceil(3)`, so `collect` reserved a fraction of the true length and the `Vec` grew.
Measured with a counting `GlobalAlloc` rather than argued: `"testpass"` abandoned one 8-byte
block holding `t\0e\0s\0t\0`; `"correct horse battery staple"` abandoned 60 bytes across two
reallocations. Now one allocation at the exact length inside a wrapper.

**`derive_block_key`** cut the block key with `digest[..key_len].to_vec()`, leaving the whole
digest of `H_final` in a bare `Vec` and copying the prefix out rather than writing it in. Now
`hash::digest_two_into` writes straight into the wrapped slot.

Both seeded goldens are byte-identical, which is the entire proof these changed no output.

**Not fixed, and named rather than carried silently:** `rc4_cryptoapi.rs:262` and
`rc4_office97.rs:95` hold the identical `collect()` under `legacy-binary`. And the spin loop
abandons ~100 000 unwiped 64-byte digests per decrypt, whose in-code defence — "intermediate
hash states, not the key" — is true and is not a security argument: given `H_i`, reaching
`H_final` costs `spinCount - i` hashes while attacking the password costs `spinCount` *per
candidate*, so any recovered round is a total break the spin count does nothing to resist.
`standard::derive_standard_key` already runs its 50 000 rounds over one reused array with no
heap traffic; the agile path is the outlier.

### The acceptance gate stopped reporting its own build failures as reader refusals

`tools/acceptance_gate.py`'s office-crypto leg runs `cargo run --example`, which compiles this
crate on the way to running someone else's — and rendered *any* non-zero exit as
`"right password REFUSED"`. A compile error in an unrelated uncommitted edit therefore came
back as a sentence about a reader and an artifact. The one leg written specifically so it is
not this crate marking its own homework (`examples/office_crypto_check.rs:13`) was the one
coupled to this crate's working tree.

The build is now a separate step; a failure raises `LegCannotRun` and the gate prints
`GATE: NOT RUN … nothing was proven` and exits 2, never FAIL — the `MutationNotApplicable`
precedent, whose reasoning already covered this case. The header gained a `tree :` line naming
HEAD and whether it is dirty.

**The first fix broke the negative control and that was worse.** It assumed the example's
refusal code was 1; the contract at `examples/office_crypto_check.rs:25-26` says 3, twenty-five
lines above the code the fix cited. Genuine refusals became `LegCannotRun`, so
`--expect-fail` — the run whose entire purpose is proving the gate *can* fail — exited 2
instead of reaching `EXPECTED FAIL`. Found by the downstream consumer within the hour, on that
control. Both polarities are now verified, and the codes are named constants beside the reason
guessing them was expensive.

Reported by the downstream consumer, who hit the original on their own artifacts and recorded
no verdict rather than a contaminated one.

### `encrypt_ooxml` refuses input it used to accept — the already-encrypted guard is the library's now

**Breaking, and it is a behaviour change rather than an addition.** `encrypt_ooxml` and
`encrypt_ooxml_standard` now accept exactly one thing, a plain OOXML package, and return an
error for everything else. Code that passed them an already-encrypted file, a 97-2003 binary
document, an empty slice or arbitrary bytes got `Ok` before and gets `Err` now.

What it was doing instead: **silently double-wrapping.** Handed a file that already carried a
password-to-open, `encrypt_ooxml` returned a CFB container wrapped in a second CFB container.
That artifact is indistinguishable from a single wrap without decrypting it, and it opens
only by decrypting twice, with two passwords the holder believes is one.

The check existed the whole time — as `encrypt_guard` in `src/bin/msoffice-crypto.rs`, tested,
correct, and unreachable from the library. **Found by the downstream consumer**, which hit the
defect and reimplemented that guard from the CLI's shape, leaving two copies of one rule with
the tests on the copy library callers could not call.

`check_encryptable(&[u8]) -> Result<(), Error>` is public, and is the same function both
writers call at the door rather than a second one that agrees with them. It is public because
the position that matters is **before a password is obtained**: prompting for a new password
for a file about to be refused is a question answered for nothing, and on an interactive path
it cannot be taken back. The CLI has always called it there, and `tests/cli.rs` pins the
ordering — all 58 of those tests pass with no edit to their code, which is how the sentences
and exit codes are known to be unchanged.

Three new `crypto-ops` variants rather than one, because the CLI's exit codes were already
evidence that the cases are different facts. `Error::AlreadyEncrypted { family, document }`
carries `classify`'s verdict so a renderer can choose between "decrypt it first" and "there is
no writer for the 97-2003 binary formats"; both are `Copy` enums, so no byte of the file
reaches the error. `Error::NotAPlainPackage` deliberately carries no `document`, which turns
"never name a document kind `classify` refused to name" from a discipline into something that
cannot be written. `Error::UnknownContainer` is exit 3 where the other two are 5.

**The shape check runs before the payload ceiling**, and the order is a claim with a test.
For a gigabyte of junk both facts are true; "not a package" is the primary one, and
`BadParameters(… PAYLOAD_CEILING …)` would be the worse answer. A real oversized package still
answers by name.

Evidence, per CLAUDE.md § *Evidence over intent*. Deleting the `?` from `encrypt_ooxml` makes
`encrypt_ooxml_refuses_a_file_it_just_encrypted` fail with `Ok(47616)` — a 47,616-byte
double-wrapped container. Reversing the guard and the ceiling makes
`the_shape_guard_runs_before_the_payload_ceiling` fail with
`Err(BadParameters("over PAYLOAD_CEILING"))`. Both were run, and restored.

The two seeded goldens are byte-identical (41,984 / `b4cc009e…`; 40,960 / `491298746c…`), so
no written byte moved: this release changes what is refused, never what is produced.

`rc.2` recorded that "the library has no `AlreadyEncrypted` variant, so this guard is the
CLI's". Both halves of that are now wrong. That entry stays as written — it was true when it
shipped — and `docs/plans/msoffice-crypto-cli-2026-09-11.md` § 7 carries a dated superseded
note beside the same claim.

### `Document::OoxmlPackage` narrowed in rc.3, and a consumer matching it gets no compile error

Recorded here rather than under rc.3, whose entry is released and stays as written. The
narrowing is documented there; what that entry does not do is turn and face a caller outside
this crate, and it should have.

At rc.2, `Document::OoxmlPackage` meant "a CFB-wrapped package **or** any ZIP". At rc.3 it
means CFB-wrapped package only, and every plain `PK` signature reports the new
`Document::ZipArchive` instead. A consumer that wrote `matches!(class.document,
Document::OoxmlPackage)` to mean "this is a package" **still compiles and silently stops
matching every plain `.docx`.** Nothing was removed, so nothing scanning for breaking changes
finds it, and `#[non_exhaustive]` makes it worse rather than better: it had already obliged
that consumer to write the catch-all arm that now swallows the new variant.

**Reported by the downstream consumer**, who checked their own dispatch rather than assuming
and found it safe by luck — their router keys on `Container`, so `.document` is read only on
the CFB branch, where the meaning did not change. Had they keyed on `.document` at the top,
the bump would have broken plain-package detection with a green build and green tests.

No remedy is offered and none is needed: the break happened, it stands, and this is the
sentence that says so.

**The two breaking changes in this release are not the same kind, and the difference is what
a consumer can plan for.** `check_encryptable` refusing input that used to be accepted
*announces itself*: an `unwrap` panics, a handled `Result` takes its error arm, a test that
asserted the old permissiveness goes red. Something happens, at a place that names the
change. The `Document` narrowing does none of that — a `matches!` arm quietly evaluates
`false` and the program carries on being wrong. **A consumer can plan for a build that
breaks and cannot plan for a match arm that stops matching**, so a silent narrowing needs
this paragraph in a way a loud refusal does not.

Drawn from the downstream consumer again, who found the distinction by having one of each:
the refusal broke exactly one of their assertions — a *negative control* written to prove
their own input gate was load-bearing rather than decorative, which this release makes
redundant in the good direction — while the narrowing would have broken nothing visible at
all. They are keeping the refusal and rewriting the control.

### The acceptance gate no longer claims to have verified an HMAC that does not exist

`tools/acceptance_gate.py`'s `msoffcrypto` leg returned `dataIntegrity HMAC verifies
(verify_integrity=True)` for **every** artifact that decrypted — including ECMA-376 standard
files, which define no `dataIntegrity` element at all and for which `msoffcrypto-tool`
silently ignores the keyword. The line was byte-identical for both families, so it was
evidence of nothing for either.

The function's own docstring already described the behaviour it did not have: *"the verdict
then says only that it decrypted."* Prose and code had drifted, and nothing caught it —
`tools/audit_claims.py` check B only guards citations that point past end of file.

`declares_data_integrity` now reads the `EncryptionInfo` version pair the way
`corrupt_integrity` already did — 4.4 and the element present, or no claim — and a standard
artifact reports `decrypted; NO dataIntegrity element to verify (verify_integrity is inert
here)`.

**Measured and reported by the downstream consumer** against their own 2007 artifacts, in the
same exchange as the `Document` finding above.

### The crate documentation states its bounds, its write profile and where plaintext is not zeroized

Three things a consumer had to ask for rather than read.

`src/lib.rs` gains a **Bounds on untrusted input** section: every cap a hostile file can
trip, grouped by build, with the two that are the spec's own numbers rather than this crate's
margins marked as such. They are `pub(crate)` constants quoted for discoverability, not public
API, and the section says so.

`encrypt_ooxml`'s documentation now states the two fixed properties of what it writes: the
100 000-round spin count has **no parameter** to change it, and a `<dataIntegrity>` element is
written **unconditionally**, so a consumer may assert `IntegrityDeclaration::Declared` on
agile output from this crate and know the assertion cannot fail.

### The release runbook now covers the window between tagging and publishing

`cargo publish` packages the working tree, not the tag, and
`.cargo_vcs_info.json` inside the `.crate` records `HEAD` at the moment it ran. A commit
made after tagging therefore decides what is published, silently, and the tag is never
consulted.

Found by doing it: during the rc.3 cut a docs-only commit landed about a minute after the
tag, and the publish recorded that commit rather than the tagged one. It cost nothing —
`docs/` is not in the `include` allowlist, and the published crate was verified
byte-identical to the tagged tree, 42 shipped files compared, 0 differing — but the same
mistake one directory over would have published a tree the acceptance gate never ran
against.

`docs/RELEASING.md` § 5a now says to stop committing until step 6 is done, and carries the
two commands for finding out what a publish actually recorded, plus the decision that
follows: move the tag if nothing shipped changed, yank and re-cut if something did.

## v0.1.0-rc.3 — 2026-09-19

### Evidence for this release

The four-reader acceptance gate, run on this machine 2026-09-19 against artifact SHA-256
`7b381f54483d962ef542204ed79aee6ae7bada32e09cd615722e45595d8a92e9` (41,984 bytes), written
into a private directory rather than shared system temp:

```
office         PASS  Word 16.0 build 16.0.19127: OPENED, content matches | WRONG PASSWORD REFUSED 0x800A1520
libreoffice    PASS  LibreOffice 26.2.1.2: OPENED, content matches | WRONG PASSWORD REFUSED (verifier)
msoffcrypto    PASS  msoffcrypto-tool 6.0.0: byte-identical to plain.docx | dataIntegrity HMAC verifies
office-crypto  PASS  office-crypto 0.3: byte-identical to plain.docx
GATE: PASS (4 of 4 readers ran; 0 not selected)
```

Both mutation proofs reached `EXPECTED FAIL`. `--tamper` failed **4 of 4** readers;
`--corrupt-integrity` failed **3 of 4** — office-crypto 0.3 verifies neither the password
verifier nor `dataIntegrity`, so blanking those blobs cannot make it fail, and three is the
number that shows the mutation hit the field it names.

Tarball verified by extraction and re-run, not by inspection: 46 files, the two allowlisted
fixtures and no others, and the ignored count inverting as it must — 13/22/33 ignored inside
the tarball against 0 in the repository.


### `classify` no longer claims a plain ZIP is an OOXML package

`Document::ZipArchive` is a new variant, and every plain `PK` signature reports it instead of
`Document::OoxmlPackage`. The decision was — and still is — four bytes of magic: `is_zip`
reads `PK` / `PK` / `PK` and opens nothing, reads no entry and
looks at no content type. `OoxmlPackage` was therefore an affirmative claim about a format
that nothing had examined, and a `.vsdx`, an `.odt`, a `.jar` and a backup archive all
carried it.

**The argument that settled it is this crate's own, applied on the side it had been skipped
on.** `Classification::is_encrypted` returns `false` for `Family::Unknown` because "nothing
could be determined is not a claim the file is plain" — and the ZIP branch was making exactly
the claim that rule forbids, in the other direction. Raised by a downstream consumer
integrating the crate, who hit it as a live defect: a test asserting "a non-Office zip is not
detected as OOXML" would have failed against a verdict that forwarded `classify`.

`OoxmlPackage` keeps its meaning for a CFB container, where an `EncryptionInfo` stream was
actually read and ECMA-376 encryption wraps a package by definition.

Scope, checked rather than assumed: `Classification::is_supported` is unaffected (it matches
`(OoxmlPackage, Agile | Standard)`, so a plain archive was already `false`), the CLI's
`encrypt` guard matches on `Container` rather than `Document`, and the CLI's decrypt routing
refuses `Family::Unencrypted` before it reaches the document match. The CLI renders it as
`zip-archive`.

### `classify` reports whether it could open the container at all

`Classification::container_read` is a new field, carrying the new `ContainerRead` enum:
`Opened`, `Unreadable`, `NotAttempted`.

The fact it records was already being computed and thrown away. `classify_cfb` called
`cfb_reader::read_encryption_info`, whose error distinguishes "the container would not open"
(`NotACfbFile`, straight from `cfb::CompoundFile::open`) from "it opened and the stream is
missing or oversized" — and a `let`-else discarded it. So the first 128 bytes of an agile
`.docx` and sixteen bytes of junk came back identically `Family::Unknown`,
`Document::Unknown`, `IntegrityDeclaration::Unknown`, with nothing to tell a caller which had
happened.

**That is a wrong answer rather than a missing one, and it is reachable from an ordinary
dispatcher.** Code that sniffs a file header, matches `Family::Agile`, and falls through
otherwise takes the same branch for "this is not an Office file" as for "you handed me a
prefix". Found by a downstream consumer whose key-rotation path peeked 128 bytes and
dispatched on the result.

4096 bytes is not enough either, which is what rules out "peek a bigger header" as the fix: a
CFB names its directory by sector offset and Office writes it near the end of the file. The
whole file is the requirement, and `Unreadable` is how a caller learns that rather than
guessing.

Named for what was observed, not for what caused it. A directory outside the supplied bytes
is equally a truncation, a prefix, and a corrupt header pointing past the end; this crate
cannot tell those apart and the variant does not claim to.

The CLI prints it as `container-read:` and carries `container_read` in `--json`, which takes
the top-level key set from nine to ten. The human column widened from 14 to 16, the longest
key having grown.

### The acceptance gate says when a mutation does not apply, instead of crashing

`tools/acceptance_gate.py --corrupt-integrity` blanks the two `dataIntegrity` blobs in an
agile `EncryptionInfo`. Run against an Office 2007 standard artifact it decoded that stream's
binary header as UTF-8 XML and died with an uncaught `UnicodeDecodeError`: exit 1, no `GATE:`
line, and under `--expect-fail` the inversion never ran — so the step failed while looking
like the gate had held.

Both mutation flags now check what they are being asked to mutate and report
`GATE: NOT RUN` with **exit 2**, distinct from the 0 and 1 a gate run returns, because such a
run neither passed nor failed. `--corrupt-integrity` is agile-only by construction — standard
encryption defines no element to blank — and both flags refuse an artifact that is not a CFB
container at all, which is what a run against a non-ECMA-376 look-alike hits.

Found by a downstream consumer whose plan invoked the flag family-agnostically, on both
writers.

### `gen_plain_binary_fixtures.ps1` produced fixtures this repository's own suite rejects

The generator set no scrub, so every fixture it wrote carried the generating machine's Office
user name in `Author` and `LastAuthor` — while `tests/fixture_identity.rs` asserts those are
empty or absent for all ten Office-written fixtures, `word97_plain.doc` among them. A rerun
therefore produced a corpus that failed the suite, and the script's own header described that
as expected and left the remedy to the reader.

Each document now sets `RemovePersonalInformation` before `SaveAs` — the programmatic
Document Inspector, which is what produced the empty fields in the fixtures already
committed. Measured both ways against a scratch fixture directory: without it all three files
carry a 13-character name in both properties; with it all three are empty.

**The remedy the old header recommended could not have worked**, which is why this was not a
one-line fix. `Application.UserName = ''` is rejected by Word with "Bad parameter";
PowerPoint's `Application` exposes no `UserName` property at all (`Get-Member`: False); and
`BuiltInDocumentProperties('Author').Value = ''` fails under PowerShell with "Object
reference not set to an instance of an object", because a parameterised COM property cannot
be assigned that way. All three checked, not reasoned about.

The header also cited the decision as "GH #9", which `docs/design/development-record.md` § 7
describes as the publish issue about a fresh `cargo test` inside the unpacked tarball.
Whether #9 also carried the metadata item is not resolvable from this repository — the issues
live in the archived one — so the header now names the check instead of the number.

**The committed fixtures were never affected.** `tests/fixture_identity.rs` has been green
throughout; it was the generator, not the corpus, that was wrong.

## v0.1.0-rc.2 — 2026-09-15

**This is the first release published to crates.io.** `v0.1.0-rc.1` exists as a git tag and
as the section below, and was never published — the CLI and the pre-publish security work
were wanted first, so the line above it is the one that ships. A reader comparing this
changelog against crates.io will find no `0.1.0-rc.1` there, and that is the reason. The
section below calls itself "First public version"; read that as the first tagged tree, not
the first thing anyone could `cargo add`.

### A command line, behind an opt-in `cli` feature

`msoffice-crypto` is now a binary as well as a library. Three subcommands over the same
entry points the library already offered:

- `classify FILE [--json]` — container, document, family, the declared algorithm tuple and
  whether a `dataIntegrity` element is present. It cannot fail: an unencrypted package,
  sixteen bytes of junk and an unrecognised container all exit 0, because all three are
  answers, and only an unreadable *file* is an error. `--json` emits one object with the
  same key set for every input — `key_data` and `password_key` are `null` rather than
  absent — built as a `serde_json::Value` rather than derived, so a field added to
  `Classification` later cannot silently vanish from the JSON.
- `decrypt IN [-o OUT] [--integrity POLICY]` — dispatches on the classification, not the
  extension, so a `.doc` that is really an OOXML package takes the right route. The
  97-2003 arm is compiled in only under `legacy-binary`; without it those files exit 9
  naming the feature to rebuild with, rather than pretending to be unreadable.
  `--integrity`'s default is rendered from `IntegrityPolicy::default()` rather than typed,
  because that default has already moved once and a hard-coded help string would have
  survived the move looking correct. The outcome is printed on stderr after every
  successful decrypt, including after `--integrity skip`.
- `encrypt IN [-o OUT] [--format agile|standard]` — agile by default. An input the
  classifier calls a CFB container is refused at exit 5; the library has no
  `AlreadyEncrypted` variant, so that guard is the CLI's.

**Passwords never come from `argv`.** There is deliberately no `--password VALUE` flag —
`argv` is world-readable in a process listing for the lifetime of the run. The four sources
are `--password-env NAME`, `--password-file PATH`, `--password-stdin` and, with none of
them, a non-echoing prompt. Exactly one may be given. `--password` is registered hidden so
that reaching for it produces the reason it does not exist.

**Ten exit codes, not two.** 0-7 carry the sibling crate's meanings; 8 and 9 exist because
this crate distinguishes facts the sibling's error type does not. 8 is tamper or a policy
refusal and is not folded into 4 or 6: at a process boundary the number is all a script
gets, and telling someone their password is wrong when the file was modified is the bug
`CLAUDE.md` § *Cryptographic Rules* forbids, re-created where it is harder to see.
`README.md` § *Command line* carries the table.

**The cost, and a licence finding.** The binary is behind `cli`, default off, because a
library consumer must not pay for an argument parser to ask whether a file is encrypted —
the same argument `default = []` already makes, one level out. `cli` adds thirteen crates
over `crypto-ops` on x86_64-pc-windows-msvc (eleven on Linux; two of the thirteen are
`windows-sys` and `windows-link`, which `rpassword` pulls on Windows alone): `clap` in its
builder form with no `derive` and no `wrap_help`, `serde_json` with no `serde` derive, and
`rpassword`. `rpassword` and its `rtoolbox` are licensed **Apache-2.0 only**, and they are
the only two crates in this graph that are — every other crate here is dual MIT/Apache-2.0
or more permissive. That matters because this crate is offered as `MIT OR Apache-2.0` and
the point of the dual offer is that a consumer may take either: one who took the MIT half
and then builds the binary must still satisfy Apache-2.0 for those two. They stay allowed
with **no `[[licenses.exceptions]]` entry**, since `Apache-2.0` was already on
`deny.toml`'s allow list; what changed is that the case is written down where it can be
found, in `deny.toml` beside the allow list and in `README.md`'s new feature table.
(`zopfli` is Apache-2.0-only as well, and is not in scope: it reaches `Cargo.lock` through
the `zip` dev-dependency and appears in no `cargo tree -e normal` output.)

**CI now runs five feature configurations, not three.** `cli` and `cli,legacy-binary`
joined the clippy and test matrices; until they did, CI had never built or tested the
binary at all and every figure about it had been measured by hand.

Two guards landed with them, and both were proved by causing the failure rather than by
being added:

- The `detection build links no cipher` job now also asserts that `clap`, `rpassword`,
  `rtoolbox` and `serde_json` are absent — the claim that `cli` is opt-in was previously
  enforced by nothing — and it measures the **default** graph as well as the
  `--no-default-features` one. That second half is the real finding: the step already
  carried `--no-default-features`, so putting `cli` into `default` left it passing
  unchanged, and adding names to the pattern would not have fixed that. With the extra
  invocation, the same mutation prints the four crates and exits 1. A matching vacuity
  guard asserts all four are **present** in the `cli` graph, so their absence elsewhere is
  falsifiable.
- `packaging-invariants` now asserts `cargo package --locked --list` ships
  `src/bin/msoffice-crypto.rs`. Dropping it from the `include` allowlist does not fail
  `cargo package`: it exits 0, adds one more `warning: ignoring binary ...` to the seven
  `ignoring example/test` warnings a correct package already prints, and ships a tarball
  whose only symptom is that `cargo install msoffice-crypto --features cli` installs
  nothing. `cargo package`'s verify build cannot see it either, because the binary is
  `required-features = ["cli"]` and verify builds default features. That is the same silent
  shape as the `build.rs` invariant beside it.

### The four-reader acceptance gate, over a CLI-written artifact

`msoffice-crypto encrypt` writes the container the library writes, so the gate below ran
over a file the *binary* produced rather than one a library test did — the first time
that has been true. The artifact came from a private directory, never the shared system
temp directory, because a run there once measured another build's file.

The blocks below are the gate's own output, with one edit and no others: the two
`libreoffice` lines carry the artifact's absolute path inside the `Unsupported URL`
message, and that path is a temporary directory under a workstation account name, so it
is elided here. Nothing else is paraphrased.

Agile, from `encrypt tests/fixtures/plain.docx --format agile`: 41984 bytes, SHA-256
`e4c9ed2929322c923c572c916125a73449754277cf7cdd509545d44aed935198`. Measured
2026-09-14 against Word 16.0 build 16.0.19127, LibreOffice 26.2.1.2, msoffcrypto-tool
6.0.0 and office-crypto 0.3:

```
office         PASS     Word 16.0 build 16.0.19127: RIGHT PASSWORD : OPENED in Word, content matches plain_content.txt | WRONG PASSWORD : REFUSED 0x800A1520 (password incorrect -- container, header, XML and KDF all accepted)
libreoffice    PASS     LibreOffice 26.2.1.2: RIGHT PASSWORD : OPENED, content matches plain_content.txt | WRONG PASSWORD : REFUSED -- verifier rejected it and LibreOffice asked for another (a password request with an XInteractionPassword2 continuation, aborted); load then threw com.sun.star.lang.IllegalArgumentException: Unsupported URL: "type detection aborted"
msoffcrypto    PASS     msoffcrypto-tool 6.0.0: byte-identical to plain.docx (36678 bytes) | dataIntegrity HMAC verifies (verify_integrity=True) | wrong password refused (exit 1): msoffcrypto.exceptions.InvalidKeyError: The file could not be decrypted with this password
office-crypto  PASS     office-crypto 0.3: byte-identical to plain.docx (36678 bytes) | wrong password: 36678 bytes, NOT plain.docx (36678 bytes) (office-crypto verifies neither the verifier nor dataIntegrity; the byte comparison is the check)

GATE: PASS (4 of 4 readers ran; 0 not selected)
```

Both mutation runs fail as they must, over that same artifact. `--tamper --expect-fail`
(one ciphertext bit flipped in `EncryptedPackage`) →
`GATE: FAIL (4 of 4 selected readers failed: office, libreoffice, msoffcrypto,
office-crypto)` / `EXPECTED FAIL: the gate failed, which is what this run required`.
`--corrupt-integrity --expect-fail` (the `dataIntegrity` HMAC blobs blanked, every
length unchanged) →
`GATE: FAIL (3 of 4 selected readers failed: office, libreoffice, msoffcrypto)` —
`office-crypto` PASSes this one on purpose, because it is the one reader here that
never checks `dataIntegrity` at all, and its byte comparison alone cannot see the
corruption — / `EXPECTED FAIL: the gate failed, which is what this run required`.
Without both of these the PASS above would be vacuous.

Standard, from the same input with `--format standard`: 40960 bytes, SHA-256
`d6d6d4c9c80419b299683fa62dc716f158bc018d5f9ff367b6605cb8528577d8`, same date and
same reader versions:

```
office         PASS     Word 16.0 build 16.0.19127: RIGHT PASSWORD : OPENED in Word, content matches plain_content.txt | WRONG PASSWORD : REFUSED 0x800A1520 (password incorrect -- container, header, XML and KDF all accepted)
libreoffice    PASS     LibreOffice 26.2.1.2: RIGHT PASSWORD : OPENED, content matches plain_content.txt | WRONG PASSWORD : REFUSED -- verifier rejected it and LibreOffice asked for another (a password request with an XInteractionPassword2 continuation, aborted); load then threw com.sun.star.lang.IllegalArgumentException: Unsupported URL: "type detection aborted"
msoffcrypto    PASS     msoffcrypto-tool 6.0.0: byte-identical to plain.docx (36678 bytes) | dataIntegrity HMAC verifies (verify_integrity=True) | wrong password refused (exit 1): msoffcrypto.exceptions.InvalidKeyError: The file could not be decrypted with this password
office-crypto  PASS     office-crypto 0.3: byte-identical to plain.docx (36678 bytes) | wrong password: 36678 bytes, NOT plain.docx (36678 bytes) (office-crypto verifies neither the verifier nor dataIntegrity; the byte comparison is the check)

GATE: PASS (4 of 4 readers ran; 0 not selected)
```

`--corrupt-integrity` does not apply to it: Office 2007 standard encryption defines no
`dataIntegrity` element, which is why `encrypt` prints `integrity: not-applicable` for
it and why there is no `--integrity` flag on `encrypt` at all.

**Read the `msoffcrypto` line in that second block with this in mind.**
`dataIntegrity HMAC verifies (verify_integrity=True)` is the single string
`msoffcrypto_integrity` returns on success (`tools/acceptance_gate.py:197`), and for a
file carrying no `dataIntegrity` at all `msoffcrypto-tool` ignores the keyword — as the
function's own docstring says. On the standard artifact that line therefore means *it
decrypted*, not that anything was authenticated, and the gate's wording does not
distinguish the two. The only HMAC claim in this entry is the agile block's, and
`--corrupt-integrity` above is what makes that one non-vacuous.

### A stale copy of the RC4 key is no longer abandoned on the heap

The 40-bit RC4 CryptoAPI key is built inside its wrapper, five bytes of `Hfinal` zero-padded
to sixteen ([MS-OFFCRYPTO] §2.3.5.2). It was built by growing an empty buffer —
`extend_from_slice` then `resize` — and `secure-gate`'s `Dynamic::new_with` hands the closure
an empty buffer to *grow*, not a sized slot. Either call can reallocate, and a `Vec` realloc
frees the old block **without wiping it**, leaving a copy of the key on the heap that nothing
will ever zeroize.

Nothing about that is visible from outside: the wrapper still zeroized what it ended up
holding, so the key was protected and a stale copy of it was not. One `reserve_exact` made
the first allocation the only one — that was the fix as it landed, and it is deliberately
not what the tree holds now; see the next paragraph. No behaviour changed — the digests
`tests/legacy_binary_fixtures.rs` pins against `msoffcrypto-tool` are unmoved, which is what
shows the key schedule still produces the same bytes.

Found while upgrading `secure-gate`, from its maintainers' guidance on growing a
`Dynamic<Vec<u8>>` in place, and it is the kind of defect that has no symptom to notice.

**And then it stopped being possible to write.** Reporting the defect upstream produced an
API change rather than a documentation note: as of `secure-gate` 0.9.0-rc.12,
`Dynamic::new_with` takes a length and hands the closure a pre-zeroed `&mut [u8]` of exactly
that size, so there is no growable buffer to reallocate. The fix above becomes a single
`copy_from_slice` with no `reserve_exact` and no trailing `resize` — the discipline is now
the type's, not this crate's.

The all-zero slot is a **documented guarantee** rather than an implementation detail, and
this crate's key is the case it was made one for: the eleven trailing zeros of the 40-bit RC4
key are key-schedule input under \[MS-OFFCRYPTO\] §2.3.5.2, so a slot that merely happened to
be zeroed would have produced a different cipher the day it was not — silently, and as a
wrong key rather than an error.

### The gate re-run after the standard writer changed, and the artifact it could not have gated before

`standard_encrypt::generate` changed below, which is a change to the encrypt path, so the
four-reader gate was re-run on this machine rather than inferred from the byte-exact
goldens. Measured 2026-09-15 against Word 16.0 build 16.0.19127, LibreOffice 26.2.1.2,
msoffcrypto-tool 6.0.0 and office-crypto 0.3. Both artifacts `GATE: PASS (4 of 4 readers
ran; 0 not selected)`:

- standard, 40960 bytes, SHA-256
  `08083d48f76431783ba66055d262d09b9faa1c4435b13de0ce453e7964545357`
- agile, 41984 bytes, SHA-256
  `6915cfcba6f6c7a974b0a893cadde0995892b39f576c5808bcbe9e44ef9d923f`

Both mutation runs fail as they must. `--tamper --expect-fail` → `GATE: FAIL (4 of 4
selected readers failed)`. `--corrupt-integrity --expect-fail` → `GATE: FAIL (3 of 4
selected readers failed: office, libreoffice, msoffcrypto)` — **three, not four, and that
is the correct number**: office-crypto verifies neither the verifier nor `dataIntegrity`,
so blanking those blobs cannot make it fail. It is the one reader whose passing there
carries no information, which is exactly why msoffcrypto-tool's line is what makes the
HMAC claim non-vacuous.

**The standard artifact could not honestly have been gated before this release.** Its test
wrote to the shared system temp directory and printed no digest, while its agile sibling
honoured `MSOFFICE_CRYPTO_ARTIFACT_DIR` and printed a SHA-256 precisely so a reader can
tell whether the gate measured this run's file. The mitigation was built for the #8 gate,
documented on the agile test, and applied to one of the two writers — leaving the
unprotected one to be the writer that changed here. Both now take the variable and print a
digest, and the digests above are the ones the tests printed.

### The same defect, found a second time, in the standard writer

`standard_encrypt::generate` built `SHA1(verifier)` by `to_vec()` on the 20-byte digest and
`resize` to the 32-byte blob. `to_vec` allocates exactly 20; 32 does not fit, so it
reallocated and freed the block holding the digest **unwiped**. Measured rather than
inferred — the pointer moves and capacity goes 20 → 40:

```
before resize: ptr=0x2d5556d0600 len=20 cap=20
after  resize: ptr=0x2d5556ce670 len=32 cap=40
```

Unlike the RC4 one this is in the **default `crypto-ops` build**, not `legacy-binary`, and
it is older than the upgrade that found it.

It also carried a second defect the first site did not. The digest left the `with_secret`
closure as a bare `Vec` and was wrapped only by the constructor on the outer line — so the
value **is** wrapped, and an audit asking "is this wrapped?" gets a yes. The gap is *where*,
and it is invisible at a glance. Size is no guide either: at 20 bytes any "check the large
buffers first" instinct ranks it last. Both are gone in one move, for the same reason —
`VerifierPlaintext::new_with(32, |slot| slot[..20].copy_from_slice(&Sha1::digest(v)))`
allocates once at the final size and never exists outside the closure.

A `const _: () = assert!(SHA1_LEN <= ENCRYPTED_VERIFIER_HASH_LEN)` now sits beside the
existing `VERIFIER_HASH_SIZE == SHA1_LEN` check, so the slice index is a build failure
rather than a panic if either constant ever moves.

No behaviour changed: the seeded-RNG goldens — `the_material_is_byte_exact_under_a_seeded_rng`
and `the_whole_container_is_byte_exact_under_a_seeded_rng` — are unmoved, which is what shows
the written bytes are identical.

### `aes` and `cbc` now zeroize, as `rc4` already did

The AES key schedule is the round keys expanded from the session key, and the CBC state
carries a block of key-dependent material. Both live inside the cipher objects where no
wrapper in this crate can reach them; only the upstream feature can, and it was off.

`rc4` has carried `features = ["zeroize"]` since the legacy-binary work, with a CI packaging
invariant to keep it. So the hazard was identified, guarded against regression, and applied
to the cipher in `legacy-binary` — while the cipher in the default build went without. That
asymmetry is the finding; the fix is two words.

`aes` declares `zeroize` as an optional dependency rather than in `[features]`, so the
feature is implicit, and it implements `ZeroizeOnDrop` on the round keys in all three
backends (`soft.rs`, `ni.rs`, `armv8.rs`). `ecb` has no such feature — checked. **No crate
enters any graph**: `zeroize` is already a `crypto-ops` node through secure-gate, so the
lockfile change is one line adding it as an edge of `aes`, and the set of crates is
byte-identical before and after.

`hmac` 0.12.1 is the one that cannot be fixed here: no `Drop`, no zeroize, and its only two
features are `reset` and `std`. Its opad/ipad state is derived from `IntegrityKey` and
nothing wipes it — MAC-forgery capability under that key rather than key recovery. Recorded
in the secure-gate skill's residual list, which had the hasher class written down and had
never carried the HMAC one across.

### `secure-gate` moves to 0.9.0-rc.12, and is pinned

Two of the breaking changes across this span reach this crate. One is the `Dynamic::new_with`
signature described above, and it is the reason the upgrade went to rc.12 rather than stopping
at rc.11. The other is below.

Of the nineteen breaking changes between rc.7 and rc.11, fourteen are in an encoding and serde
surface this crate does not compile, and four of the remaining five do not reach it. The fifth
would not have announced itself: `into_inner()` now returns the plain value and protection ends
at that call, where it used to return a wrapper that kept wiping — so an untyped binding keeps
compiling and quietly stops zeroizing. Verified absent here; every `into_inner` in `src/` is
`std::io::Cursor` or `cfb::CompoundFile`.

The one that reached us there was mechanical. rc.10 deleted the `*_alias!` macros, which only
ever expanded to `type` aliases, so `src/sensitive.rs` becomes seven `type` lines and not one
call site moves — across roughly forty-six `with_secret` closures, six `ct_eq` comparisons
and three `from_rng` draws.

The requirement is now pinned with `=`. A caret carrying a pre-release tag matches later
pre-releases of the same version, so the previous `"0.9.0-rc.7"` already resolved to rc.10 —
a bare `cargo update` would have deleted those macros with no warning, and only `--locked`
discipline was holding it.

Measured rather than assumed: `zeroize` drops from `alloc,zeroize_derive` to `alloc`,
`zeroize_derive` leaves the graph, and a duplicate `syn v2.0.119` leaves with it. `syn v3.0.5`
stays, via this crate's own `thiserror` — the proc-macro chain does not leave, only that one
crate does. The detection build still links no `secure-gate` at all, and all five feature
configurations hold their test counts exactly, seeded encrypt goldens included.

## v0.1.0-rc.1 — 2026-09-11

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
