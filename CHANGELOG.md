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
