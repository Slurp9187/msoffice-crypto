# Plan — customizable agile write parameters, within spec bounds

Opened 2026-09-20. Executed on `feat/library-encrypt-guard`, PR #23 (draft).

**This file arrived late and that is worth recording.** CLAUDE.md § *Conventions* says a plan
is a dated file in `docs/plans/`; this one was written and worked from outside the repository
for its whole first day, so the design existed while the record did not. It is copied in
unedited apart from this header and the status annotations in § *Implementation order*, which
is the convention `msoffice-crypto-foundation-2026-09-04.md:221` sets — annotate in place, do
not rewrite.

The issues half of the protocol (a parent `plan` issue, one `slice` sub-issue each) is **not
filed**. Named here so the gap is visible rather than assumed closed.

## Status at 2026-09-20

| slice | state |
| --- | --- |
| 0. Provenance sweep | **not started** — skipped, and the plan said to do it first |
| 1. `hash.rs` predicate, `digest_len`/`name` public | done, `f5b7b64` |
| 2. `Error::EncryptParams` + payload enums + canary | done, `f5b7b64` |
| 3. CLI exit code | done, `f5b7b64` |
| 4. `encrypt_params.rs` + tests | done, `f5b7b64` |
| 5. `integrity.rs` `pad_zero` | done, `f5b7b64` |
| 6. `encryption_info` threading | done, `ac3bce8` |
| 7. `agile_encrypt` threading | done, `ac3bce8` |
| 8. `lib.rs` entry point | done, `ac3bce8` |
| 9. Tests + evidence pass | done, `ac3bce8` — ten tuples, both goldens unmoved |
| 10. Artifacts + gate + grid | **not started — this is what blocks the merge** |
| 11. Prose | partly, `64b82ce` + `ac3bce8` |

Landed alongside, outside this plan's scope, because they were found while doing it:
`85ed681` the encrypt guard, `ad64424` `spinCount` spec-exactness, `fe0e075` two secret
residues, `05a9027`/`67db5c3` the acceptance gate's measurement validity, `5175467` the
docs.rs link, `12ae7e0` the CodeQL test split.

> Supersedes the completed EFV-API plan (`85ed681`, `05a9027`, `09e137f`, `27b5cde`,
> `ad64424` on `feat/library-encrypt-guard`).

## Context

**[MS-OFFCRYPTO] §2.3.4.10 defines agile encryption as a parameter space. This crate implements
one point in it and calls that the writer.** `ST_SpinCount` admits `0..=10000000`, `ST_SaltSize`
`1..=65536`, `ST_KeyBits` any multiple from 8 upward; the format's own schema says a conforming
writer may emit any of them. `encrypt_ooxml` emits AES-256 / SHA-512 / 100 000 / 16 and nothing
else. The read path already honours four hashes and three key sizes (GH #11/#13), so the crate
can *read* far more of the format than it can *write* — an asymmetry with no basis in the spec.

**That gap is the reason for this work, and it is sufficient on its own.** It is not motivated
by a consumer request, and no consumer's adoption or non-adoption bears on whether it is
correct. The crate's purpose is a faithful implementation of the formats [MS-OFFCRYPTO]
defines; writing one hardcoded tuple out of a defined space is not that, whether or not anyone
has yet asked for a second point.

**Outcome:** a public `EncryptParams` whose `Default` is byte-identical to today's output, a
parameterised entry point beside `encrypt_ooxml`, and validation that refuses only what the
format or the cipher actually forbids — with the reason stated honestly in each case.

## Governing principle — the spec decides, not the sibling

**The specification is the authority. No implementation is, including the ones this crate is
built from and tested against.** CLAUDE.md already states it — *"prefer the spec over any
implementation, and cite section numbers"* — and this plan applies it without exception:

| source | standing |
| --- | --- |
| **[MS-OFFCRYPTO]** | the authority. A claim cites a section number or it is not a claim |
| **Word 16** | Microsoft's own implementation, so a disagreement is serious and blocks — but it is not automatically right, and this repo already records it departing from its own documented behaviour (`development-record.md:230`) |
| msoffcrypto-tool, LibreOffice, office-crypto, herumi | **interpretations of the same document.** Differential oracles: useful for locating a difference, never for adjudicating one. Two of them agreeing is two interpretations agreeing, and § 4 of the development record is a list of bugs found in these very references |
| `odf-crypto` | a different format entirely. Shape may be shared; **no number crosses** |

Concretely, for the sibling: where the spec states a number, that number wins outright. Where
the spec states nothing, a sibling's figure is a tiebreak that must be labelled a **margin**,
never presented as correctness.

**This crate was templated off odf-crypto, so the infiltration is structural, not a stray
citation.** My first audit grepped for places that *name* odf-crypto and found eight; that was
the wrong search, because a template carries assumptions that cite nothing. The real instance:

odf-crypto's `limits.rs` carries `PBKDF2_MIN_ITER`/`MAX_ITER`, `ARGON2_MIN_*`/`MAX_*`,
`DERIVED_KEY_MIN_LEN`/`MAX_LEN` — **a MIN and a MAX for every field** — and CLAUDE.md
§ *Design Values* encodes that as this crate's rule, citing `odf-crypto/src/limits.rs` as the
shape to copy. ODF's spec does not bound KDF cost, so odf-crypto bounds it by *margin over what
real writers emit*. [MS-OFFCRYPTO] **does** bound `spinCount`, and the margin methodology came
across anyway and overrode the spec's number. The crate has already had to fight the rule once:
`SPIN_COUNT_MAX` has no floor, deliberately and with an argument, against a template that says
every field gets one.

So the sweep below is **Item 0 of the implementation, not a footnote** — the parameterisation
work is precisely where inherited methodology would do the most damage, because it is about
which values a caller may choose.

| target | question | expected outcome |
| --- | --- | --- |
| `CLAUDE.md` § *Design Values*, "MIN and MAX for every field" | is a floor required, or inherited? | restate: **the spec's range is the rule**; a MIN exists only where the format or the arithmetic needs one, and `SPIN_COUNT_MAX`'s absent floor is the worked example |
| `limits.rs:6,61` module doc, "the shapes match deliberately" | shape or numbers? | keep as shape-sharing; say explicitly that no *number* crosses between the crates |
| `limits.rs:215` `PAYLOAD_CEILING` | is the burden inverted? | the comment says a different number "would need a reason this crate has and the sibling does not, and there is none" — that makes the sibling the default. Keep 1 GiB (the spec states no ceiling and the memory argument is our own) but argue it from **our** grounds, not from theirs |
| `cfb_reader.rs:119` | number imported or shape cited? | verify it cites odf-crypto's `MANIFEST_READ_CAP` for shape only — ours is 1 MiB, theirs 8 MiB, so the numbers already differ |
| `sensitive.rs:22` `Fixed`/`Dynamic` rule | style or correctness claim? | house style; label it as such |
| every remaining bound | is its spec/cipher/margin label right? | the table added in `ad64424` is the artifact; re-walk it against the PDF now that the PDF has been read |

For this change the principle has teeth: every parameter's range comes from the schema
(`ST_SpinCount`, `ST_SaltSize`, `ST_KeyBits`) or from AES, and from nowhere else.

## Skips audit — my own first draft contained three

Held to "no skip because we don't think anyone will need it", the first version of this plan
does not survive. Each of these was scoped out on demand grounds, and each is a place the crate
implements less of [MS-OFFCRYPTO] than [MS-OFFCRYPTO] defines.

**Skip 1 — standard encryption implements one of three key sizes, and I argued it out of scope
circularly.** §2.3.2 defines `0x0000660E` (AES-128), `0x0000660F` (AES-192), `0x00006610`
(AES-256); read from the PDF, verbatim: *"0x0000660E (AES-128), 0x0000660F (AES-192), or
0x00006610 (AES-256)"*. This crate reads and writes AES-128 only, and `standard::require_aes_128`
refuses the other two **by name**. My draft cited that refusal as evidence that
`encrypt_ooxml_standard` has "no spec-legal parameter" — but the reader refuses them *because we
chose not to implement them*, so the evidence was the decision restated. **Both directions are
unfaithful**: the crate cannot read a conforming Office 2007 document that uses AES-192 or
AES-256, which is the spinCount defect again on a different field — an owner locked out of their
own file by our choice, not the format's.

**Skip 2 is not a skip — and the clause that settles it must be cited where a consumer will
find it.** §2.3.4.10, immediately after the HashAlgorithm table: *"Values that are not defined
MAY be used, and a compliant implementation is not required to support all defined values."*
Accepting only SHA-1/256/384/512 is therefore **authorised by the format**, the exact opposite
of the `spinCount` case where the spec stated a ceiling and carried no such licence.

That makes a **third** refusal shape, distinct from both spec violation and implementation
margin, and the distinction is not academic: a margin implies "we could and chose not to", so an
override is at least coherent; authorised non-support means the format itself contemplates an
implementation declining. It cannot arise through `EncryptParams` — `hash` is a typed enum, so
no caller can ask for WHIRLPOOL — but it arises on every read of a file that declares one.

**Action: `Error::UnsupportedAlgorithm`'s doc must cite §2.3.4.10's licensing clause.** Today it
says only that the crate has not implemented the named algorithm, which understates it and
leaves a consumer to guess whether the file or the library is at fault. Citing the clause turns
"we didn't build it" into "the format permits this value and permits us not to support it" —
the sentence a downstream renderer actually needs. Adding the hashes themselves stays a support
decision, and the owner's, not a conformance one.

**Skip 2's original framing, retained for the record — the agile hash set is four of ten.** `HashAlgorithm::parse` (`classify.rs:273`)
accepts SHA-1/256/384/512. The spec's own list, read from the PDF: `MD5 MD4 MD2 RIPEMD-128
RIPEMD-160 WHIRLPOOL` in addition to the SHA family. Refusing to **write** MD4 or MD5 has a real
argument (they are broken, and a writer choosing them creates a weak file today). Refusing to
**read** one does not: that is a conforming document its owner already holds, and this crate is
the thing standing between them and it. The two directions must be decided separately and on
their own evidence, not collapsed.

**Skip 3 — per-element parameters, argued on demand.** I recommended one tuple for both
`<keyData>` and `<p:encryptedKey>` partly because *"no known writer emits a mismatched pair and
no reader is tested on one"* — exactly the reasoning being rejected. Re-checked against the
spec, it splits:

- **`hashAlgorithm`: one value is the faithful answer.** §2.3.4.10 obliges a *writer* to make
  them equal — *"the hashing algorithm specified MUST be the same as the hashing algorithm
  specified for the Encryption.keyData element"* (quoted at `hash.rs:8-11`). A writer emitting a
  mismatched pair is non-conforming, so the single field is correct and the demand argument was
  merely redundant.
- **`keyBits` and `saltSize`: no such requirement is stated**, and the reader already parses each
  element independently (`check_key_bits` and `check_salt_size` are called per element, and
  `check_salt_size` exists in that shape precisely so one element's size can never be checked
  against the other's salt). Under the rule these are per-element, and the single-field version
  is a skip.

The read side of skips 1 and 2 matters more than the write side: a writer that emits a conforming
subset is still conforming, but a **reader** that refuses a conforming document is the failure
this crate exists to not be.

## Decisions taken

| Question | Answer |
| --- | --- |
| Scope | Everything the schema allows: `spinCount`, `hashAlgorithm`, `keyBits`, `saltSize` |
| Shape | Plain params struct, `Default` = the Office tuple, `..Default::default()` |
| Errors | Dedicated typed error — subject + reason, matchable, extensible |
| Per-element | One tuple written to both `<keyData>` and `<p:encryptedKey>` |
| LibreOffice's narrow allowlist | Write the tuple anyway; document reader support from measurement |
| `saltSize` interop | Gate it before shipping — measure, don't caveat |
| Breaks | Clean only. No `#[deprecated]`, no shim, no compat path |

Decided on the design pass's recommendations, all following from "spec-faithful and extensible":
type named `EncryptParams`; `key_bits: u32` not an enum (symmetry with the wire attribute and
with `AGILE_KEY_BITS_ALLOWED`); params **by value** on the `IntegrityPolicy` precedent; exit
code `EX_USAGE`; `spin_count = 0` and `salt_size = 1` **allowed**, because the schema allows
them and scope says the schema decides — the cost is documented, and a `Weak` reason stays
addable later since both payload enums are `#[non_exhaustive]`.

**Genuinely out of scope, and only these.** Standard encryption's spin count is fixed by
§2.3.4.7 and is not a file field at all (`standard.rs:67`), and its SHA-1 is fixed by the format
(`standard.rs:70`) — nothing to parameterise, from the spec rather than from our reader.
`ST_BlockSize`'s `2..=4096` is generic across ciphers; AES-CBC's block **is** 16, so writing any
other value with AES would be incoherent rather than merely unimplemented. Both are derivations,
not skips.

**Standard encryption's key size is now in scope** — see Skips audit, skip 1. Reading AES-192
and AES-256 (§2.3.2) comes first and matters most; writing them follows.

---

## Three findings that change the shape

**1. `EncryptParams` must NOT be `#[non_exhaustive]`.** That attribute forbids struct-expression
syntax from another crate — and `..Default::default()` *is* struct-expression syntax. The chosen
ergonomics and the attribute are mutually exclusive. Nothing real is lost: the functional-update
contract already survives added fields. `tests/encrypt_entry_points.rs` compiles as a separate
crate and is the ready-made proof (test T10).

**2. Three zero-pad sites are dead today and go live the moment `hash` or `key_bits` moves — each
is the heap-residue defect `standard_encrypt.rs:204-215` already documents.** `to_vec()` at one
length then `resize` to a larger one reallocates and frees the block holding the secret
**unwiped**:

| site | no-op today because | live when |
| --- | --- | --- |
| `agile_encrypt.rs:151-153` verifier input | `salt_size` is 16 | `salt_size` not a multiple of 16 |
| `agile_encrypt.rs:163-167` verifier hash | SHA-512's 64 needs no pad | `hash = Sha1` (20 → 32) |
| `integrity.rs:487-491` `pad_zero` — **never wrapped at all** | same | `hash = Sha1` (HMAC key 20 → 32) |

The third is worst: it produces a bare `Vec<u8>` holding the whole `dataIntegrity` HMAC key.
All three must be fixed in this change, because this change is what makes them reachable.
Allocate at the final length and copy in — precedents at `standard_encrypt.rs:217` and
`rc4_cryptoapi.rs:310` using `Dynamic::new_with`, whose slot is pre-zeroed by guarantee.
**This is security-relevant and goes in the changelog as a fix, not a refactor.**

**3. The password-blob IV must go through `fit_iv`, and today it does not.**
`agile_encrypt.rs:157,169,176` pass `&password_salt` straight to `aes_cbc_encrypt`. The reader
takes the same value through `AgileParams::password_blob_iv` → `fit_iv` (`agile.rs:215`), which
pads a short salt and truncates a long one per §2.3.4.12. At `salt_size = 16` they agree by
accident. The failure at any other size is loud (`check_cbc_lengths` refuses a non-16-byte IV),
but it is the single line most easily missed.

---

## The ten writable combinations

`keyBits / 8 <= digest_len(hash)` (`agile.rs:1137`, `:641`). SHA-1's 20-byte digest admits
**128 only**; `(Sha1, 192)` and `(Sha1, 256)` would produce files this crate could not read back.

| hash | digest | permitted `keyBits` | `encryptedKeyValue` at each |
| --- | --- | --- | --- |
| SHA-1 | 20 | 128 | 16 |
| SHA-256 | 32 | 128, 192, 256 | 16 / **32** / 32 |
| SHA-384 | 48 | 128, 192, 256 | 16 / **32** / 32 |
| SHA-512 | 64 | 128, 192, 256 | 16 / **32** / 32 ← default is 256 |

A **combination** constraint, not a per-field one — the error type must be able to say so.

---

## Item 1 — `EncryptParams`

New module `src/encrypt_params.rs` (+ `_tests.rs`), `crypto-ops`-gated, re-exported beside
`IntegrityPolicy`. Not in `agile_encrypt.rs`: CLAUDE.md's one-module-one-job rule, and that
module's job already needs three "and"s.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]   // deliberately NOT #[non_exhaustive]
pub struct EncryptParams {
    pub spin_count: u32,      // 0..=10_000_000   ST_SpinCount
    pub hash: HashAlgorithm,
    pub key_bits: u32,        // 128 | 192 | 256  (AES; ST_KeyBits has no maximum)
    pub salt_size: u32,       // 1..=65_536       ST_SaltSize
}
```

Manual `Default` (not derived — each value is measured, and carries its provenance):
`{ OFFICE_SPIN_COUNT, Sha512, 256, 16 }`.

`u32` throughout: it is the wire type the schema declares and the type `AGILE_SALT_SIZE` and
`AGILE_KEY_BITS_ALLOWED` already speak. One `as usize` inside the generator, infallible at a
validated max of 65 536.

**Promote `HashAlgorithm::digest_len()` and `name()` to `pub`.** They are facts about SHA, not
about this crate. Without `digest_len` a caller can name `Sha384` but cannot reason about the
one coupling rule the API imposes — they would discover it by trial.

## Item 2 — the typed error

```rust
Error::EncryptParams {
    param: EncryptParam,
    problem: EncryptParamProblem,
    got: u32,               // what the caller asked for
    min: u32, max: u32,     // the bound that refused it
}

#[non_exhaustive] pub enum EncryptParam {
    SpinCount, HashAlgorithm, KeyBits, SaltSize,
    /// `keyBits` **and** `hashAlgorithm` together — neither wrong alone.
    KeyBitsWithHash,
}
#[non_exhaustive] pub enum EncryptParamProblem {
    OutsideSpecRange,           // outside what §2.3.4.10 defines for the attribute
    UnsupportedByCipher,        // inside the spec, outside AES as implemented here
    UnusableCombination,        // legal apart, unreadable together
    ExceedsImplementationLimit, // spec-legal, cipher-fine, and this crate declines
}
```

**The fourth reason is the whole point, and my first draft dropped it** — which is the same
blind spot the governing principle describes, reappearing in the error type. The three-way split
mirrors `limits.rs`'s provenance table but omitted its **margin** row, the row that exists
*because* of sibling-derived bounds. `PAYLOAD_CEILING` is exactly that case: 1 GiB is spec-legal
(the format states no ceiling), cipher-irrelevant, combination-irrelevant, and refused anyway.
Filing it under `OutsideSpecRange` would be a **typed** assertion that the Office format forbids
what it permits — worse than the prose version, because a typed variant reads as authoritative
and a consumer renders it as fact. Caught by the downstream consumer, who has a live issue open
on exactly this class of misreporting.

The two sentences a consumer writes are materially different, which is the test for whether a
variant earns its place:

- `OutsideSpecRange` → *"this file's settings are outside what the Office format allows"* — the
  file is the problem
- `ExceedsImplementationLimit` → *"this asks for more work than this app will do"* — the file is
  fine, and an override is a coherent thing to offer

It also has a producer the moment a read-side margin is ever reintroduced, which the principle
above says must be labelled rather than disguised.

**The `got`/`min`/`max` payload, and why adopting it does not breach the governing principle.**
Carrying the offending value and the bound that refused it lets a consumer name the parameter
instead of quoting a sentence — the structural signal, one level finer than the category alone.
All three are caller-supplied `u32`s, so no file byte reaches the error and the no-attacker-text
rule holds. `Display` must also name **whose** rule was broken ("[MS-OFFCRYPTO] §2.3.4.10
bounds…" against "this crate declines…"), so a consumer with no match arm still gets an honest
sentence rather than a merely bounded one.

This shape arrived via the downstream consumer, who reports odf-crypto reaching it independently
from the other direction. **That is not why it is being adopted** — a sibling's design is not
evidence about [MS-OFFCRYPTO], per § *Governing principle*. It is adopted because whether an
error carries its operand is an API-ergonomics question the spec has no opinion on, so there is
nothing to be unfaithful to. What the convergence *is* evidence for is that the missing fourth
reason was a real partition gap rather than one consumer's preference.

**Where the two crates legitimately diverge, and it is the principle working.** odf-crypto's
taxonomy reportedly has no "outside spec" case at all, because ODF's manifest schema types these
attributes as unbounded — there is nothing to be outside of. Ours needs that row precisely
because [MS-OFFCRYPTO] *does* state ranges (`ST_SpinCount`, `ST_SaltSize`). Same method, different
answer, because different specification. A shared shape here would have been the error.

The pair is a variant of the *subject* enum rather than a second `Error` variant — the enum
names what is being refused, and "the pair" is a subject as legitimately as a field is. A second
variant would double the consumer's match arms and split one fact across two shapes.

**The three reasons are not invented here — they are `limits.rs`'s own provenance taxonomy**
(spec / cipher / margin, `limits.rs:24-31`) made matchable. The doc comment should cite those
lines, which is also what keeps this honest under the governing principle above.

`EncryptParam::HashAlgorithm` has no producer today — all four hashes are writable at some
`key_bits`. It is not dead API: `validate` matches `self.hash` exhaustively with no `_`, so a
fifth `HashAlgorithm` variant is `E0004` at the one place that must decide whether the writer
can emit it. Same device as `check_encryptable`'s container match.

Exit code **`EX_USAGE` (1)** — the caller asked for something impossible; there is often no file
at all, so 6 (`EX_MALFORMED`, a fact about a file) and 9 (`EX_UNSUPPORTED`, "a flag away") are
both wrong. `describe()` deliberately forwards via its `_` arm, with a comment saying so: the
`Display` names a spec attribute and a reason, with no Rust path and no remedy the CLI knows
better. Unreachable from today's CLI, which has no parameter flags; the canary forces the
decision anyway.

## Item 3 — validation

`pub fn validate(&self) -> Result<(), Error>` on `EncryptParams`, called by
`agile_encrypt::encrypt` **and** `encryption_info::write`, so the answer a caller gets before
paying for a password is the answer the writer enforces — the `check_encryptable` precedent.

**Do not bump the four `agile.rs` validators' visibility.** They are parser *adapters*, not
predicates: each takes `Option<u32>` and returns `XmlParse("missing …")` on `None` (unreachable
for a struct field), each returns `BadParameters` naming an XML attribute of a file (which would
defeat the typed error), and `check_salt_size` cross-checks a decoded `saltValue` that does not
exist at validate time. Calling them would force parser-flavoured errors or a mode flag.

What must be single-sourced is the *rule*, and three of four already are — `validate` reads
`SPIN_COUNT_MAX`, `AGILE_SALT_SIZE` and `AGILE_KEY_BITS_ALLOWED` directly. The fourth is an
expression duplicated twice today (`agile.rs:1137`, `:641`); extract it once:

```rust
// src/hash.rs, impl HashAlgorithm
pub(crate) fn can_carry_key_bits(self, key_bits: u32) -> bool {
    (key_bits / 8) as usize <= self.digest_len()
}
```

and rewrite both existing sites to call it. Net duplication goes **down**.

Order — **a single-field refusal outranks any combination it participates in; otherwise
declaration order**:

```
1. hash        exhaustive match, no `_`   (guard for a future variant)
2. key_bits    ∈ AGILE_KEY_BITS_ALLOWED   → (KeyBits, UnsupportedByCipher)
3. key_bits×hash  can_carry_key_bits      → (KeyBitsWithHash, UnusableCombination)
4. salt_size   ∈ AGILE_SALT_SIZE          → (SaltSize, OutsideSpecRange)
5. spin_count  ≤ SPIN_COUNT_MAX           → (SpinCount, OutsideSpecRange)
```

Step 2 before 3 is the whole content of that rule: `key_bits: 200, hash: Sha1` fails both, and
reporting the pair would send the caller to change the hash when no hash carries 200 bits.

## Item 4 — threading

`EncryptionInfoParams` **absorbs the profile** — `params: EncryptParams` replaces the loose
`spin_count` field. Four loose fields would let `write` be handed a hash the generator did not
use; one value cannot.

`encryption_info::write` deletes `HASH`, `SESSION_KEY_LEN` and all of `mod lengths` (including
its second independent `SALT = 16` and the **wrong** `ENCRYPTED_KEY_VALUE = SESSION_KEY_LEN`),
calls `validate()?` first, and derives all seven lengths. **Assertion #7 was wrong, not merely
fixed**: `encryptedKeyValue` is `roundUp(key_bits/8, block)`, not `key_bits/8` — AES-192's
24-byte key travels in a 32-byte blob, which `agile.rs:1160` checks on the way back in and which
real Word 16 opens in `agile_aes192_sha384.docx`. The shared failure message loses
"this crate writes AES-256/SHA-512" and names the params instead.

Those seven stay `BadParameters` and must **not** become `EncryptParams`: by then `validate` has
passed, so a mismatch means the generator and writer disagree — the crate contradicting itself,
not the caller choosing badly.

`agile_encrypt`: delete `SALT_LEN`/`HASH`/`KEY_BITS`; the two salts in `AgileKeyMaterial` become
`Vec<u8>`; `generate` and `encrypt` take `EncryptParams`; `encrypt` validates **before** the
payload ceiling and before any RNG draw. Add the `fit_iv` blob IV (finding 3) and the three
final-length allocations (finding 2), plus a `new_with` zero-tailed AES-192 key blob — zeros
being the only pad Word accepts anywhere in this format, thirteen measured variants deep
(`integrity.rs:453-466`).

`AES_BLOCK_LEN` stays 16 everywhere: fixed by AES-CBC, not by us.

## Item 5 — public API

```rust
pub fn encrypt_ooxml_with_params(package: &[u8], password: &str, params: EncryptParams)
    -> Result<Vec<u8>, Error>
{ check_encryptable(package)?; agile_encrypt::encrypt(package, password, params, &mut SysRng) }

pub fn encrypt_ooxml(package: &[u8], password: &str) -> Result<Vec<u8>, Error>
{ encrypt_ooxml_with_params(package, password, EncryptParams::default()) }
```

Naming and by-value both follow `decrypt_ooxml` / `decrypt_ooxml_with_policy` in the same file.
`encrypt_ooxml` is one line for the same reason it is one line today: "the default path and the
parameterised path are the same code" must be a fact, not a claim.

## Item 6 — tests

**T1** 12-cell sweep: 10 `Ok`, `(Sha1,192)`/`(Sha1,256)` → `(KeyBitsWithHash,
UnusableCombination)`. Expectations typed literally, never computed from `can_carry_key_bits` —
a test that recomputes the implementation proves only self-agreement. Assert the `Ok` count is
10 so the table cannot silently shrink.
**T2** Round trip each of the 10 under `IntegrityPolicy::Require` (not the default), so
`<keyData>`'s half — package IVs, HMAC, both integrity blobs — is proved at every hash.
**T3** Wrong password per tuple → `WrongPassword`, never `BadParameters`. Without it T2 passes
on a verifier that accepts anything.
**T4** Lengths per tuple, including AES-192's 32-byte blob with bytes `24..32` asserted **zero**.
**T5** Blob unwrap per tuple, including `recover_session_key`'s truncation at 192.
**T6** `salt_size ∈ {1, 8, 15, 16, 17, 24, 32, 64, 65536}` — the non-multiples make `fit_iv` and
the verifier pad live; 65 536 additionally asserts the stream stays under
`ENCRYPTION_INFO_READ_CAP` (≈258 KiB against 1 MiB), backed by a `const _: () = assert!`.
**T7** One test per `(param, problem)` cell, asserting **both payload fields** — the point of the
typed error is that this is possible without string matching.
**T8** Precedence: `key_bits: 200, hash: Sha1` → `(KeyBits, UnsupportedByCipher)`.
**T9** `validate` runs before the RNG: a failing call must consume no draw.
**T10** FRU from `tests/encrypt_entry_points.rs` (separate crate) — the compile-time proof that
omitting `#[non_exhaustive]` was necessary.
**T11** `EncryptParams::default()` asserted as a literal, so a default change fails by name.

**The two goldens must not move.** Draw order, number and length are unchanged on the default
path (16/16/32/16/64), and `fit_iv(salt,16)` is the identity, so only the *call* changes in
`agile_encrypt_tests.rs:46` and `:322`. **If either moves, stop and fix the draw path — do not
re-measure.** Keep `fill()` rather than reaching for `new_with` on the RNG path, which cannot
carry a `Result` out of its closure.

**Evidence pass:** delete `validate()?`, the `fit_iv` line, and assertion #7 in turn; record
which test failed and how; restore.

## Item 7 — interop, measured

Ten tuples × four readers, plus three salt sizes. Predictions grounded in what is already
written down, so the run can falsify them: LibreOffice refuses AES-256/SHA-256 and AES-256/SHA-384
(allowlist, `development-record.md:110-120`); msoffcrypto refuses SHA-1 agile
(`ecma376_agile.py:466`) and cannot read its own AES-192 (`development-record.md:324`);
office-crypto 0.3 refuses every non-SHA-512 agile file.

**`saltSize ≠ 16` is the real unknown, and Word is the risk.** Before blaming our writer, run the
isolating experiment: extend `tools/gen_agile_fixtures.py`'s existing hook with `saltSize`, have
**msoffcrypto** write a `saltSize=8` file, and open that in Word. That separates "Word dislikes
`saltSize≠16`" from "Word dislikes *our* file" — the technique that produced the five existing
fixtures.

`acceptance_gate.py` needs **no changes**; it is already tuple-agnostic. Leave the existing
single-artifact test and its file name alone (CI and the README both name it) and add a sibling
that writes the matrix.

**Who this crate is for, and what that does and does not decide.** It exists for the
encrypted-file-vault application: that consumer's constraints are first-class requirements and
coordination with it is an obligation, not a courtesy. It does **not** follow that the crate
implements only what that consumer asks for — correctness is fidelity to [MS-OFFCRYPTO], and
the completeness that falls out of taking the spec seriously is a bonus for everyone else who
takes the crate off crates.io. Two consequences, both load-bearing below:

- **No consumer-shaped affordances in the public API.** A function whose shape comes from one
  integrator's dispatch is wrong even when that integrator is the reason the crate exists. The
  test is whether a stranger with no knowledge of that application would want the same thing.
- **The docs must stand alone.** rc.2 and rc.3 are on the registry with real downloads, so
  readers without any of this context already exist.

**Reader evidence stays out of the API, but the need is met — decided, not open.** A request
exists for something like `EncryptParams::has_external_reader_evidence() -> bool`. The API half
is declined on two independent grounds, the first sufficient by itself:

1. **It is not a fact about the format.** What Word 16.0.19127 opens on one machine in September
   2026 is a measurement about third-party software, not a property of [MS-OFFCRYPTO]. Encoding
   it in this crate's API would make the library assert a consumer's interop policy as though it
   were a spec fact — the same category error as letting a sibling crate's margin stand in for a
   spec range, which is what § *Governing principle* exists to stop.
2. It cannot be kept true. It goes stale the moment any reader changes, and stale-but-typed is
   the failure mode this whole plan is about.

**But declining the API is not declining the need**, and treating it that way would leave the
one application this crate exists for gating itself to the default tuple — shipping a parameter
space its only consumer cannot safely use. So the grid also ships as a **dated, machine-readable
artifact in the repository**, versioned with the crate and carrying reader names, versions and
measurement date as data. Anyone's build can consume it; the library asserts nothing it cannot
keep true; and the staleness is visible in the file rather than hidden behind a `-> bool`. It
serves a stranger and that consumer identically, which is the test from the section above.

The prose home stays the dated grid in `CHANGELOG.md` and the README split of *writable* from
*externally accepted*. **A tuple no external reader opens is still written**, because the spec
defines it; the grid records what readers did, and does not decide what the crate implements.

### The ultimate check is the owner opening the files in real Office, by hand

Above the automated gate and above every differential oracle. **This is the deliverable, not a
by-product**, and it is not redundant with `office_com_check.ps1`: that drives Word through COM,
and the interactive open path is a different one — Protected View, the Trust Center, and the
password prompt itself all sit on the manual path and not necessarily on the automated one. A
file COM opens is not proof a person can open it.

So the run produces a **durable, named artifact set the owner can double-click**, not a
`mktemp` directory the automation consumes and forgets:

```
artifacts/tuples-2026-09-20/
  agile_sha512_256_default.docx      ← must be byte-identical to the 41,984 golden
  agile_sha512_192.docx   agile_sha512_128.docx
  agile_sha384_256.docx   agile_sha384_192.docx   agile_sha384_128.docx
  agile_sha256_256.docx   agile_sha256_192.docx   agile_sha256_128.docx
  agile_sha1_128.docx
  agile_default_salt8.docx  agile_default_salt24.docx  agile_default_salt32.docx
  standard_aes128.docx    standard_aes192.docx    standard_aes256.docx   ← skip 1
  MANIFEST.md
```

`MANIFEST.md` carries, per file: the tuple in words, the password (`testpass`), the SHA-256, the
expected document text, and **what a failure would mean** — so a refusal can be reported back
precisely rather than as "this one didn't work". One `.docx` per tuple is the minimum; `.xlsx`
and `.pptx` for the default tuple as well, since Excel and PowerPoint have each already produced
a distinct finding in this crate's history.

**How the owner's verdict is used.** It outranks everything else in the grid. If real Word
refuses a file on the interactive path, that is case 1 or case 2 below and it blocks — and it
blocks even if the COM leg passed, in which case the divergence between the two paths is itself
the finding.

**Word is not one of the four readers for this purpose — it is the reference.** A refusal from
Word 16.0.19127 on a file this crate believes is conforming is **never** `REFUSED-BY-READER`.
Microsoft wrote the format and wrote that implementation, so a disagreement is one of exactly
two things, and both are issues to sort out rather than cells to annotate:

1. **Our output is wrong** — we misread §2.3.4.10, or a length, pad or IV is subtly off. This is
   the default assumption and it blocks. Everything already known about Word's pickiness in this
   format arrived this way: the zero-pad rule (`0x800A1066`, thirteen measured variants) and the
   verifier-value tail (`0x800A1520`) were both *our* bugs, found because Word said no.
2. **Word diverges from its own published spec** — possible, and then the finding is the
   deliverable: record the exact AlgID/tuple/build, cite the spec clause it contradicts, and
   bring it back for a decision. It does not silently become a documented caveat.

**The authority is the specification, and nothing else is.** CLAUDE.md already says it —
*"prefer the spec over any implementation, and cite section numbers"* — and it applies to every
other program in this exercise. msoffcrypto-tool, LibreOffice, office-crypto and herumi are
**interpretations of the same document**, useful as differential oracles and never as a
standard. Word is Microsoft's own implementation, which makes a disagreement with it serious;
it does not make Word automatically right, and this repository already records Word departing
from its own documented behaviour (`development-record.md:230`, where it ignored the registry
setting that selects the encryption tuple and wrote AES-256/SHA-512 regardless).

**So the mandated first move on a Word refusal is to re-derive the bytes from the clause**, not
to compare against another program. Read §2.3.4.10 for the field in question, compute what a
conforming writer must emit, and check our output against *that*. The verdict is "the spec says
X and we wrote Y", with a section number.

The differential run stays, demoted to what it actually is: **a locator, not an adjudicator.**
Extending `tools/gen_agile_fixtures.py`'s hook so msoffcrypto emits the same tuple, and opening
that in Word, narrows *where* in the byte stream to look — Word opening theirs and refusing ours
means our bytes differ from theirs somewhere, which is a search hint. It never establishes that
theirs are correct; two implementations agreeing is two interpretations agreeing, and this
repository has already found bugs in the references it ports from
(`development-record.md` § 4). If the spec is silent or genuinely ambiguous on the point, that
ambiguity is the finding and it comes back for a decision — it is not resolved by vote.

The same standard applies to the AES-192/256 standard-encryption work from skip 1: those AlgIDs
are Microsoft's own, so Word refusing a file that declares one is a finding, not a caveat.

Record a **tuple × reader grid**, each cell exactly one of `PASS` / `FAIL` (ours — blocks) /
`REFUSED-BY-READER` (with a citation) / `NOT RUN`, plus an arithmetic summary. Three rules:
`REFUSED-BY-READER` never collapses into `NOT RUN`; a `REFUSED-BY-READER` without a citation is
a `FAIL`; **the Word column may only hold `PASS`, `FAIL` or `NOT RUN`** — `REFUSED-BY-READER` is
not available there, by the rule above; and a tuple whose row has zero `PASS` is documented as one this crate writes and no
external reader has read — on CI that is at least SHA-1/128. **A zero-pass row is a fact to
record, not a reason to stop writing the tuple**: the spec defines it, so the crate implements
it, and the grid says what the readers of the day did with it. `README.md:194` must split
*writable* from *externally accepted*; collapsing them is the overstatement `audit_claims.py`
exists to catch.

## Item 8 — prose

- **`src/lib.rs:152-156` is wrong in the tree right now**, from my commit `ad64424`: the bounds
  section still says `spinCount` is capped at 2^21 "far below the 10 000 000 the spec permits".
  Fix regardless of the rest of this plan.
- `src/lib.rs:541-544` — the "profile is fixed … no parameter to change it" paragraph. Scope the
  fixed half to `encrypt_ooxml` and point at the new entry point; **keep the unconditional
  `<dataIntegrity>` guarantee intact**, since it holds for every tuple.
- `CHANGELOG.md:176` ships that guarantee as an rc.4 note — amend in place; rc.4 is unreleased.
- `README.md:8,57,194`, the module headers in `agile_encrypt.rs` and `encryption_info.rs`,
  `CLAUDE.md` § Layout (new module line), and a changelog entry covering the parameters, the ten
  combinations, the heap-residue fix and the interop grid.

---

## Implementation order

Each step compiles and its tests pass before the next.

0. **The provenance sweep** from § *Governing principle* — the CLAUDE.md MIN/MAX rule, the
   `limits.rs` module doc, `PAYLOAD_CEILING`'s inverted burden, and a re-walk of the
   spec/cipher/margin table against the PDF. Prose and one rule, no code. First, because it is
   the standard everything after it is measured against, and because doing it after would mean
   building the feature under the methodology being audited.
1. `hash.rs`: `can_carry_key_bits`; rewrite `agile.rs:1137` and `:641` to call it; `digest_len`/
   `name` public. *Pure refactor — whole suite green, goldens untouched. This is the baseline.*
2. `error.rs`: the variant + the two payload enums; canary arm = 1. *`E0004` tells you it landed.*
3. CLI: `exit_code` → `EX_USAGE`; the deliberate-forward comment; the test assertion.
4. `encrypt_params.rs` + tests T1, T7, T8, T11; wire the module and re-export. *Self-contained.*
5. `integrity.rs:487` `pad_zero` → wrapped single allocation. *Byte-identical at SHA-512, so the
   container golden is the check.*
6. `encryption_info.rs`: delete the consts and `mod lengths`; absorb `params`; derive all seven
   lengths with `key_blob` at #7. *The 1 289-byte Office byte-identity test is the proof.*
7. `agile_encrypt.rs`: the salts, the params, `fit_iv`, the three final-length allocations, the
   AES-192 key blob. **Run both goldens now.**
8. `lib.rs`: the new entry point, `encrypt_ooxml` as one line, the rustdoc surgery, crate-doc
   lists.
9. Tests T2–T6, T9, T10; then the evidence pass.
10. Artifacts: the durable `artifacts/tuples-<date>/` set plus `MANIFEST.md`, the local gate over
    the matrix, the grid in `CHANGELOG.md`, CI steps. **Then hand the directory over and stop for
    the manual Office check** — it is the gate on shipping, not a formality after it.
11. Prose, then `python tools/audit_claims.py` — it range-checks every `file:line` added above.

## Verification

Full matrix from CLAUDE.md § *Build and verify*, **one cargo at a time**: five `cargo test`, five
`cargo clippy -- -D warnings`, `cargo fmt --check`, both `cargo doc` under
`RUSTDOCFLAGS="-D warnings"`, `cargo deny`, `audit_claims.py`.

Then, into a private artifact directory:

```bash
export MSOFFICE_CRYPTO_ARTIFACT_DIR="$(mktemp -d)"
cargo test --locked --no-default-features --features crypto-ops
for f in "$MSOFFICE_CRYPTO_ARTIFACT_DIR"/*.docx; do
  python tools/acceptance_gate.py "$f" --expect-package tests/fixtures/plain.docx \
    --expect-text-file tests/fixtures/plain_content.txt
done
```

The default artifact must still be `GATE: PASS` 4 of 4 and byte-identical to 41 984 /
`b4cc009e…`. Check `tasklist` for a leaked WINWORD, EXCEL, POWERPNT or soffice after.

**Then the check that decides it:** write the durable artifact set and `MANIFEST.md` described
in Item 7, hand the owner the directory, and **stop**. Their verdict from opening the files in
real Word, Excel and PowerPoint is the one that settles whether this ships, and it is collected
before anything is called done — not after. Any refusal on that path blocks and is worked
through the two-case procedure in Item 7, starting from the spec clause.

**What a green gate proves, stated so it is not overclaimed: interoperability, not
conformance.** Four programs opening a file means four interpretations accepted it. Three of
those four are third-party readings of [MS-OFFCRYPTO] with known defects of their own, and the
fourth is Microsoft's implementation rather than Microsoft's document. Conformance is
established by deriving the bytes from the cited clause and checking ours against it — which is
what the byte-exact goldens against real Office output do for the default tuple, and what the
per-field derivations in `encryption_info::write` must do for every other. `GATE: PASS` is
evidence that the artifact is usable; the spec citation is the evidence that it is right.

Commit in slices on `feat/library-encrypt-guard`, and **stop before pushing**.
