Status: Shipped in #51 (2026-10-19), unreleased until 0.1.0-rc.9 is published. The owner answered all five open points as recommended (2026-10-19 UTC; § Open points). Two findings refined the plan: the stream read cap became `StreamTooLarge { stream, limit }` with no length, because the capped read stops one byte past the limit; and the record walkers' faults needed a `FileProblem::Unreadable { offset }`.

# Plan: a refusal of the file's own settings carries no text from the file

Opened 2026-10-19 by the EFV NATIVE session, the encrypted-file-vault consumer
(EFV master issue #1064, its #309 line). The companion arc in odf-crypto is
`docs/plans/structured-bad-parameters-2026-10-19.md` there.

> **Goal.** `Error::BadParameters` names the field, the value the file declares
> and what was allowed, as closed enums and integers. A consumer can then write
> its own sentence, *"This file declares a spinCount of 12,000,000; the format
> allows at most 10,000,000"*, and nothing the file chose reaches the error or
> its `Display`.

## Why

The owner's decision (2026-10-19 UTC): structure the decrypt-side refusal like a
closed enum of which setting, the value the file declares and the allowed range,
**with no free text from the file anywhere in the error or its Display**.

The survey at `723be5f` (read-only) found:

- **None of the 103 production sites interpolates file text today.** The parts
  that come from the file are integers. The rest is `HashAlgorithm::name()` (a
  closed set), `&'static str` field names and `limits.rs` constants.
- **The `String` payload is still what lets the next site leak.** That is why EFV
  routes every detail through its own `Foreign::token` and the CLI forwards it
  as-is. Structuring the type closes this by construction.
- **The one real channel from the file is outside this variant.**
  `UnsupportedAlgorithm.name` (`agile.rs`) carries the file's own spelling of
  `hashAlgorithm`, `cipherAlgorithm` or `cipherChaining`, truncated to 32
  characters (§ Open points, 3).
- **Only 14 sites are the "declares X, the most we read is Y" kind**, the range
  and margin-cap checks. The rest are structural, cross-field, truncation, or
  internal invariants. A single `OutOfRange` would misstate most of them, hence
  the problem enum below.

## The shape

Keep the variant's name, so every existing `BadParameters(x)` pattern fails to
compile instead of silently changing meaning. It becomes a struct variant, and it
stays ungated because `cfb_reader` builds it in the detection-only build:

```rust
#[error("{field} {problem}")]
BadParameters { field: FileField, problem: FileProblem },
```

- **`FileField`** (`#[non_exhaustive]`, `Copy + Eq`, ungated). The field in the
  spec's own spelling, with separate entries where the format has two copies:
  `KeyDataKeyBits` and `EncryptedKeyKeyBits`, `KeyDataSaltSize` and
  `EncryptedKeySaltSize`, and so on. It covers agile, the binary
  EncryptionHeader/Verifier, the package size and the legacy containers (FIB,
  BIFF, PowerPoint persist and session records, the encrypted summary stream).
  Its `Display` is an exhaustive match with no `_` arm, the `EncryptParam`
  convention.
- **`FileProblem`** (`#[non_exhaustive]`). Integers and closed enums only, `u64`
  so measured lengths fit:
  - `OutOfRange { got, min, max, bound }`: spinCount, saltSize, CryptoAPI
    KeySize, the header-size floor and ceiling, lKey;
  - `NotInSet { got, allowed: AllowedSet, bound }`, for keyBits and the like,
    so a set is never printed as a range;
  - `NotRequiredValue { got, required, bound }`;
  - `Disagrees { got, expected, with: FileField }`;
  - `DigestMismatch { got, hash: HashAlgorithm }` (under `crypto-ops`);
  - `Truncated { have, need }`, and `OutOfBounds { offset, len, end, index }`;
  - the fieldless structural faults: `Missing`, `Duplicate`, `Overlaps`,
    `Unterminated`, `FlagClear`, `BadSignature`, `OutOfOrder { after_record }`,
    `Unrecognized { got }`;
  - `Unrepresentable { got }`.
- **`Bound`** (`Spec`, `Cipher`, `Margin`, `Crate`). Whose number it is, the
  `limits.rs` taxonomy phrased for a file.
- **`EncryptParamProblem` is not reused.** Its wording speaks to a caller, and
  "whose number it is" is the documented reason the two variants are separate.
  The taxonomy is shared, not the type. A test pins that every `limits.rs` label
  has a `Bound` variant.

## The sites, by category (103)

| category | count | becomes |
| --- | --- | --- |
| range or set on one field | 10 | `OutOfRange` / `NotInSet` |
| fixed value or structural | 20 | `NotRequiredValue`, or a fieldless fault |
| cross-field | 10 | `Disagrees` / `DigestMismatch` |
| truncated or out of bounds | 30 | `Truncated` / `OutOfBounds` |
| margin cap | 4 | `OutOfRange { bound: Margin }`; the read cap (`cfb_reader.rs`) moves to a size variant, following rc.7's `PackageTooLarge` |
| internal invariant, unrepresentable, encrypt plumbing | 29 | leave `BadParameters` for `InvariantViolated(Invariant)` (§ Open points, 1) |

## Doc and code mismatches fixed in the same PR

- rc.7 moved the 1 GiB refusal to `PackageTooLarge`, but four docs still say
  `BadParameters` (`lib.rs` twice, `agile_encrypt.rs`, `standard_encrypt.rs`).
- `UnsupportedEncryptedContent`'s doc says an unknown Pictures record type lands
  there, but `powerpoint97.rs` returns `BadParameters`. One of them changes to
  match the other: the record type is a file value, so the doc follows the code.
- A missing spinCount is `XmlParse`, while a missing hashSize or HMAC attribute is
  `BadParameters`. These are made consistent: a missing attribute is
  `FileProblem::Missing`, keeping `XmlParse` for XML that does not parse.

## Open points (answered by the owner 2026-10-19 UTC: all five as recommended)

1. The 29 invariant and plumbing sites leave `BadParameters` for
   `InvariantViolated(Invariant)`, exit 6 → 7. Recommended: yes.
2. (odf-crypto's arc) its row path becomes an index.
3. `UnsupportedAlgorithm.name` closes in this arc: `Known(KnownAlgorithm)` plus
   `Unknown { len }`, with no token, because a cleaned token is still text the
   file chose. Recommended: yes.
4. The shape above, in one PR with three commits, because the tree cannot build
   half converted. Recommended: yes.
5. No written bytes change, but error construction does in encrypt-path files
   (`dataspaces.rs`, `encryption_info.rs`, `integrity.rs`, shared helpers). The
   four-reader gate runs once on the final tree and is recorded. Recommended: yes.

## Slices

One branch, one PR, one rc. Each slice is a sub-issue under the parent and a
commit in the PR.

| slice | what | done when |
| --- | --- | --- |
| S1 | the types; agile (16), standard (9), integrity read side (3), `cfb_reader` (1), `hash` and `segments` plumbing; the invariant sites | those sites and their ~20 tests converted; each rewritten guard broken once to prove it |
| S2 | legacy binary: RC4 CryptoAPI (14), RC4 Office97 and the RC4 core (6), Word 97 (4), Excel 97 (7), PowerPoint 97 (16), encrypted summary (19), legacy container (1), and `legacy_malformed.rs` | every site converted; the ~33 `msg.contains(..)` tests become variant matches |
| S3 | CLI exit map and its canary, rustdoc, README, SECURITY.md, `error.rs` prose, the three mismatches above, `UnsupportedAlgorithm.name` (if 3 is yes), `audit_claims.py --clones`, CHANGELOG `## [0.1.0-rc.9] - Unreleased` | the five-configuration matrix, `cargo doc -D warnings`, `cargo deny` and the four-reader gate (recorded) all pass |

## Release

The owner publishes. This arc bumps `Cargo.toml` to `0.1.0-rc.9` with a
`--locked` refresh and opens the CHANGELOG section. It states the break plainly:
the payload change, every moved meaning (invariant sites, the read cap, any exit
code), and what EFV's pin bump lands. It does not tag, cut or publish.

EFV moves its exact pin only after the owner publishes. Moving msoffice-crypto
again means rerunning EFV's four-reader evidence gate and moving its constants.
EFV's sentence quotes the crate's bound: rc.8 already reads spinCount up to the
spec's 10,000,000, so EFV's old "2,097,152" example is stale.
