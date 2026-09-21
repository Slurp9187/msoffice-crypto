---
name: msoffice-crypto-secure-gate
description: Handling password-derived key material in msoffice-crypto with secure-gate wrappers. Use when touching spin_hash/derive_block_key/verify_password in agile.rs, derive_standard_key in standard.rs, the RC4 families under legacy-binary, or the encrypt side; or when adding an alias to sensitive.rs. Not for the password argument or the returned plaintext Vec<u8> on the public API — those stay plain by design — and not for cfb_reader/error code, which never sees key material.
---

# secure-gate in msoffice-crypto

**Sole authority for this topic.** `CLAUDE.md` carries the crate-wide rules and points here;
when the two disagree, this file wins on secure-gate and `CLAUDE.md` wins on everything else.

The protocol — access tiers, the residue hazards, Fixed vs Dynamic, alias vs newtype, the
reveal-borrow defect — is in the global `secure-gate` skill. **This file records only what is
true of this crate.**

## Dependency

```toml
secure-gate = { version = "=0.9.0-rc.12", optional = true, default-features = false, features = ["alloc"] }
```

Enabled by the crate's own `crypto-ops` feature, which also turns on `secure-gate/ct-eq` and
`secure-gate/rand`. Not `encoding` — this crate neither displays nor copies key material.

**Optional, on `crypto-ops`.** The rule for adding a secure-gate feature is: *does the
detection build use it?* None of `alloc`, `ct-eq` or `rand` is, so all three ride on
`crypto-ops`. This is not a dependency-count argument — in the build that has key material,
secure-gate and its `zeroize` come along regardless, which is what they are for. What holds is
that no module compiled into the detection build references it, because that build holds no key
material and has nothing to zeroize.

`ct-eq`'s justification is the `dataIntegrity` check specifically: it compares a MAC this crate
computes against a value the *file* supplies — the textbook MAC-forgery oracle shape, where a
short-circuiting `==` leaks how many leading bytes of a forged tag were right. Marginal cost is
zero: `subtle` is a leaf, and `hmac` pulls it in regardless via `digest`'s `mac` feature.

**Every rule in the global skill is read against rc.12.** The rc.13 bump is a coordinated
ecosystem wave — see the global skill's *upgrade* reference. This crate declares no newtypes,
so the rc.13 `derive: [ConstantTimeEq]` break does **not** hit it.

## Boundary — the public API stays plain

`decrypt_ooxml(data: &[u8], password: &str) -> Result<Vec<u8>, _>` is called by code this repo
does not control, and both ends stay plain on purpose: the caller owns the password, and
handing back the plaintext package *is* the function.

**Settled 2026-09-04: the boundary stays plain.** A plan to move it onto secure-gate types was
withdrawn as a design error. Do not reopen it without new evidence, and do not move it
piecemeal.

## The eight aliases

All in `src/sensitive.rs`, all `pub(crate)`, all plain `type` aliases — **not** newtypes.

| Alias | Inner | Holds |
|---|---|---|
| `Utf16Password` | `Dynamic<Vec<u8>>` | the UTF-16LE password bytes the legacy KDFs hash |
| `PasswordDigest` | `Dynamic<Vec<u8>>` | agile `H_final`, standard's 50 000-round SHA-1 digest, RC4 CryptoAPI's `SHA1(salt ‖ password)`, and the five bytes Office 97/2000 RC4 keeps from its second MD5 |
| `DerivedKey` | `Dynamic<Vec<u8>>` | a block key, the XOR-ladder key, the RC4 families' per-block key |
| `XorObfuscationArray` | `Fixed<[u8; 16]>` | the 16-byte XOR obfuscation array of \[MS-OFFCRYPTO\] §2.3.7.2 |
| `SessionKey` | `Dynamic<Vec<u8>>` | the key that decrypts `EncryptedPackage` |
| `VerifierPlaintext` | `Dynamic<Vec<u8>>` | decrypted verifier hash input/value, and the drawn verifier on the encrypt side |
| `IntegrityKey` | `Dynamic<Vec<u8>>` | the HMAC key from `dataIntegrity/@encryptedHmacKey` |
| `IntegrityTag` | `Dynamic<Vec<u8>>` | the expected package HMAC, and the one we compute |

**`Dynamic`, not `Fixed`, and why:** every length here is decided by the *file*. Agile's
`keyBits` comes out of the `EncryptionInfo` XML and sets the derived-key and session-key length
(16/24/32); the digest is 20 or 64 bytes depending on the hash the file names.

**`XorObfuscationArray` is the one `Fixed`**, because its 16 bytes are the *spec's*, not the
file's — the rule applied in the direction the rest of the table does not show. It is
`legacy-binary`-gated, which makes that the only configuration compiling a `Fixed` at all.

**Seven of the eight are the same nominal type.** `SessionKey` is kept separate from
`DerivedKey` because they have different blast radii — a `DerivedKey` is worthless without the
password's digest, while a `SessionKey` decrypts the document on its own and survives a
password change — but that separation buys **readability and grep targets, not compile-time
safety.** Six interchangeable `Dynamic<Vec<u8>>` roles is past the point where the global skill
says to settle the newtype question; it stays a deliberate open choice because nothing has yet
passed the wrong one. Revisit when a ninth appears.

## Tier 1 only

Measured in `src/` (files, not occurrences):

```sh
for m in with_secret with_secret_mut expose_secret into_inner from_rng from_random new_with ct_eq; do
  printf '%-16s %s\n' "$m" "$(grep -rl "$m" --include=*.rs src/ | wc -l)"
done
```

| method | files |
|---|---|
| `with_secret` | 12 |
| `new_with` | 8 |
| `ct_eq` | 6 |
| `from_rng` | 4 |
| `with_secret_mut` | **0** |
| `expose_secret` | **0** |
| `into_inner` | **0** |
| `from_random` | **0** |

**There is no Tier 2 and no Tier 3 in this crate.** Every secret access is a `with_secret`
closure, which is what makes "every access is greppable" actually true here — so keep it that
way, and treat the first `expose_secret` as a decision to argue for rather than a convenience.

⚠️ **Grep trap, confirmed here:** a bare `grep into_inner` returns hits in 9 files, every one
`cursor.into_inner()` or `cfb.into_inner()`. Filter before counting — a case-sensitive
exclusion of `Cursor` alone still reports 17 false hits.

`from_rng`, not `from_random`: **the RNG is injected, never a global.** `generate(password,
spin_count, rng)` takes `&mut R where R: rand::TryRng + rand::TryCryptoRng`, and
`generate_with_system_rng` is a one-line wrapper passing `rand::rngs::SysRng` — so the seeded
path a test drives and the path a caller gets are the same function. Tests use
`chacha20::ChaCha12Rng`, **not** `rand_chacha` (pinned to `rand_core` 0.9, fails `from_rng`'s
bounds) and **not** `rand::rngs::StdRng` (documented non-portable even with a fixed seed, which
would silently invalidate a committed golden).

## Comparisons

All three comparisons use `ct_eq` in the nested-closure form. Only one *needs* it — the
`dataIntegrity` MAC, where the right-hand side is attacker-supplied. `verify_password`'s
channel is far weaker, both operands deriving from the password being guessed. **They were
converted together anyway**, because two comparisons that look identical but were reasoned
about differently is how the wrong one gets copied next.

## Deliberately not wrapped

- **`password: &str` and the returned package `Vec<u8>`** — the public boundary.
- **Salts, IVs, `spinCount`, `keyBits`, the block-key constants** — public by construction.
  Salts and `keyBits` are read from the file's own XML; the five block keys are constants
  published in \[MS-OFFCRYPTO\]. Wrapping a constant that appears in the spec is theater.
- **Ciphertext** — `EncryptedPackage` bytes, `EncryptionInfo` XML, the CFB streams.
- **The per-segment `padded` chunk buffer** in `decrypt_package` — it holds *ciphertext* going
  in, and its decrypted output is appended to `output`, which becomes the public return.
- **Salt and IV on the encrypt side**, drawn from the same injected CSPRNG — they are written
  into `EncryptionInfo` in the clear. Do not wrap what the file publishes.

## Residue

Re-derive from the manifests rather than trusting this list — it was incomplete once already.

- `Sha512`/`Sha1` hashers buffer the raw password until `finalize` and drop unzeroized;
  `sha1`/`sha2` at 0.10 expose no `zeroize` feature.
- **`HmacSha*` holds opad/ipad state derived from `IntegrityKey`, and nothing wipes it.**
  `hmac` 0.12 has no `Drop`, no zeroize, and only `reset`/`std` features — unlike `aes`, `cbc`
  and `rc4` there is no flag to turn on. Exposure is MAC-forgery capability under that key.
  **This entry was missing until the rc.12 audit**, and the way it was missing is the lesson:
  the hasher class directly above it was known, written down, and then not carried across to
  the HMAC path in the same crate.
- `sha2::compress512` spills its message schedule; `W[0..16]` *is* the message block verbatim.
- **The spin loop, specific to this format.** `spin_hash` runs `spinCount` (typically 100 000)
  rounds, each allocating a fresh `Vec` dropped unzeroized — ~100 000 abandoned 64-byte buffers
  per decrypt. They are *intermediate hash states*, not the key, and inverting SHA-512 to get
  back to the password is the work the spin count exists to make expensive. **Do not wrap
  them.** If it ever matters the fix is one reused buffer, not 100 000 wrappers.

## Enforcement

**None for secure-gate usage.** `tools/audit_claims.py` runs in CI but checks documentation
claims, not wrapper discipline. Tier usage, coverage and the reveal-borrow shape are caught in
review only.

The audit record that matters: the rc.12 sweep found `standard_encrypt.rs` building
`VerifierPlaintext::new(verifier.with_secret(|v| Sha1::digest(v).to_vec()))` — wrapped on the
line, leaking in the gap — with the realloc hazard stacked underneath it, both killed by the
same `new_with`. 12 of the 13 sites that sweep flagged were false positives, which is the point
of an over-broad pattern rather than a flaw.

## Verify

The feature split makes this a matrix, not a run. `legacy-binary` is **the only configuration
that compiles `XorObfuscationArray` at all**, so a change to the one `Fixed` alias is invisible
without it.

```bash
cargo test --locked --no-default-features
cargo test --locked --no-default-features --features crypto-ops
cargo test --locked --no-default-features --features legacy-binary
cargo test --locked --no-default-features --features cli
cargo test --locked --no-default-features --features cli,legacy-binary
cargo clippy --locked --all-targets --no-default-features -- -D warnings   # and once per feature set above
cargo fmt --all --check

# the claim the split exists to make:
cargo tree --locked -e normal --prefix none --no-default-features \
  | grep -E '^(aes|cbc|ecb|sha1|sha2|hmac|subtle|rand|secure-gate|zeroize|base64) '   # must print nothing
```

## What did not transfer

- **The global skill's `new_with`-everywhere reading.** A broader `new_with` adoption was an
  approved plan item here; every candidate was checked against the producer rule and the item
  was **cancelled without converting anything**. `new` is a move and is correct where the
  producer returns owned.
- **Newtypes.** The global skill says the newtype wins where a role exists, and six
  interchangeable roles is past its threshold. Kept as aliases deliberately — nothing has
  passed the wrong one — and recorded here rather than silently ignored.
- **The `encoding` feature and everything about `EncodedSecret`.** This crate never displays or
  parses key material.
