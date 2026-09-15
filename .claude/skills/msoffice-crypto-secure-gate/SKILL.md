---
name: msoffice-crypto-secure-gate
description: Handling password-derived key material in msoffice-crypto with secure-gate wrappers. Use when touching spin_hash/derive_block_key/verify_password in agile.rs, derive_standard_key in standard.rs, adding a new cipher or KDF path, or adding the encrypt side (where the rand feature turns on). Not for the password argument or the returned plaintext Vec<u8> on the public decrypt_ooxml API — those stay plain by design — and not for cfb_reader/error code, which never sees key material.
---

# secure-gate in msoffice-crypto

**Sole authority for this topic.** CLAUDE.md carries the crate-wide rules and points here
for secure-gate specifics rather than duplicating them -- when the two disagree, this file
wins on secure-gate and CLAUDE.md wins on everything else. Adapted from the sibling crate
`odf-crypto`'s `odf-crypto-secure-gate` skill — the rules are the same, the material is
not.

## The rule: secure-gate is this crate's zeroizing primitive, full stop

Every value between the password and the decrypted package is wrapped. There is no bare
`Zeroizing` anywhere in `src/`, and no "this one's local so plain is enough" exception.

**Dependency:** `secure-gate = "0.9.0-rc.7"`, `optional = true, default-features = false,
features = ["alloc"]`, enabled by the crate's own `crypto-ops` feature together with
`secure-gate/ct-eq` and `secure-gate/rand`. Not `encoding` — this crate neither displays
nor copies key material. `rand` has been on since GH #6 step 4 (see "When encrypt lands"
below, which has landed).

`ct-eq` was switched on at **S2**, and this is the record the "Comparisons" bullet below
asks for. The reason is the dataIntegrity check specifically: it compares a MAC this crate
computes against a value the *file* supplies, which is the textbook MAC-forgery oracle
shape — a short-circuiting `==` there leaks how many leading bytes of a forged tag were
right. The cost is exactly one crate, `subtle` 2.6, a leaf with no transitive dependencies,
and `hmac` (added in the same slice for the HMAC itself) pulls it in regardless via
`digest`'s `mac` feature. So the marginal dependency cost of `ct-eq` is zero.

secure-gate is **optional, on `crypto-ops`**, since 2026-09-05. It was unconditional
through S1's feature split on the strength of a plan item — "the remaining third of S1
puts its types on the public API, at which point the detection build uses it directly" —
that was withdrawn as a design error. The reason that survives is the one that was
always true: no module compiled into the detection build references it, because the
detection build holds no key material and has nothing to zeroize. This is not a
dependency-count argument; in the build that has key material, secure-gate and its
`zeroize` come along regardless, which is what they are for.

The rule when adding a secure-gate feature is unchanged: does the detection build *use*
it? None of `alloc`, `ct-eq` or `rand` is, so all three ride on `crypto-ops`.

## Scope: the public API stays plain

`decrypt_ooxml(data: &[u8], password: &str) -> Result<Vec<u8>, _>` is called by code this
repo does not control, and both ends stay plain on purpose:

- **`password: &str`** — the caller owns it. Wrapping here adds no protection they don't
  already have, and forces every consumer to depend on secure-gate.
- **The returned `Vec<u8>`** — handing back the plaintext OOXML package *is* the function.
  Wrapping it would be ceremony; the caller receives it in full regardless.

**Settled, 2026-09-04: the boundary stays plain.** The plan to move it onto secure-gate
types at S1 was withdrawn as a design error — both this file and `odf-crypto`'s two
published releases say the boundary stays plain, and the one consumer passes a bare
`&str`. Do not reopen it without new evidence, and do not move it piecemeal.

## What is wrapped

All seven aliases live in `src/sensitive.rs`, all `pub(crate)`. Six are `Dynamic<Vec<u8>>`;
`XorObfuscationArray` is the one `Fixed<[u8; 16]>`, and it is `legacy-binary`-gated, which
makes that the only configuration compiling a `Fixed` at all.

They are plain `type` aliases, not newtypes — since secure-gate 0.9.0-rc.10 deleted the
`*_alias!` macros, they are spelled as `type` lines directly. Two aliases over
`Dynamic<Vec<u8>>` are therefore the *same nominal type*: nothing stops a `SessionKey` being
passed where a `DerivedKey` is meant. The separation buys greppable names and honest doc
comments, not type safety.

| Alias | Holds | Live at |
|---|---|---|
| `PasswordDigest` | agile `H_final` (SHA-512 × `spinCount`), standard's 50 000-round SHA-1 digest, RC4 CryptoAPI's `SHA1(salt ‖ password)`, and the five bytes Office 97/2000 RC4 keeps from its second MD5 | `agile.rs` `spin_hash` return; consumed by `derive_block_key`, `verify_password`. `standard.rs` `derive_standard_key`, inside — **since GH #7**; this row claimed it earlier and the standard path held `H_final` bare until then. Under `legacy-binary`: `rc4_cryptoapi.rs` and `rc4_office97.rs` hold it as a struct field for the life of the key schedule |
| `DerivedKey` | a block key, `SHA512(H_final ‖ block_key)[..keyBits/8]`; standard's XOR-ladder key; the RC4 families' per-block key, zero-padded to 128 bits at exactly 40 | `agile.rs` `derive_block_key` return; `standard.rs` `derive_standard_key` return, consumed by `standard_encrypt.rs` `generate` and `encrypt_package`. Under `legacy-binary`: the `BlockKeySchedule::block_key` return in `rc4_cryptoapi.rs` and `rc4_office97.rs`, consumed by `rc4.rs` |
| `XorObfuscationArray` | the 16-byte XOR obfuscation array of \[MS-OFFCRYPTO\] §2.3.7.2 — the password transformed, not a key in any cryptographic sense | `xor_obfuscation.rs`, built by `xor_array` with `Fixed::new_with` and held as a struct field. `legacy-binary` only. **`Fixed`, not `Dynamic`: its 16 bytes are the spec's, not the file's** — which is the rule below, applied in the one direction the rest of the table does not show |
| `SessionKey` | the key that decrypts `EncryptedPackage`, from `encryptedKeyValue` | `agile.rs` `decrypt`, consumed by `decrypt_package` |
| `VerifierPlaintext` | decrypted `encryptedVerifierHashInput` / `…Value`; on the encrypt side, the drawn verifier and its hash before encryption | `agile.rs` and `standard.rs` `verify_password`; `agile_encrypt.rs` `generate`, `standard_encrypt.rs` `generate` (the standard verifier is drawn straight into the wrapper with `from_rng`) |
| `IntegrityKey` | the HMAC key from `dataIntegrity/@encryptedHmacKey` | `integrity.rs` `verify` |
| `IntegrityTag` | the expected package HMAC, and the one we compute | `integrity.rs` `verify` |

**Why `Dynamic`, not `Fixed`.** Every length here is decided by the *file*, not by us:
agile's `keyBits` attribute comes out of the `EncryptionInfo` XML and sets the derived-key
and session-key length (16/24/32); the digest is 20 or 64 bytes depending on the hash the
file names. Contrast a consuming application's own file key, which is `Fixed` when its
byte count is an architectural constant that application chose. **Reach for `Fixed` when the byte count is fixed by
your design; `Dynamic` when it is fixed by input you don't control.**

`SessionKey` is separate from `DerivedKey` even though both are `Dynamic<Vec<u8>>` and the
same length. They are different secrets with different blast radii: a `DerivedKey` is
worthless without the password's digest, while `SessionKey` decrypts the document on its
own and survives a password change. Type-level separation makes it hard to pass one where
the other belongs.

## What is deliberately NOT wrapped

- **`password: &str`** and **the returned package `Vec<u8>`** — the public boundary; see
  "Scope".
- **Salts, IVs, `spinCount`, `keyBits`, the block-key constants** — all public by
  construction. Salts and `keyBits` are read out of the file's own XML; the five block
  keys are fixed constants published in [MS-OFFCRYPTO]. Wrapping a constant that appears
  in the spec is theatre.
- **Ciphertext** — `EncryptedPackage` bytes, `EncryptionInfo` XML, the CFB streams. Still
  encrypted, not credentials.
- **The per-segment `padded` chunk buffer** in `decrypt_package` — it holds *ciphertext*
  going in. Its decrypted output is appended to `output`, which becomes the public return.

## The pattern

```rust
// spin_hash: the digest is moved into the wrapper, not copied.
fn spin_hash(password: &str, salt: &[u8], spin_count: u32) -> PasswordDigest {
    // ... iterate ...
    PasswordDigest::new(h)
}

// derive_block_key: the digest is read inside the closure; a wrapper comes back out.
fn derive_block_key(h_final: &PasswordDigest, block_key: &[u8; 8], key_bits: u32) -> DerivedKey {
    h_final.with_secret(|hf| {
        let mut hasher = Sha512::new();
        hasher.update(hf);
        hasher.update(block_key);
        let digest = hasher.finalize();
        DerivedKey::new(digest[..(key_bits / 8) as usize].to_vec())
    })
}

// verify_password: two wrapped plaintexts, nested closures, only a bool escapes --
// and the comparison is ct_eq, never ==. (This snippet showed == until 2026-09-05,
// contradicting the rule two paragraphs down; the code never did.)
let matches = verifier_input.with_secret(|vi| {
    let computed = hash.digest(vi);
    verifier_hash.with_secret(|vh| computed.as_slice().ct_eq(&vh[..digest_len]))
});

// decrypt_package: the key is read per segment, never held unwrapped across the loop.
let dec = encryption_key.with_secret(|k| aes256_cbc_decrypt(&padded, k, &iv))?;
```

Three shapes worth naming:

- **Producing functions hand back the wrapper.** `spin_hash`, `derive_block_key`,
  `derive_standard_key` all return a wrapped type, so a caller cannot forget to wrap.
- **Comparisons happen inside nested closures, and use `ct_eq`.** `Dynamic` has no
  `PartialEq` by design — `==` on secrets is the timing-unsafe habit the wrapper exists to
  prevent. Nest the closures, compare with `secure_gate::ConstantTimeEq::ct_eq` on the
  `&[u8]` inside, and let the `bool` out. Prefer that form over the wrapper-level
  `a.ct_eq(&b)`: the wrapper impl calls `expose_secret()` internally, so a wrapper-level
  call does not show up in a `with_secret` audit sweep and quietly breaks the "every
  secret access is greppable" story.

  All three comparisons in the crate use it. Only one of them *needs* it — the
  dataIntegrity MAC, where the right-hand side is attacker-supplied. `verify_password`'s
  channel is far weaker, both operands being derived from the password being guessed. They
  were converted together anyway: two comparisons that look identical but were reasoned
  about differently is how the wrong one gets copied next.
- **Cipher helpers keep plain `&[u8]` signatures.** `aes256_cbc_decrypt` and
  `aes128_ecb_decrypt` are called *from inside* `with_secret`; Rust's auto-deref coerces
  the `&Vec<u8>` closure parameter, so none of them needed a signature change.

## Residual the wrapper cannot reach — know it, don't chase it

- The `Sha512`/`Sha1` hashers buffer the raw password bytes internally until `finalize`,
  and are dropped unzeroized. `sha1`/`sha2` at 0.10 expose no `zeroize` feature.
- `sha2::compress512` spills its message schedule on the stack, and `W[0..16]` of that
  schedule *is* the message block verbatim.
- **The spin loop is the loud one here and is specific to this format.** `spin_hash` runs
  `spinCount` (typically 100 000) rounds, each allocating a fresh `Vec` for the
  intermediate `h` and dropping it unzeroized. That is ~100 000 abandoned 64-byte heap
  buffers per decrypt. They are *intermediate hash states*, not the key — only `H_final`
  derives block keys, and inverting SHA-512 to get from `H_i` back to the password is the
  work the spin count exists to make expensive. Wrapping every round would allocate
  100 000 wrappers to protect values whose secrecy is already the KDF's job. **Don't.**
  If it ever matters, the fix is a single reused buffer, not a wrapper per round.

The fix for the first two is upstream. Do not reimplement SHA here to close them.

## The encrypt side (GH #6 step 4, landed) — the rand rule

`src/agile_encrypt.rs` is the first place this crate generates a secret, and it is where
secure-gate's `rand` feature went on.

**The RNG is injected, never a global** (plan D3). `generate(password, spin_count, rng)`
takes `&mut R where R: rand::TryRng + rand::TryCryptoRng`; the production entry point
`generate_with_system_rng` is a one-line wrapper passing `rand::rngs::SysRng`, so the
seeded path a test drives and the path a caller gets are the same function — a golden then
proves something about production rather than about a second implementation that agrees
today.

```rust
// production: the one-line wrapper
generate(password, spin_count, &mut rand::rngs::SysRng)
// tests -- byte-exact, reproducible; `chacha20::ChaCha12Rng`, NOT rand_chacha (whose
// 0.9 is pinned to rand_core 0.9 and does not satisfy from_rng's bounds) and NOT
// rand::rngs::StdRng (seedable, compiles, and documented non-portable "even with a
// fixed seed" -- which would silently invalidate a committed golden)
generate(password, spin_count, &mut chacha20::ChaCha12Rng::from_seed([0u8; 32]))
```

Inside, the session key is `SessionKey::from_rng(SESSION_KEY_LEN, rng)`, which writes into
the wrapper's own storage via `new_with` so the secret never exists outside it; the
intermediate verifier plaintext is `VerifierPlaintext`; the three encrypted blobs and the
two salts are drawn or produced unwrapped, because every one of them is written into
`EncryptionInfo` in the clear.

**One deliberate departure from the reference**, recorded in that file's header: herumi
draws the session key at `saltSize` (16) bytes and pads to `keyBits / 8` with `0x36`,
which is an AES-256 key with 128 bits of entropy. This crate draws all 32. No round-trip
test in any implementation could have found that, because the key is whatever the writer
says it is.

**The golden bar** is byte-exactness against our own committed golden under the seeded
RNG, plus every external reader (GH #8) opening the result. Diffing against herumi's and
msoffcrypto's bytes for identical inputs was the original bar and was withdrawn: it needs
both tools driven with our salt, IV and session key, for evidence #8 gives more directly.

**Salt and IV stay unwrapped even on the encrypt side** — they are written to
`EncryptionInfo` in the clear, so they are public by construction, exactly like the KDF
parameters beside them. They are drawn from the same injected CSPRNG via
`TryRng::try_fill_bytes`; do not wrap what the file publishes.

## Adding a new alias

1. **Is its length fixed by your own design, or by input you don't control?** By design →
   `fixed_alias!`. By input (a `keyBits` attribute, a hash algorithm named in the file) →
   `dynamic_alias!`, matching the four already there.
2. Declare it `pub(crate)` in `sensitive.rs` beside its peers, with a doc string saying
   what it is and — for a `Dynamic` — why not `Fixed`.
3. Wrap at the point of creation, in the function that produces the value.
4. Check whether it needs to leave the crate on a public signature. Per "Scope" that is
   unlikely before S1 — but if it does, decide it explicitly and record it here.

**S2 (dataIntegrity) landed and this section was wrong about it in two ways**, both worth
keeping as a record of how the reasoning failed:

1. *"It needs no new alias — the two dataIntegrity block keys are `DerivedKey` like their
   three siblings."* There are no dataIntegrity block **keys**. The two constants
   `5f b2 ad 01 0c b9 e1 f6` / `a0 67 7f 02 b2 2c 84 33` derive the two CBC **IVs**; the AES
   key that unwraps both blobs is the `SessionKey`. So the slice introduced two aliases
   instead: `IntegrityKey` (the HMAC key, a real secret with its own blast radius — it
   forges tags) and `IntegrityTag` (the expected and computed MAC, wrapped for the
   comparison shape rather than because a tag is secret). Neither is a `DerivedKey`.
2. *"The HMAC comparison is a nested-closure `bool` like `verify_password`'s."* True of the
   shape, wrong about the operator: `verify_password`'s was `==`. Following that literally
   would have shipped a variable-time MAC comparison. See the `ct-eq` record above.

One factual correction while here: this section claims separating `SessionKey` from
`DerivedKey` "makes it hard to pass one where the other belongs". It does not.
secure-gate's `macros/mod.rs:7-12` is explicit that these are plain `type` aliases, not
newtypes — two aliases over `Dynamic<Vec<u8>>` are the *same nominal type* and are freely
interchangeable. The separation buys readability and grep targets; the compiler enforces
nothing. If nominal separation is ever actually wanted, wrap the alias in a `struct`.

## Verify

S1's feature split landed, so this is a matrix, not a single run. Each row is load-bearing:
the detection build proves it compiles and passes with no cipher crate in the graph;
`crypto-ops` that nothing on the decrypt path regressed; and **`legacy-binary` is the only
configuration that compiles `XorObfuscationArray` at all**, so a change to the one `Fixed`
alias — or to a `use secure_gate::Fixed` import — is invisible without it. The `cli` rows
build the binary, which links the same wrappers through the library.

```bash
cargo test --no-default-features
cargo test --no-default-features --features crypto-ops
cargo test --no-default-features --features legacy-binary
cargo test --no-default-features --features cli
cargo test --no-default-features --features cli,legacy-binary
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --no-default-features --features crypto-ops -- -D warnings
cargo clippy --all-targets --no-default-features --features legacy-binary -- -D warnings
cargo clippy --all-targets --no-default-features --features cli -- -D warnings
cargo clippy --all-targets --no-default-features --features cli,legacy-binary -- -D warnings
cargo fmt --all --check

# and the claim the split exists to make:
cargo tree --no-default-features -e normal | grep -Ei 'aes|sha1|sha2|cbc|ecb|hmac|subtle'
# -> no output
```
