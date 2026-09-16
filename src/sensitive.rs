//! Key material wrapped with `secure-gate`.
//!
//! Internal only. The public [`crate::decrypt_ooxml`] API still takes
//! `password: &str` and returns a plain `Vec<u8>` — the caller already owns
//! the password, and the decrypted OOXML package *is* the return value, so
//! wrapping either end would be ceremony. Everything between them is wrapped:
//! the spin hash, every block key derived from it, the session key, and the
//! verifier plaintexts that reveal whether the password was right.
//!
//! This is the property that distinguishes this crate from `office-crypto`,
//! `ms-offcrypto-writer`, `msoffcrypto-tool` and `herumi/msoffice`, all of
//! which hold the same values in bare containers. It is not a claim that they
//! are wrong — a CLI that exits after one file has little to gain — but a
//! long-lived process that decrypts documents alongside other secrets does.
//!
//! Every alias whose length the *file* decides is `Dynamic<Vec<u8>>` rather than
//! `Fixed<[u8; N]>` — `XorObfuscationArray` is the exception and says so itself, its 16
//! bytes being the spec's rather than the file's. That choice is
//! forced by the format rather than chosen: the agile `keyBits` attribute is
//! read from the file's own `EncryptionInfo` XML, so the derived key length
//! (16/24/32) is decided by input this crate does not control. The rule, same
//! as odf-crypto's: `Fixed` when the byte count is fixed by *your* design,
//! `Dynamic` when it is fixed by input you don't.

//! These were `dynamic_alias!` / `fixed_alias!` invocations until secure-gate 0.9.0-rc.10
//! deleted all four alias macros. They only ever expanded to a `type` alias, so the change
//! below is spelling: not one call site moved, across ~46 `with_secret` closures, six
//! `ct_eq` comparisons and three `from_rng` draws.
//!
//! They remain aliases rather than `fixed_newtype!` / `dynamic_newtype!` newtypes, and that
//! is deliberate. A newtype would make `SessionKey` and `DerivedKey` distinct types the
//! compiler could keep apart — today they are the same nominal type and nothing stops one
//! being passed where the other is meant. The separation here buys greppable names, not type
//! safety, and the rustdoc on the deleted macros said so. Taking the newtypes is a change
//! worth arguing on its own evidence, not one to smuggle in under a dependency bump.

use secure_gate::Dynamic;

// Gated to match its one alias below: `Fixed` is unused without `legacy-binary`, and the
// unused import would fail `clippy -- -D warnings` in the other three configurations. The
// deleted `fixed_alias!` avoided this by being path-qualified at its single call site.
#[cfg(feature = "legacy-binary")]
use secure_gate::Fixed;

/// The password hash every key in a file derives from — agile's `H_final` after
/// `spinCount` rounds of SHA-512, standard encryption's 50 000-round SHA-1 digest,
/// RC4 CryptoAPI's un-iterated `SHA1(salt || password)` (`legacy-binary`), or the
/// five bytes of Office 97/2000 RC4's second MD5 that its block keys are made from.
/// It is the single most valuable intermediate in the crate. Length follows the
/// hash algorithm named in the file — 20, 32, 48 or 64 bytes — plus the five Office
/// 97/2000 RC4 keeps from its second MD5, hence `Vec<u8>`.
pub(crate) type PasswordDigest = Dynamic<Vec<u8>>;

/// A block key: `Hp(H_final || block_key)` — under the hash
/// `p:encryptedKey/@hashAlgorithm` names — truncated to `keyBits / 8` for
/// agile — one per purpose: verifier input, verifier hash, key value — or, for the
/// RC4 families, `H(H_0 || block_number)` cut to the header's `KeySize` (and zero-padded
/// to 128 bits at exactly 40), one per 512- or 1024-byte block of a stream or per
/// PowerPoint persist object. Length comes from the file's `keyBits` or `KeySize`, so
/// `Vec<u8>` rather than a fixed array.
pub(crate) type DerivedKey = Dynamic<Vec<u8>>;

/// The 16-byte XOR obfuscation array of \[MS-OFFCRYPTO\] §2.3.7.2: the password's
/// bytes, padded, XORed with the 16-bit key and rotated. Not a key in any
/// cryptographic sense — it is the password with a fixed transformation applied,
/// which is exactly why it is held wrapped for the few lines it exists. `Fixed`, not
/// `Dynamic`: the length is the spec's, not the file's.
#[cfg(feature = "legacy-binary")]
pub(crate) type XorObfuscationArray = Fixed<[u8; 16]>;

/// The session encryption key that actually decrypts `EncryptedPackage`, recovered
/// by decrypting `encryptedKeyValue` under a [`DerivedKey`]. This is the key an
/// attacker wants: it is independent of the password and unlocks the document on
/// its own. Length follows `keyBits`.
pub(crate) type SessionKey = Dynamic<Vec<u8>>;

/// A decrypted `encryptedVerifierHashInput` / `encryptedVerifierHashValue`. Not a
/// key, but derived from the password and sufficient to confirm a password guess
/// offline, so it is held wrapped for the few lines it exists.
pub(crate) type VerifierPlaintext = Dynamic<Vec<u8>>;

/// The HMAC key recovered from `dataIntegrity/@encryptedHmacKey`. It is not a block
/// key — the two dataIntegrity block constants derive the *IVs*, and the AES key that
/// unwraps this blob is the [`SessionKey`]. Holding it is equivalent to being able to
/// forge an integrity tag for any package the session key encrypts, so it is wrapped
/// for the few lines between its decryption and the HMAC. Length is
/// `keyData/@hashSize` (20/32/48/64), read from the file's own XML, hence `Vec<u8>`
/// rather than a fixed array.
pub(crate) type IntegrityKey = Dynamic<Vec<u8>>;

/// A package HMAC — both the expected value decrypted from
/// `dataIntegrity/@encryptedHmacValue` and the one this crate computes over the
/// `EncryptedPackage` stream. A MAC tag is not a key and not secret against someone
/// holding the file, but it is wrapped so the comparison happens inside nested
/// `with_secret` closures like every other comparison in the crate, and so neither
/// operand can be printed by accident. Length follows `keyData/@hashSize`, which the
/// file declares, hence `Vec<u8>`.
pub(crate) type IntegrityTag = Dynamic<Vec<u8>>;
