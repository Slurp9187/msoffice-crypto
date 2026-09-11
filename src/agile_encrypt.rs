//! Generate the agile password encryptor: salts, the session key and the three blobs.
//!
//! GH #6 step 4, the inverse of `agile::verify_password`. [MS-OFFCRYPTO] §2.3.4.11-13, and
//! herumi `include/encode.hpp:132-197` (`encode_in`), BSD-3 with attribution in `NOTICE`.
//!
//! ```text
//! password_salt  <- random(16)                       public: p:encryptedKey/@saltValue
//! H_final         = spin(SHA512, password_salt, pw, spinCount)
//! skey1/2/3       = H(H_final || blockKey_{1,2,3})[..32]
//! verifier_input <- random(16)                       secret, never stored in the clear
//! encryptedVerifierHashInput = AES-CBC-Enc(verifier_input,          skey1, password_salt)
//! encryptedVerifierHashValue = AES-CBC-Enc(SHA512(verifier_input),  skey2, password_salt)
//! session_key    <- random(32)                       secret
//! encryptedKeyValue          = AES-CBC-Enc(session_key,             skey3, password_salt)
//! key_data_salt  <- random(16)                       public: keyData/@saltValue
//! ```
//!
//! # The session key is 32 random bytes, drawn at full length
//!
//! **This module deliberately diverged from the reference here, and the reference has since
//! been corrected.** Until 2026-09-10 herumi drew the session key with
//! `FillRand(secretKey, encryptedKey.saltSize)` — the *salt* size, 16 — and then called
//! `normalizeKey(secretKey, encryptedKey.keyBits / 8)`, which is
//! `key.resize(keySize, char(0x36))` (`include/crypto_util.hpp:38-41`). On the AES-256 path
//! that produced a key whose top 16 bytes were the constant `36 36 … 36`: 128 bits of
//! entropy in a 256-bit key. The AES-128 path was unaffected, since `keyBits / 8` and
//! `saltSize` are both 16 there and the padding was a no-op.
//!
//! It read like `saltSize` written where `keyBits / 8` was meant. Nothing downstream
//! noticed — the file decrypts perfectly, in every reader, because the key is whatever the
//! writer says it is — so no round-trip test anywhere could find it. `ms-offcrypto-writer`
//! did not share it (`src/lib.rs:474`, `intermediate_key: [u8; 32]`), which is what made it
//! a bug rather than a reading of the format.
//!
//! **Reported privately to the maintainer and fixed upstream the same day**, in
//! herumi/msoffice commit `b5fed299`, which changes the draw to
//! `FillRand(secretKey, encryptedKey.keyBits / 8)` — the fix suggested in the report. He
//! confirmed the finding and gave permission to describe it. The history is kept because it
//! is why this module draws at full length and why the test below exists; anyone reading
//! today's upstream will find the two implementations agree.
//!
//! This crate draws `SESSION_KEY_LEN` bytes. Porting the padding would have been the
//! easier read of `encode.hpp` and is the kind of thing § *Every input is hostile* exists
//! to catch on the way out as well as in.
//!
//! # Randomness is injected, never taken from a global — plan D3
//!
//! Every draw goes through the `rng` argument, so `generate` under a seeded
//! `chacha20::ChaCha12Rng` is byte-for-byte reproducible and can be committed as a golden.
//! [`crate::encrypt_ooxml`] is the production entry point and is a one-line wrapper over
//! `encrypt`, so the seeded path and the real path are the *same code* rather than two
//! that agree today.
//!
//! **The draw order is herumi's** — password salt, verifier input, session key, keyData
//! salt (`encode.hpp:151, 163, 177, 188`). Nothing in the format depends on it, and this
//! module could draw in any order; matching leaves the door open to diffing against a
//! `SAME_KEY` build of herumi later, and costs nothing to keep.
//!
//! # What is wrapped and what is not
//!
//! `session_key` and the intermediate verifier plaintext are key material and are wrapped.
//! The two salts and all three ciphertext blobs are **written into `EncryptionInfo` in the
//! clear**, so they are public by construction and wrapping them would be theatre — the
//! rule `sensitive.rs` states and `encryption_info::EncryptionInfoParams` relies on.

use crate::agile::{
    aes_cbc_encrypt, derive_block_key, spin_hash, BLOCK_KEY_VALUE, BLOCK_VERIFIER_HASH,
    BLOCK_VERIFIER_INPUT,
};
use crate::encryption_info::{self, EncryptionInfoParams, SESSION_KEY_LEN};
use crate::error::Error;
use crate::hash::HashAlgorithm;
use crate::segments::Segments;
use crate::sensitive::{SessionKey, VerifierPlaintext};
use crate::{dataspaces, integrity, limits};
use rand::{TryCryptoRng, TryRng};
use secure_gate::RevealSecret;

/// `saltSize` on both elements, and the length of the verifier input. Office writes 16.
pub(crate) const SALT_LEN: usize = 16;

/// The AES block size — the multiple every blob is padded up to before encryption.
const AES_BLOCK_LEN: usize = 16;

/// The tuple this crate writes. Kept beside the generator that depends on it; widening is
/// GH #13, and doing it here without widening the decrypt side would produce files this
/// crate could not open.
const HASH: HashAlgorithm = HashAlgorithm::Sha512;

/// `keyBits` for both elements, derived from the session key length rather than repeated.
pub(crate) const KEY_BITS: u32 = (SESSION_KEY_LEN * 8) as u32;

/// One generated password encryptor: what goes in the file, plus the key that does not.
pub(crate) struct AgileKeyMaterial {
    /// `keyData/@saltValue` — public. Seeds every package segment IV and both
    /// dataIntegrity IVs.
    pub(crate) key_data_salt: [u8; SALT_LEN],
    /// `p:encryptedKey/@saltValue` — public. The spin-hash salt, and the literal CBC IV
    /// for all three blobs below.
    pub(crate) password_salt: [u8; SALT_LEN],
    /// The key that actually encrypts the package. **The only secret here**, and the one
    /// value in this struct that never appears in the file except wrapped under
    /// `encrypted_key_value`.
    pub(crate) session_key: SessionKey,
    /// `p:encryptedKey/@encryptedVerifierHashInput` — public ciphertext.
    pub(crate) encrypted_verifier_hash_input: Vec<u8>,
    /// `p:encryptedKey/@encryptedVerifierHashValue` — public ciphertext.
    pub(crate) encrypted_verifier_hash_value: Vec<u8>,
    /// `p:encryptedKey/@encryptedKeyValue` — public ciphertext, the wrapped session key.
    pub(crate) encrypted_key_value: Vec<u8>,
}

/// Generate a password encryptor from an **injected** RNG.
///
/// Deterministic given `rng`, which is the whole point (plan D3): a seeded
/// `chacha20::ChaCha12Rng` makes the output a committable golden, and the production path
/// is [`crate::encrypt_ooxml`] rather than a second copy of this function.
///
/// # Errors
///
/// [`Error::RandomSource`] if the RNG will not produce bytes, and
/// [`Error::BadParameters`] from the key derivation — unreachable for the fixed
/// tuple above, since SHA-512's 64-byte digest comfortably exceeds the 32 bytes
/// `derive_block_key` truncates to, but propagated rather than unwrapped because that
/// argument stops holding the moment GH #13 widens the tuple.
pub(crate) fn generate<R: TryRng + TryCryptoRng>(
    password: &str,
    spin_count: u32,
    rng: &mut R,
) -> Result<AgileKeyMaterial, Error> {
    // Draw order is herumi's; see the module header. Each step is numbered against
    // `include/encode.hpp` so the two can be read side by side.

    // encode.hpp:151 -- the password salt, which is also the CBC IV for all three blobs.
    let mut password_salt = [0u8; SALT_LEN];
    fill(rng, &mut password_salt)?;

    // encode.hpp:156 -- the spin hash, under `p:encryptedKey/@hashAlgorithm`.
    let h_final = spin_hash(HASH, password, &password_salt, spin_count);

    // encode.hpp:158-160 -- the three block keys. Same constants, same order and the same
    // `derive_block_key` the decrypt side uses; deriving them differently here is exactly
    // the drift that would produce a file only this crate could open.
    let skey_verifier_input = derive_block_key(HASH, &h_final, &BLOCK_VERIFIER_INPUT, KEY_BITS)?;
    let skey_verifier_hash = derive_block_key(HASH, &h_final, &BLOCK_VERIFIER_HASH, KEY_BITS)?;
    let skey_key_value = derive_block_key(HASH, &h_final, &BLOCK_KEY_VALUE, KEY_BITS)?;

    // encode.hpp:163-168 -- the verifier input: `saltSize` random bytes, padded up to a
    // block multiple. Wrapped: it is not a key, but hashing it is how a password guess is
    // confirmed offline, so it is worth no more exposure than the keys around it.
    let mut verifier_input = vec![0u8; SALT_LEN];
    fill(rng, &mut verifier_input)?;
    verifier_input.resize(round_up(SALT_LEN, AES_BLOCK_LEN), 0);
    let verifier_input = VerifierPlaintext::new(verifier_input);

    let encrypted_verifier_hash_input = verifier_input.with_secret(|vi| {
        skey_verifier_input.with_secret(|k| aes_cbc_encrypt(vi, k, &password_salt))
    })?;

    // encode.hpp:171-172 -- H(verifier_input), padded up to a block multiple. A no-op for
    // SHA-512 (64 is a multiple of 16) and load-bearing for SHA-1 (20 -> 32); written as
    // the rule so GH #13 does not have to rediscover it.
    let verifier_hash = VerifierPlaintext::new(verifier_input.with_secret(|vi| {
        let mut digest = HASH.digest(vi);
        digest.resize(round_up(HASH.digest_len(), AES_BLOCK_LEN), 0);
        digest
    }));
    let encrypted_verifier_hash_value = verifier_hash.with_secret(|vh| {
        skey_verifier_hash.with_secret(|k| aes_cbc_encrypt(vh, k, &password_salt))
    })?;

    // encode.hpp:177 -- the session key. `SESSION_KEY_LEN` random bytes, drawn at full
    // length rather than drawn short and padded to fit; see the module header.
    let session_key = SessionKey::from_rng(SESSION_KEY_LEN, rng).map_err(random_source)?;
    let encrypted_key_value = session_key
        .with_secret(|sk| skey_key_value.with_secret(|k| aes_cbc_encrypt(sk, k, &password_salt)))?;

    // encode.hpp:188 -- the package salt, drawn last.
    let mut key_data_salt = [0u8; SALT_LEN];
    fill(rng, &mut key_data_salt)?;

    Ok(AgileKeyMaterial {
        key_data_salt,
        password_salt,
        session_key,
        encrypted_verifier_hash_input,
        encrypted_verifier_hash_value,
        encrypted_key_value,
    })
}

/// Encrypt a package into the `EncryptedPackage` stream: the 8-byte little-endian
/// plaintext length, then every 4096-byte segment under its own IV.
///
/// Runs on [`Segments`], the same iterator `agile::decrypt_package` reads through, so the
/// two directions share one segmentation and one IV derivation (plan D4). The final
/// segment is zero-padded to a block multiple — herumi's `data.resize(RoundUp(size, 16))`
/// — and the reader truncates it away against the prefix.
///
/// `hash` is `<keyData>`'s. Production writes SHA-512; the parameter exists so the
/// mixed-hash test can write a file whose `<keyData>` names SHA-1. That file is
/// non-conforming — [MS-OFFCRYPTO] §2.3.4.10 tells a writer the two `hashAlgorithm`
/// attributes MUST match — and a reader must still honour each element.
pub(crate) fn encrypt_package(
    plaintext: &[u8],
    session_key: &SessionKey,
    key_data_salt: &[u8],
    hash: HashAlgorithm,
) -> Result<Vec<u8>, Error> {
    let mut stream = Vec::with_capacity(8 + plaintext.len() + AES_BLOCK_LEN);
    stream.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());
    for segment in Segments::new(plaintext, hash, key_data_salt, AES_BLOCK_LEN)? {
        let segment = segment?;
        let block =
            session_key.with_secret(|k| aes_cbc_encrypt(&segment.padded(), k, &segment.iv))?;
        stream.extend_from_slice(&block);
    }
    Ok(stream)
}

/// Encrypt an OOXML package with a password into a complete CFB container — the whole
/// agile write path, assembled, with the randomness injected.
///
/// The seeded entry point behind [`crate::encrypt_ooxml`], which is one line over this
/// with `rand::rngs::SysRng`. Everything a test can prove about production goes through
/// here: a committed golden under a seeded `chacha20::ChaCha12Rng`, and the external
/// readers in GH #8 opening what a seeded run wrote.
///
/// ```text
/// material  = generate(password, spin_count, rng)                      step 4
/// package   = LE64(len) || AES-CBC per 4096-byte segment, SHA-512 IVs  step 2
/// integrity = integrity::generate(session_key, package, rng)           step 5
/// info      = encryption_info::write(material, integrity)              step 3
/// container = dataspaces::build_container(info, package)               step 1
/// ```
///
/// # Errors
///
/// [`Error::BadParameters`] if `package` exceeds
/// [`limits::PAYLOAD_CEILING`] — the same 1 GiB the decrypt side refuses, checked on the
/// input so that a file this crate writes is a file this crate can read back;
/// [`Error::RandomSource`] if `rng` will not produce bytes;
/// [`Error::Io`] if the in-memory container cannot be written.
pub(crate) fn encrypt<R: TryRng + TryCryptoRng>(
    package: &[u8],
    password: &str,
    spin_count: u32,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    if package.len() > limits::PAYLOAD_CEILING {
        return Err(Error::BadParameters(format!(
            "the package is {} bytes; this crate encrypts at most {} (see \
             limits::PAYLOAD_CEILING), because that is what it will read back",
            package.len(),
            limits::PAYLOAD_CEILING
        )));
    }

    let material = generate(password, spin_count, rng)?;
    let encrypted_package = encrypt_package(
        package,
        &material.session_key,
        &material.key_data_salt,
        HASH,
    )?;
    let blobs = integrity::generate(
        &material.session_key,
        HASH,
        &material.key_data_salt,
        AES_BLOCK_LEN,
        &encrypted_package,
        rng,
    )?;
    let info = encryption_info::write(&EncryptionInfoParams {
        key_data_salt: &material.key_data_salt,
        encrypted_hmac_key: &blobs.encrypted_hmac_key,
        encrypted_hmac_value: &blobs.encrypted_hmac_value,
        spin_count,
        password_salt: &material.password_salt,
        encrypted_verifier_hash_input: &material.encrypted_verifier_hash_input,
        encrypted_verifier_hash_value: &material.encrypted_verifier_hash_value,
        encrypted_key_value: &material.encrypted_key_value,
    })?;
    dataspaces::build_container(&info, &encrypted_package)
}

/// `roundUp(n, multiple)` — the format's padding rule, in one place.
fn round_up(n: usize, multiple: usize) -> usize {
    n.div_ceil(multiple) * multiple
}

/// Fill `dst` from the injected RNG, mapping the RNG's own error into this crate's.
pub(crate) fn fill<R: TryRng + TryCryptoRng>(rng: &mut R, dst: &mut [u8]) -> Result<(), Error> {
    rng.try_fill_bytes(dst).map_err(random_source)
}

/// The RNG's `Display`, which describes the *source* and never its output — on a failure
/// there is no output to describe.
///
/// **This is the one foreign `Display` this crate forwards on purpose**, and it is the
/// exception that `Error`'s own docs argue for rather than assume. `agile::xml_error`
/// classifies quick-xml's instead of forwarding it, because quick-xml's carries text drawn
/// from a document an attacker wrote. An RNG's does not: it names an environment failure —
/// no `getrandom` in the sandbox, an exhausted descriptor table — and that sentence is the
/// whole diagnostic value of the variant. Classifying it to "the random source failed"
/// would leave a caller with an unactionable error where the actionable one was free.
///
/// It is **truncated** all the same. The bound is not about this RNG, whose messages are a
/// short sentence; it is that the generic accepts any `Display`, so the length is a
/// property of whatever is passed rather than of anything checked here. Same reasoning as
/// `agile::unsupported_algorithm`'s 32-character cap on an attribute name: bounded at the
/// construction site, and the variant says so.
pub(crate) fn random_source<E: core::fmt::Display>(e: E) -> Error {
    /// Long enough for any real `io::Error` or `getrandom` sentence, short enough that the
    /// message cannot become a payload.
    const MAX: usize = 200;

    let text = e.to_string();
    let bounded = match text.char_indices().nth(MAX) {
        // `char_indices` keeps the cut on a boundary, so this cannot panic on a multi-byte
        // character the way `truncate(MAX)` would.
        Some((cut, _)) => format!("{}…", &text[..cut]),
        None => text,
    };
    Error::RandomSource(bounded)
}

#[cfg(test)]
#[path = "agile_encrypt_tests.rs"]
mod tests;
