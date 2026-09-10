//! Serialise the agile `\EncryptionInfo` stream — the inverse of `agile`'s parser.
//!
//! GH #6 step 3. The stream is an 8-byte binary header followed by a UTF-8 XML document:
//!
//! ```text
//! u16 vMajor = 4 | u16 vMinor = 4 | u32 Reserved = 0x00000040 | <encryption …>
//! ```
//!
//! # The shape is Word's, measured rather than composed
//!
//! Word 16, Excel 16 and PowerPoint 16 write a **byte-identical 1 289-byte stream** for
//! the same tuple — verified across `tests/fixtures/{word16_agile.docx,
//! excel16_agile.xlsx, powerpoint16_agile.pptx}`, whose XML differs only in the base64
//! values. That is the target this module reproduces exactly, down to the `\r\n` after the
//! declaration and the absence of a space before every `/>`.
//!
//! herumi writes the same document from a `snprintf` template (`crypto_util.hpp:356-390`,
//! BSD-3) and differs in exactly two places: a bare `\n` after the declaration, and the
//! `xmlns:c` certificate namespace only when its `isOffice2013` flag is set. Word emits
//! `\r\n` and always declares `xmlns:c`, so **this follows Word**. Both readings of the
//! format are fine; matching the one that ships in the product is the cheaper bet when
//! GH #8's acceptance bar is real Word opening the result.
//!
//! Nothing here is copied from herumi. The document is written from the fixture bytes
//! this repository already carries, which is a fact about Microsoft's output rather than
//! anyone's expression — the same posture as `dataspaces`.
//!
//! # Nothing secret and nothing attacker-controlled is interpolated
//!
//! Every value written below is either an integer this module chose or base64 of bytes
//! the caller generated. The password never appears in this document — that is the point
//! of the verifier blobs — and base64's alphabet cannot produce `<`, `>`, `&` or a quote,
//! so there is no escaping to get wrong and no injection to defend against. Keeping the
//! only string inputs base64 is what holds that true; do not add a free-text attribute
//! here without revisiting it.
//!
//! # The writer refuses to emit what the reader would reject
//!
//! Every length checked in `write` is one `agile::parse_encryption_info` cross-checks on
//! the way back in. Deriving `saltSize` and `hashSize` from the data rather than accepting
//! them as parameters is the same idea: the two cannot disagree because there is only one
//! source. A writer that can emit a file its own reader refuses is a bug generator, and
//! this crate is both halves.

use crate::error::Error;
use crate::hash::HashAlgorithm;
use crate::limits;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

/// `EncryptionInfo.vMajor` / `vMinor` for agile encryption — [MS-OFFCRYPTO] §2.3.4.10.
const AGILE_VERSION: (u16, u16) = (4, 4);

/// The AES block size, which is also `blockSize` on both elements.
const AES_BLOCK_LEN: usize = 16;

/// The one tuple this crate writes: AES-256 in CBC under SHA-512.
///
/// Not a parameter, and no longer because the reader would refuse the output: GH #13
/// widened `agile::aes_cbc_decrypt` to all three AES key sizes, so this crate now opens
/// what it declines to write. It stays fixed because one tuple is the tuple Office 16
/// itself writes, and every byte-identity test against real Office output is pinned to
/// it — widening the writer would need its own evidence, not merely a reader that
/// tolerates the result. `keyBits` is
/// [`SESSION_KEY_LEN`] × 8 and `hashSize` is the digest length, both derived below rather
/// than repeated.
const CIPHER_ALGORITHM: &str = "AES";
const CIPHER_CHAINING: &str = "ChainingModeCBC";
const HASH: HashAlgorithm = HashAlgorithm::Sha512;

/// AES-256 — the session key length, and `keyBits / 8` on both elements.
pub(crate) const SESSION_KEY_LEN: usize = 32;

/// What Office 16 writes, and what this crate writes.
///
/// 100 000 SHA-512 rounds, measured identically in all three real-Office fixtures. Well
/// under [`limits::SPIN_COUNT_MAX`], which [`write()`] checks against anyway: the ceiling
/// exists to bound a *hostile* file, and emitting one this crate would refuse to read is
/// the failure this module is shaped to prevent.
pub(crate) const OFFICE_SPIN_COUNT: u32 = 100_000;

/// The salt and blob lengths [`write()`] requires, all fixed by the tuple above.
///
/// Each is the length `agile::parse_encryption_info` cross-checks, so they are stated once
/// here and asserted once in [`write()`] rather than being implicit in a caller.
mod lengths {
    use super::{AES_BLOCK_LEN, SESSION_KEY_LEN};

    /// `saltSize` on both elements. Office writes 16.
    pub(super) const SALT: usize = 16;
    /// `encryptedKeyValue` — the session key under a block key, `keyBits / 8` bytes.
    pub(super) const ENCRYPTED_KEY_VALUE: usize = SESSION_KEY_LEN;
    /// `encryptedVerifierHashInput` — `roundUp(saltSize, blockSize)`.
    pub(super) const VERIFIER_INPUT: usize = SALT.div_ceil(AES_BLOCK_LEN) * AES_BLOCK_LEN;
}

/// Everything [`write()`] needs that is not fixed by the tuple.
///
/// All of it is **public by construction**: every field is written into the document in
/// the clear, so none is wrapped and none may be. The session key, the block keys and the
/// spin hash are what produced these blobs and none of them appears here — that separation
/// is the whole reason this struct exists rather than the writer taking the key material.
pub(crate) struct EncryptionInfoParams<'a> {
    /// `keyData/@saltValue` — the package salt.
    pub(crate) key_data_salt: &'a [u8],
    /// `dataIntegrity/@encryptedHmacKey`.
    pub(crate) encrypted_hmac_key: &'a [u8],
    /// `dataIntegrity/@encryptedHmacValue`.
    pub(crate) encrypted_hmac_value: &'a [u8],
    /// `p:encryptedKey/@spinCount`. [`OFFICE_SPIN_COUNT`] unless a caller says otherwise.
    pub(crate) spin_count: u32,
    /// `p:encryptedKey/@saltValue` — the password salt.
    pub(crate) password_salt: &'a [u8],
    /// `p:encryptedKey/@encryptedVerifierHashInput`.
    pub(crate) encrypted_verifier_hash_input: &'a [u8],
    /// `p:encryptedKey/@encryptedVerifierHashValue`.
    pub(crate) encrypted_verifier_hash_value: &'a [u8],
    /// `p:encryptedKey/@encryptedKeyValue` — the wrapped session key.
    pub(crate) encrypted_key_value: &'a [u8],
}

/// Serialise the whole `\EncryptionInfo` stream, header included.
///
/// # Errors
///
/// [`Error::BadParameters`] if any blob is not the length the tuple fixes, or
/// if `spin_count` exceeds [`limits::SPIN_COUNT_MAX`]. Every one of those is a check the
/// parser makes on the way back in, so failing here is the writer declining to produce a
/// file this crate could not read.
pub(crate) fn write(params: &EncryptionInfoParams<'_>) -> Result<Vec<u8>, Error> {
    let hash_size = HASH.digest_len();
    // `roundUp(hashSize, blockSize)` — 64 is already a multiple of 16 under SHA-512, so
    // this is an identity today and is written as the rule rather than as the number so
    // that GH #13's SHA-1 tuple (20 -> 32) does not need it rediscovered.
    let hash_blob = hash_size.div_ceil(AES_BLOCK_LEN) * AES_BLOCK_LEN;

    for (what, got, want) in [
        (
            "keyData/@saltValue",
            params.key_data_salt.len(),
            lengths::SALT,
        ),
        (
            "p:encryptedKey/@saltValue",
            params.password_salt.len(),
            lengths::SALT,
        ),
        (
            "dataIntegrity/@encryptedHmacKey",
            params.encrypted_hmac_key.len(),
            hash_blob,
        ),
        (
            "dataIntegrity/@encryptedHmacValue",
            params.encrypted_hmac_value.len(),
            hash_blob,
        ),
        (
            "p:encryptedKey/@encryptedVerifierHashInput",
            params.encrypted_verifier_hash_input.len(),
            lengths::VERIFIER_INPUT,
        ),
        (
            "p:encryptedKey/@encryptedVerifierHashValue",
            params.encrypted_verifier_hash_value.len(),
            hash_blob,
        ),
        (
            "p:encryptedKey/@encryptedKeyValue",
            params.encrypted_key_value.len(),
            lengths::ENCRYPTED_KEY_VALUE,
        ),
    ] {
        if got != want {
            return Err(Error::BadParameters(format!(
                "{what} is {got} bytes; this crate writes AES-256/SHA-512, which fixes it \
                 at {want}"
            )));
        }
    }

    if params.spin_count > limits::SPIN_COUNT_MAX {
        return Err(Error::BadParameters(format!(
            "spinCount {} exceeds this crate's own ceiling of {}; a file written with it \
             could not be read back",
            params.spin_count,
            limits::SPIN_COUNT_MAX
        )));
    }

    let key_bits = SESSION_KEY_LEN * 8;
    let salt_size = lengths::SALT;
    let b64 = |bytes: &[u8]| BASE64.encode(bytes);

    // One line after the declaration, no indentation, no space before `/>`. Word's exact
    // layout -- see the module header for why it is Word's and not herumi's.
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n\
         <encryption \
         xmlns=\"http://schemas.microsoft.com/office/2006/encryption\" \
         xmlns:p=\"http://schemas.microsoft.com/office/2006/keyEncryptor/password\" \
         xmlns:c=\"http://schemas.microsoft.com/office/2006/keyEncryptor/certificate\">\
         <keyData saltSize=\"{salt_size}\" blockSize=\"{block}\" keyBits=\"{key_bits}\" \
         hashSize=\"{hash_size}\" cipherAlgorithm=\"{cipher}\" cipherChaining=\"{chaining}\" \
         hashAlgorithm=\"{hash}\" saltValue=\"{key_data_salt}\"/>\
         <dataIntegrity encryptedHmacKey=\"{hmac_key}\" encryptedHmacValue=\"{hmac_value}\"/>\
         <keyEncryptors>\
         <keyEncryptor uri=\"http://schemas.microsoft.com/office/2006/keyEncryptor/password\">\
         <p:encryptedKey spinCount=\"{spin}\" saltSize=\"{salt_size}\" blockSize=\"{block}\" \
         keyBits=\"{key_bits}\" hashSize=\"{hash_size}\" cipherAlgorithm=\"{cipher}\" \
         cipherChaining=\"{chaining}\" hashAlgorithm=\"{hash}\" saltValue=\"{password_salt}\" \
         encryptedVerifierHashInput=\"{verifier_input}\" \
         encryptedVerifierHashValue=\"{verifier_value}\" \
         encryptedKeyValue=\"{key_value}\"/>\
         </keyEncryptor></keyEncryptors></encryption>",
        block = AES_BLOCK_LEN,
        cipher = CIPHER_ALGORITHM,
        chaining = CIPHER_CHAINING,
        hash = HASH.name(),
        key_data_salt = b64(params.key_data_salt),
        hmac_key = b64(params.encrypted_hmac_key),
        hmac_value = b64(params.encrypted_hmac_value),
        spin = params.spin_count,
        password_salt = b64(params.password_salt),
        verifier_input = b64(params.encrypted_verifier_hash_input),
        verifier_value = b64(params.encrypted_verifier_hash_value),
        key_value = b64(params.encrypted_key_value),
    );

    let mut stream = Vec::with_capacity(8 + xml.len());
    stream.extend_from_slice(&AGILE_VERSION.0.to_le_bytes());
    stream.extend_from_slice(&AGILE_VERSION.1.to_le_bytes());
    stream.extend_from_slice(&crate::AGILE_ENCRYPTION_RESERVED.to_le_bytes());
    stream.extend_from_slice(xml.as_bytes());
    Ok(stream)
}

#[cfg(test)]
#[path = "encryption_info_tests.rs"]
mod tests;
