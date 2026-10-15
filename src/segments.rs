//! The 4096-byte segment layout the agile package is encrypted in.
//!
//! [MS-OFFCRYPTO] §2.3.4.15 encrypts `EncryptedPackage` in 4096-byte segments, each under
//! its own IV derived from the segment's index:
//!
//! ```text
//! iv(i) = H(keyData.saltValue || LE32(i))[..keyData.blockSize]
//! ```
//!
//! # Why this is a module and not a `for` loop
//!
//! Plan design **D4**. The segmentation is the same on both sides of the format — herumi
//! rounds the whole plaintext up to a 16-byte multiple and cuts 4096-byte segments off it
//! (`include/encode.hpp:74-97`, `EncContent`), and the decrypt path cuts the same segments
//! back out of the ciphertext — but the two are easy to write twice and hard to notice
//! disagreeing, because the writer and the reader here are the same crate and would agree
//! with each other while both being wrong.
//!
//! That is not hypothetical. The IV derivation in `decrypt_package` hardcoded SHA-512 and
//! a 16-byte truncation until GH #11, so a file naming any other `keyData/@hashAlgorithm`
//! decrypted under the wrong IVs *after* `integrity::verify` had already reported
//! `Verified` under the right ones. One place to derive an IV is what makes that class of
//! bug a single edit rather than a search.
//!
//! # Padding
//!
//! The final segment is zero-padded up to an AES block boundary. On the encrypt side this
//! is a real choice and it matches herumi, whose `data.resize(RoundUp(size, 16))` pads with
//! `'\0'` before segmenting; the reader recovers the original length from the stream's
//! 8-byte prefix and truncates, so the pad bytes never reach a caller. On the decrypt side
//! a well-formed final segment is already a block multiple — AES-CBC preserves length — so
//! the padding is defensive, and it is what keeps a truncated file an error from the cipher
//! rather than a panic in it.
//!
//! Rounding the whole buffer once, as herumi does, and rounding only the final segment, as
//! this does, are the same operation: 4096 is a multiple of 16, so no interior segment can
//! be short.

use std::io::Read;

pub(crate) use crate::cfb_reader::read_full;
use crate::error::Error;
use crate::hash::{derive_iv, HashAlgorithm};

/// [MS-OFFCRYPTO] §2.3.4.15 — the agile package segment length.
///
/// A format constant, not a bound: it is fixed by the spec rather than declared by the
/// file, which is why it lives here beside the code that cuts on it rather than in
/// [`crate::limits`]. Same rule that keeps the 16-byte AES block and the 72-byte
/// `EncryptionVerifier` out of that module.
pub(crate) const SEGMENT_LEN: usize = 4096;

/// AES block size in bytes — the multiple the final segment is padded up to.
const AES_BLOCK_LEN: usize = 16;

/// One segment, as [`Segmenter::fill`] left it in the caller's slot.
pub(crate) struct Filled {
    /// Bytes of the input in the slot — [`SEGMENT_LEN`], shorter only for the last.
    pub(crate) len: usize,
    /// `len` rounded up to an AES block. The slot is zero from `len` to here, so
    /// `slot[..padded_len]` is what the cipher takes.
    pub(crate) padded_len: usize,
    /// `H(salt || LE32(index))[..block_size]`.
    ///
    /// The index itself is not carried: decrypt does not need it, encrypt gets it folded
    /// into this value, and a test recovers it by counting. A field kept for a
    /// hypothetical caller is the `allow(dead_code)` argument wearing a different hat.
    ///
    /// Not wrapped: an IV is not key material, and on the encrypt side it is derived from
    /// a salt the file publishes in the clear.
    pub(crate) iv: Vec<u8>,
}

/// Cuts a payload into segments as it is read, giving each the IV its index derives.
///
/// Reads rather than borrows, so neither direction ever holds the whole package: the
/// encrypt path reads plaintext from the caller's reader and the decrypt path reads
/// ciphertext out of the `EncryptedPackage` stream, a segment at a time, into one slot the
/// caller owns and reuses. The slot is the caller's because what it holds differs by
/// direction — plaintext going in to encrypt, plaintext coming out of decrypt — and the
/// caller is the one that knows it must be a wiped buffer.
pub(crate) struct Segmenter<'a> {
    salt: &'a [u8],
    hash: HashAlgorithm,
    block_size: usize,
    /// The index the next segment will carry, or `None` once `u32::MAX` has been used.
    next_index: Option<u32>,
}

impl<'a> Segmenter<'a> {
    /// Segment under `<keyData>`'s hash, salt and block size.
    ///
    /// # Errors
    ///
    /// [`Error::BadParameters`] if `block_size` exceeds the digest the named hash
    /// produces — the IV would be a slice past the end. Checked here, once, before any
    /// hashing, with a message naming the field.
    pub(crate) fn new(
        hash: HashAlgorithm,
        salt: &'a [u8],
        block_size: usize,
    ) -> Result<Self, Error> {
        if block_size > hash.digest_len() {
            return Err(Error::BadParameters(format!(
                "keyData blockSize {} exceeds the {} digest length {}",
                block_size,
                hash.name(),
                hash.digest_len()
            )));
        }
        Ok(Self {
            salt,
            hash,
            block_size,
            next_index: Some(0),
        })
    }

    /// Read the next segment of `reader` into `slot`, zero its tail up to an AES block,
    /// and return where it ends and the IV it takes — or `None` once `reader` is empty.
    ///
    /// Empty input yields nothing rather than one empty segment: a writer handed an empty
    /// package emits no ciphertext, not one segment of padding.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if `reader` fails, a cancelling reader included. [`Error::BadParameters`]
    /// if the payload needs a segment past index `u32::MAX`. The format's IV suffix is LE32,
    /// so a counter allowed to wrap would reuse every IV from zero under one key. No caller in
    /// this crate gets near it — the V3 stream cap allows 2^19 segments — but the cap and this
    /// type are separate concerns, so the counter refuses rather than wraps.
    pub(crate) fn fill<R: Read>(
        &mut self,
        reader: &mut R,
        slot: &mut [u8; SEGMENT_LEN],
    ) -> Result<Option<Filled>, Error> {
        let len = read_full(reader, slot)?;
        if len == 0 {
            return Ok(None);
        }
        let Some(index) = self.next_index else {
            return Err(Error::BadParameters(format!(
                "the payload needs more than 2^32 {SEGMENT_LEN}-byte segments; the IV's                  LE32 index would wrap"
            )));
        };
        self.next_index = index.checked_add(1);

        let padded_len = len.div_ceil(AES_BLOCK_LEN) * AES_BLOCK_LEN;
        // `padded_len <= SEGMENT_LEN` because 4096 is itself a block multiple, so this
        // slice is in bounds; `get_mut` keeps that a fact the code states, not one a
        // panic would report.
        if let Some(tail) = slot.get_mut(len..padded_len) {
            tail.fill(0);
        }
        let iv = derive_iv(self.hash, self.salt, &index.to_le_bytes(), self.block_size)?;
        Ok(Some(Filled {
            len,
            padded_len,
            iv,
        }))
    }
}

#[cfg(test)]
#[path = "segments_tests.rs"]
mod tests;
