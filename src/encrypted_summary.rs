#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The RC4 CryptoAPI encrypted summary stream — [MS-OFFCRYPTO] §2.3.5.4, with its
//! descriptor in §2.3.5.3 — turned back into the two property-set streams it replaced.
//!
//! When a `.doc`, `.xls` or `.ppt` is saved with "Encrypt document properties", the
//! encryption header's `fDocProps` flag is clear, `\x05SummaryInformation` is absent,
//! `\x05DocumentSummaryInformation` is a stub with no properties, and the real two
//! streams travel encrypted inside one more stream. A decrypt that ignores it hands back
//! a "plain" file whose properties are still ciphertext — which `decrypt_binary_office`
//! did until 0.1.0-rc.6, as `msoffcrypto-tool` still does (`ppt97.py:794`, a TODO).
//!
//! No permissive implementation exists to port, so this follows the spec, and where the
//! spec is ambiguous it follows what Office 16 writes, measured 2026-10-14 on the three
//! `*_encprops` fixtures (`tools/gen_password_binary_fixtures.ps1` says how they were
//! made — Office 16 ignores the COM argument and honours only the application setting):
//!
//! - **The stream's name** is "specified by the application" (§2.3.5.4). Word and Excel
//!   call it `encryption`; PowerPoint calls it `EncryptedSummary`, as [MS-PPT] §2.1.6
//!   says and LibreOffice's PowerPoint filter checks for (`sd/source/filter/sdpptwrp.cxx:172`,
//!   MPL, behaviour only — it refuses such a file outright). The name is the caller's.
//! - **The 8-byte prefix is encrypted.** `StreamDescriptorArrayOffset` and
//!   `StreamDescriptorArraySize` decrypt under block 0 to `(8200, 132)` in all three
//!   files, landing exactly at the stream's end; read in the clear they are noise. Step 8
//!   of §2.3.5.4 says "initialize the encryption key … block number of 0" and stops.
//! - **The count and the descriptors** are one run under a fresh block-0 keystream
//!   (step 7), and each stream is decrypted under its own descriptor's `Block` — 0 for
//!   `\x05SummaryInformation` and 1 for `\x05DocumentSummaryInformation` in every file,
//!   though step 2.1 says 0 for any stream. The descriptor is what is read.
//!
//! **What is accepted is what Office writes, and the rest is refused by name, never left
//! encrypted.** The two property-set streams, each at most once; a storage (`fStream`
//! clear) or any other name — both of which the spec permits and no Office build
//! measured here writes — is [`Error::UnsupportedEncryptedContent`]. A decrypt that
//! skipped them would be the bug this module exists to remove, one entry smaller.
//!
//! Every number is the file's and is checked before use: the array lies inside the
//! stream and after the prefix, the count fits the array at its smallest descriptor,
//! each name fits and is NUL-terminated, each stream lies between the prefix and the
//! array, and no two streams overlap. The keystream reuse the spec admits to (§4.1.3,
//! block 0 for the prefix, the array and the first stream) is the format's, not ours.

use crate::binary_office::le32;
use crate::error::Error;
use crate::file_params::{bad, wide, Bound, FileField, FileProblem, Invariant};
use crate::legacy_container::LegacyContainer;
use crate::rc4::{self, BlockKeySchedule};

/// Word's and Excel's name for the stream, measured (module docs).
pub(crate) const WORD_EXCEL_STREAM: &str = "/encryption";
/// PowerPoint's: [MS-PPT] §2.1.6, and measured.
pub(crate) const POWERPOINT_STREAM: &str = "/EncryptedSummary";

pub(crate) const SUMMARY_INFORMATION: &str = "/\u{5}SummaryInformation";
pub(crate) const DOCUMENT_SUMMARY_INFORMATION: &str = "/\u{5}DocumentSummaryInformation";

/// `StreamDescriptorArrayOffset`(4) + `StreamDescriptorArraySize`(4).
const PREFIX_LEN: usize = 8;
/// `EncryptedStreamDescriptorCount`.
const COUNT_LEN: usize = 4;
/// §2.3.5.3: `StreamOffset`(4) `StreamSize`(4) `Block`(2) `NameSize`(1) flags(1)
/// `Reserved2`(4), before the name.
const DESCRIPTOR_FIXED_LEN: usize = 16;
/// The smallest descriptor: the fixed part and a lone NUL terminator.
const DESCRIPTOR_MIN_LEN: usize = DESCRIPTOR_FIXED_LEN + 2;
/// `A – fStream`, bit 0 of the flags byte.
const F_STREAM: u8 = 0x01;

/// The two property-set streams, decrypted and ready to be written back.
pub(crate) struct RestoredSummary {
    stream: &'static str,
    entries: Vec<(&'static str, Vec<u8>)>,
}

impl RestoredSummary {
    /// Remove the encrypted summary stream and write each restored stream in its place.
    pub(crate) fn write(self, container: &mut LegacyContainer) -> Result<(), Error> {
        container.remove(self.stream)?;
        for (name, bytes) in &self.entries {
            container.replace(name, bytes)?;
        }
        Ok(())
    }
}


/// Read and decrypt the encrypted summary stream `stream`, without touching the
/// container. `MissingStream` if it is absent: the caller asks only when `fDocProps` is
/// clear, where [MS-PPT] §2.3.7 says it "MUST exist" and every Office-written file has
/// one.
pub(crate) fn decrypt(
    container: &mut LegacyContainer,
    schedule: &dyn BlockKeySchedule,
    stream: &'static str,
) -> Result<RestoredSummary, Error> {
    if !container.exists(stream) {
        return Err(Error::MissingStream(if stream == POWERPOINT_STREAM {
            "EncryptedSummary (fDocProps is clear)"
        } else {
            "encryption (fDocProps is clear)"
        }));
    }
    let data = container.read(stream)?;
    let entries = decrypt_stream(&data, schedule)?;
    Ok(RestoredSummary { stream, entries })
}

/// The parse and decrypt of the stream's bytes, apart from the container so the
/// hostile-input tests can drive it with synthetic streams.
pub(crate) fn decrypt_stream(
    data: &[u8],
    schedule: &dyn BlockKeySchedule,
) -> Result<Vec<(&'static str, Vec<u8>)>, Error> {
    let Some(prefix) = data.get(..PREFIX_LEN) else {
        return Err(bad(
            FileField::SummaryStream,
            FileProblem::Truncated {
                have: wide(data.len()),
                need: wide(PREFIX_LEN),
            },
        ));
    };
    let mut prefix = prefix.to_vec();
    rc4::decrypt_with_block(schedule, &mut prefix, 0)?;
    let (Some(array_offset), Some(array_size)) = (le32(&prefix, 0), le32(&prefix, 4)) else {
        return Err(Error::InvariantViolated(Invariant::InternalSlice));
    };
    let array_offset = usize::try_from(array_offset).map_err(|_| Error::InvariantViolated(Invariant::Unrepresentable))?;
    let array_size = usize::try_from(array_size).map_err(|_| Error::InvariantViolated(Invariant::Unrepresentable))?;
    let array_end = array_offset
        .checked_add(array_size)
        .filter(|&end| array_offset >= PREFIX_LEN && end <= data.len())
        .ok_or_else(|| {
            bad(
                FileField::SummaryDescriptorArray,
                FileProblem::OutOfBounds {
                    offset: wide(array_offset),
                    len: wide(array_size),
                    end: wide(data.len()),
                },
            )
        })?;
    let mut array = data
        .get(array_offset..array_end)
        .ok_or(Error::InvariantViolated(Invariant::InternalSlice))?
        .to_vec();
    rc4::decrypt_with_block(schedule, &mut array, 0)?;

    let count = le32(&array, 0).ok_or_else(|| {
        bad(
            FileField::SummaryDescriptorArray,
            FileProblem::Truncated {
                have: wide(array_size),
                need: wide(COUNT_LEN),
            },
        )
    })?;
    // Bounds the loop by the array's length before a single descriptor is read.
    let count = usize::try_from(count).map_err(|_| Error::InvariantViolated(Invariant::Unrepresentable))?;
    if count
        .checked_mul(DESCRIPTOR_MIN_LEN)
        .is_none_or(|need| need > array_size - COUNT_LEN)
    {
        return Err(bad(
            FileField::SummaryDescriptorCount,
            FileProblem::OutOfRange {
                got: wide(count),
                min: 0,
                max: wide((array_size - COUNT_LEN) / DESCRIPTOR_MIN_LEN),
                bound: Bound::Spec,
            },
        ));
    }

    let mut entries: Vec<(&'static str, Vec<u8>)> = Vec::with_capacity(count);
    let mut extents: Vec<(usize, usize)> = Vec::with_capacity(count);
    let mut at = COUNT_LEN;
    for i in 0..count {
        let _ = i;
        let fixed = array.get(at..at + DESCRIPTOR_FIXED_LEN).ok_or_else(|| {
            bad(
                FileField::SummaryDescriptor,
                FileProblem::Truncated {
                    have: wide(array.len().saturating_sub(at)),
                    need: wide(DESCRIPTOR_FIXED_LEN),
                },
            )
        })?;
        let (Some(offset), Some(size)) = (le32(fixed, 0), le32(fixed, 4)) else {
            return Err(Error::InvariantViolated(Invariant::InternalSlice));
        };
        let block = u32::from(u16::from_le_bytes([fixed[8], fixed[9]]));
        let name_chars = usize::from(fixed[10]);
        let flags = fixed[11];
        at += DESCRIPTOR_FIXED_LEN;
        let name_len = 2 * name_chars;
        let name_bytes = array.get(at..at + name_len).ok_or_else(|| {
            bad(
                FileField::SummaryStreamName,
                FileProblem::OutOfBounds {
                    offset: wide(at),
                    len: wide(name_len),
                    end: wide(array.len()),
                },
            )
        })?;
        if array.get(at + name_len..at + name_len + 2) != Some(&[0, 0][..]) {
            return Err(bad(FileField::SummaryStreamName, FileProblem::Unterminated));
        }
        let name = property_set_name(name_bytes);
        at += name_len + 2;

        if flags & F_STREAM == 0 {
            return Err(Error::UnsupportedEncryptedContent(
                "a storage inside the encrypted summary stream",
            ));
        }
        let Some(name) = name else {
            return Err(Error::UnsupportedEncryptedContent(
                "a stream inside the encrypted summary stream other than the two property sets",
            ));
        };
        if entries.iter().any(|(seen, _)| *seen == name) {
            return Err(bad(FileField::SummaryDescriptor, FileProblem::Duplicate));
        }

        let offset = usize::try_from(offset).map_err(|_| Error::InvariantViolated(Invariant::Unrepresentable))?;
        let size = usize::try_from(size).map_err(|_| Error::InvariantViolated(Invariant::Unrepresentable))?;
        let end = offset
            .checked_add(size)
            .filter(|&end| offset >= PREFIX_LEN && end <= array_offset)
            .ok_or_else(|| {
                bad(
                    FileField::SummaryStreamExtent,
                    FileProblem::OutOfBounds {
                        offset: wide(offset),
                        len: wide(size),
                        end: wide(array_offset),
                    },
                )
            })?;
        if extents.iter().any(|&(s, e)| offset < e && s < end) {
            return Err(bad(FileField::SummaryStreamExtent, FileProblem::Overlaps));
        }
        extents.push((offset, end));

        let mut plain = data.get(offset..end).ok_or(Error::InvariantViolated(Invariant::InternalSlice))?.to_vec();
        rc4::decrypt_with_block(schedule, &mut plain, block)?;
        entries.push((name, plain));
    }
    Ok(entries)
}

/// The container path for a descriptor's UTF-16LE name, if it is one of the two the
/// module accepts.
fn property_set_name(utf16le: &[u8]) -> Option<&'static str> {
    let units: Vec<u16> = utf16le
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let name = String::from_utf16(&units).ok()?;
    [SUMMARY_INFORMATION, DOCUMENT_SUMMARY_INFORMATION]
        .into_iter()
        .find(|path| path.strip_prefix('/') == Some(name.as_str()))
}
