#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! PowerPoint 97-2003 (`.ppt`) decryption — [MS-PPT] §2.3.7 `CryptSession10Container`,
//! over RC4 CryptoAPI ([MS-OFFCRYPTO] §2.3.5), the only family the format defines.
//!
//! What the format says (§2.3.7): the `Current User` stream is not encrypted; in the
//! `PowerPoint Document` stream the `UserEditAtom`, the `PersistDirectoryAtom` and the
//! `rh` of the `CryptSession10Container` are not encrypted and everything else is; the
//! stream contains exactly one `UserEditAtom`, whose `encryptSessionPersistIdRef` names
//! the persist object holding the container, whose `data` is the encryption header
//! structure. Each persist object is decrypted under the key for the block number equal
//! to its **persist object identifier**, over `8 + recLen` bytes from its offset —
//! except that the `recLen` is itself encrypted, so, like msoffcrypto, this reads each
//! object as extending to the next object's offset (or to the persist directory) and
//! decrypts the gap too, which is a no-op on padding and the same bytes the oracle
//! writes.
//!
//! **The `Pictures` stream** ([MS-PPT] §2.1.3) is decrypted too, which msoffcrypto does
//! not do (`ppt97.py:793`, a TODO) and this crate did not until 0.1.0-rc.6. The rule is
//! in the `CryptSession10Container` section: for "each field of an
//! `OfficeArtBStoreContainerFileBlock` record" ([MS-ODRAW] §2.2.22), the key is block 0
//! and "the size of each field in bytes MUST be decrypted" — the keystream restarts at
//! every field, the 8-byte record header included. Measured 2026-10-14 on
//! `powerpoint97_picture.ppt`: decrypting per field yields a PNG whose signature and
//! `IEND` are where [MS-ODRAW] puts them, and decrypting the body as one run, or
//! continuing the header's keystream into it, yields noise. The fields are [MS-ODRAW]'s
//! (§2.2.24-§2.2.31): `rgbUid1`, `rgbUid2` when the instance is the odd one of its pair,
//! then a 34-byte `OfficeArtMetafileHeader` (EMF, WMF, PICT) or a 1-byte `tag` (JPEG,
//! PNG, DIB, TIFF), then the picture data. A file-block entry (`OfficeArtFBSE`) there,
//! which no PowerPoint build measured here writes, or a blip type and instance [MS-ODRAW]
//! does not define, is refused rather than left encrypted.
//!
//! **Encrypted document properties** (`fDocProps` clear) live in the `EncryptedSummary`
//! stream and are restored by `encrypted_summary`, which says how.
//!
//! What is written back: every persist object decrypted, the `CryptSession10Container`
//! zeroed (header and data), the `UserEditAtom` shortened to `0x1C` with its
//! `encryptSessionPersistIdRef` zeroed in place, and `CurrentUserAtom.headerToken` set
//! to the unencrypted token `0xE391C05F` ([MS-PPT] §2.3.2; PowerPoint 16 writes that
//! token even when encrypting, so on a real file this last write changes nothing). The
//! persist directory is left exactly as it was: its entry for the container now names a
//! zeroed record, which is an unknown record and "MUST be ignored" (§2.1.2).
//!
//! **That last point is where this output differs from `msoffcrypto-tool -d`'s, and the
//! difference is four bytes.** msoffcrypto decrements the first `PersistDirectoryEntry`'s
//! `cPersist` so the directory no longer counts the container — but leaves the atom's
//! `recLen` and the container's offset in place, so a reader walking the atom finds a
//! second entry made of that stray offset, with `cPersist = 0`, which §2.3.5 forbids
//! ("MUST be greater than or equal to 0x001"). PowerPoint 16 refuses the result
//! outright: `0x80048242`, "Office has detected a problem with this file". Measured on
//! 2026-09-05 by bisecting the rewrite — the oracle's bytes with only that word restored
//! open with the full slide text, and every variant keeping the atom at `0x20` is refused
//! whatever the directory says. So `tests/legacy_binary_fixtures.rs` pins this crate's
//! output to its own digest *and* pins that re-applying msoffcrypto's decrement to it
//! reproduces msoffcrypto's digest exactly: identical everywhere but the one word the
//! real application rejects. Word and Excel outputs match the oracle byte for byte.
//!
//! Behaviour ported from msoffcrypto-tool `msoffcrypto/format/ppt97.py` (MIT); see
//! NOTICE. Two further deliberate departures, both for hostile input: persist object
//! extents come from the offsets sorted, not from the directory's order, so no object
//! can be decrypted twice or overlap the next; and an `offsetLastEdit` other than zero
//! is refused, because the spec makes it a MUST and a second edit's objects would
//! otherwise be left encrypted with no error.

use crate::binary_office::{
    self, UserEditAtom, CURRENT_USER, CURRENT_USER_HEADER_TOKEN_AT, POWERPOINT_DOCUMENT,
    USER_EDIT_ATOM_LEN_ENCRYPTED, USER_EDIT_ATOM_LEN_PLAIN,
};
use crate::encrypted_summary;
use crate::error::Error;
use crate::file_params::{bad, wide, AllowedSet, Bound, FileField, FileProblem, Invariant};
use crate::legacy_container::LegacyContainer;
use crate::rc4::{self, BlockKeySchedule};
use crate::rc4_cryptoapi::{self, CryptoApiKeySchedule};

/// `CurrentUserAtom.headerToken` for a file that is not encrypted — [MS-PPT] §2.3.2.
const HEADER_TOKEN_PLAIN: u32 = 0xE391_C05F;

/// [MS-PPT] §2.1.3.
const PICTURES: &str = "/Pictures";
/// `OfficeArtFBSE` — [MS-ODRAW] §2.2.32.
const RT_FBSE: u16 = 0xF007;
/// `rgbUid1` / `rgbUid2` — [MS-ODRAW] §2.2.24-§2.2.31.
const UID_LEN: usize = 16;
/// `OfficeArtMetafileHeader` — [MS-ODRAW] §2.2.31: cbSize(4) rcBounds(16) ptSize(8)
/// cbSave(4) compression(1) filter(1).
const METAFILE_HEADER_LEN: usize = 34;
/// A bitmap blip's `tag` — [MS-ODRAW] §2.2.27-§2.2.30.
const BITMAP_TAG_LEN: usize = 1;
/// `RecordHeader` — [MS-ODRAW] §2.2.1.
const RECORD_HEADER_LEN: usize = 8;

/// A file offset that does not fit this host's `usize`: ours to report (#47).
fn unrepresentable(_: std::num::TryFromIntError) -> Error {
    Error::InvariantViolated(Invariant::Unrepresentable)
}

/// Decrypt the container in place. The container is left untouched on any error.
pub(crate) fn decrypt(container: &mut LegacyContainer, password: &str) -> Result<(), Error> {
    let current_user = container.read(CURRENT_USER)?;
    let doc = container.read(POWERPOINT_DOCUMENT)?;
    let mut src: &[u8] = &doc;

    let edit_offset = binary_office::current_edit_offset(&current_user).ok_or(
        Error::MissingStream("Current User stream shorter than its atom"),
    )?;
    let edit_offset = usize::try_from(edit_offset).map_err(unrepresentable)?;
    let atom = binary_office::user_edit_atom(&mut src, edit_offset as u64).ok_or_else(|| {
        bad(
            FileField::UserEditAtom,
            FileProblem::Unreadable {
                offset: wide(edit_offset),
            },
        )
    })?;
    if atom.rec_len == USER_EDIT_ATOM_LEN_PLAIN {
        return Err(Error::NotEncrypted);
    }
    debug_assert_eq!(atom.rec_len, USER_EDIT_ATOM_LEN_ENCRYPTED);
    // An encrypted presentation contains exactly one user edit ([MS-PPT] 2.3.7).
    if atom.offset_last_edit != 0 {
        return Err(bad(
            FileField::OffsetLastEdit,
            FileProblem::NotRequiredValue {
                got: atom.offset_last_edit.into(),
                required: 0,
                bound: Bound::Spec,
            },
        ));
    }
    let directory_offset =
        usize::try_from(atom.offset_persist_directory).map_err(unrepresentable)?;
    let directory = binary_office::persist_directory(&mut src, directory_offset as u64)
        .ok_or_else(|| {
            bad(
                FileField::PersistDirectory,
                FileProblem::Unreadable {
                    offset: wide(directory_offset),
                },
            )
        })?;
    let session_id = atom
        .encrypt_session_persist_id_ref
        .ok_or_else(|| bad(FileField::EncryptSessionPersistIdRef, FileProblem::Missing))?;
    let session_offset = *directory.get(&session_id).ok_or_else(|| {
        bad(
            FileField::EncryptSessionPersistIdRef,
            FileProblem::Unrecognized {
                got: session_id.into(),
            },
        )
    })?;
    let structure = binary_office::crypt_session_container(&mut src, u64::from(session_offset))
        .ok_or_else(|| {
            bad(
                FileField::CryptSession10Container,
                FileProblem::Unreadable {
                    offset: session_offset.into(),
                },
            )
        })?;
    let session_len = binary_office::record_header(&mut src, u64::from(session_offset))
        .map(|rh| rh.rec_len)
        .unwrap_or(0);

    let header = rc4_cryptoapi::parse(&structure)?;
    let schedule = CryptoApiKeySchedule::new(password, &header.salt, header.key_bits)?;
    schedule.verify(&header)?;

    // The two streams outside `PowerPoint Document` that the password also covers, read
    // and decrypted before anything is written.
    let pictures_plain = if container.exists(PICTURES) {
        let mut pictures = container.read(PICTURES)?;
        decrypt_pictures(&schedule, &mut pictures)?;
        Some(pictures)
    } else {
        None
    };
    let summary = if header.doc_props_in_the_clear() {
        None
    } else {
        Some(encrypted_summary::decrypt(
            container,
            &schedule,
            encrypted_summary::POWERPOINT_STREAM,
        )?)
    };

    // Every persist object must lie below the persist directory ([MS-PPT] §2.3.5), which
    // bounds the total work by the stream's length once the extents are disjoint.
    let mut objects: Vec<(u32, usize)> = Vec::with_capacity(directory.len());
    for (&id, &offset) in &directory {
        let offset = usize::try_from(offset).map_err(unrepresentable)?;
        // Every persist object lies below the directory ([MS-PPT] 2.3.5).
        if offset >= directory_offset {
            let _ = id;
            return Err(bad(
                FileField::PersistObject,
                FileProblem::OutOfRange {
                    got: wide(offset),
                    min: 0,
                    max: wide(directory_offset.saturating_sub(1)),
                    bound: Bound::Spec,
                },
            ));
        }
        objects.push((id, offset));
    }
    objects.sort_by_key(|&(_, offset)| offset);

    let mut plain = doc.clone();
    for (i, &(id, offset)) in objects.iter().enumerate() {
        let end = objects
            .get(i + 1)
            .map_or(directory_offset, |&(_, next)| next);
        if offset == usize::try_from(session_offset).unwrap_or(usize::MAX) {
            // The container: header and data zeroed, bounded by its own recLen, which
            // `crypt_session_container` has already read within the stream.
            let len = 8usize.saturating_add(usize::try_from(session_len).unwrap_or(0));
            let zero_end = offset.saturating_add(len).min(plain.len());
            plain[offset..zero_end].fill(0);
            continue;
        }
        if end <= offset {
            // Two objects at one offset: the sort put them adjacent and the second has no
            // extent. Nothing to decrypt twice.
            continue;
        }
        rc4::decrypt_with_block(&schedule, &mut plain[offset..end], id)?;
    }

    // UserEditAtom: recLen 0x20 -> 0x1C, and the reference field zeroed where it stood.
    let rec_len_at = edit_offset + UserEditAtom::REC_LEN_AT;
    plain[rec_len_at..rec_len_at + 4].copy_from_slice(&USER_EDIT_ATOM_LEN_PLAIN.to_le_bytes());
    let ref_at = edit_offset + UserEditAtom::ENCRYPT_SESSION_REF_AT;
    plain[ref_at..ref_at + 4].fill(0);

    // The persist directory is deliberately not touched -- see the module docs for the
    // four bytes msoffcrypto changes here and what PowerPoint makes of them.

    // The container guarantees the same length; the header token is the one field of
    // `Current User` that changes, and only if it was the encrypted token.
    let mut current_user_plain = current_user.clone();
    if let Some(slot) =
        current_user_plain.get_mut(CURRENT_USER_HEADER_TOKEN_AT..CURRENT_USER_HEADER_TOKEN_AT + 4)
    {
        slot.copy_from_slice(&HEADER_TOKEN_PLAIN.to_le_bytes());
    }

    container.overwrite(POWERPOINT_DOCUMENT, &plain)?;
    if current_user_plain != current_user {
        container.overwrite(CURRENT_USER, &current_user_plain)?;
    }
    if let Some(pictures) = pictures_plain {
        container.overwrite(PICTURES, &pictures)?;
    }
    if let Some(summary) = summary {
        summary.write(container)?;
    }
    Ok(())
}

/// Decrypt a `Pictures` stream in place, record by record and field by field (module
/// docs). Every record must be a blip [MS-ODRAW] defines and must fit the stream; the
/// walk advances by at least the 8-byte header each time, so it ends.
pub(crate) fn decrypt_pictures(
    schedule: &dyn BlockKeySchedule,
    pictures: &mut [u8],
) -> Result<(), Error> {
    let len = pictures.len();
    let mut at = 0usize;
    let mut index = 0usize;
    while at < len {
        let header = pictures
            .get_mut(at..at + RECORD_HEADER_LEN)
            .ok_or_else(|| {
                let _ = index;
                bad(
                    FileField::PicturesRecord,
                    FileProblem::Truncated {
                        have: wide(len - at),
                        need: wide(RECORD_HEADER_LEN),
                    },
                )
            })?;
        rc4::decrypt_with_block(schedule, header, 0)?;
        let ver_instance = u16::from_le_bytes([header[0], header[1]]);
        let rec_type = u16::from_le_bytes([header[2], header[3]]);
        let rec_len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

        let fields = blip_fields(rec_type, ver_instance)?;
        let body_start = at + RECORD_HEADER_LEN;
        let body_end = usize::try_from(rec_len)
            .ok()
            .and_then(|n| body_start.checked_add(n))
            .filter(|&end| end <= len)
            .ok_or_else(|| {
                bad(
                    FileField::PicturesRecord,
                    FileProblem::OutOfBounds {
                        offset: wide(body_start),
                        len: rec_len.into(),
                        end: wide(len),
                    },
                )
            })?;
        let body = pictures
            .get_mut(body_start..body_end)
            .ok_or(Error::InvariantViolated(Invariant::InternalSlice))?;
        let mut field_start = 0usize;
        for size in fields {
            let field_end = field_start + size;
            let field = body.get_mut(field_start..field_end).ok_or_else(|| {
                bad(
                    FileField::PicturesRecord,
                    FileProblem::Truncated {
                        have: rec_len.into(),
                        need: wide(field_end),
                    },
                )
            })?;
            rc4::decrypt_with_block(schedule, field, 0)?;
            field_start = field_end;
        }
        // The picture data: the rest of the record, one field.
        if let Some(data) = body.get_mut(field_start..) {
            rc4::decrypt_with_block(schedule, data, 0)?;
        }
        at = body_end;
        index += 1;
    }
    Ok(())
}

/// The fixed fields of a blip before its data, by [MS-ODRAW] §2.2.24-§2.2.31: each
/// type's two instances differ only in whether a second UID follows the first.
fn blip_fields(rec_type: u16, ver_instance: u16) -> Result<Vec<usize>, Error> {
    let rec_ver = ver_instance & 0x000F;
    let instance = ver_instance >> 4;
    if rec_type == RT_FBSE {
        return Err(Error::UnsupportedEncryptedContent(
            "a file-block entry (OfficeArtFBSE) in the Pictures stream",
        ));
    }
    let (pair, trailer) = match rec_type {
        0xF01A => ([0x3D4, 0x3D4], METAFILE_HEADER_LEN), // EMF
        0xF01B => ([0x216, 0x216], METAFILE_HEADER_LEN), // WMF
        0xF01C => ([0x542, 0x542], METAFILE_HEADER_LEN), // PICT
        0xF01D => ([0x46A, 0x6E2], BITMAP_TAG_LEN),      // JPEG, RGB and CMYK
        0xF01E => ([0x6E0, 0x6E0], BITMAP_TAG_LEN),      // PNG
        0xF01F => ([0x7A8, 0x7A8], BITMAP_TAG_LEN),      // DIB
        0xF029 => ([0x6E4, 0x6E4], BITMAP_TAG_LEN),      // TIFF
        0xF018..=0xF117 => {
            return Err(Error::UnsupportedEncryptedContent(
                "a Pictures record of a blip type [MS-ODRAW] does not define",
            ))
        }
        // A record type is a value the file declares, so this is a bad parameter;
        // `UnsupportedEncryptedContent` is for content of a known kind not decrypted.
        other => {
            return Err(bad(
                FileField::PicturesRecord,
                FileProblem::NotInSet {
                    got: other.into(),
                    allowed: AllowedSet::PicturesRecordTypes,
                    bound: Bound::Spec,
                },
            ))
        }
    };
    if rec_ver != 0 || !pair.contains(&(instance & !1)) {
        return Err(bad(
            FileField::PicturesRecord,
            FileProblem::Unrecognized {
                got: ver_instance.into(),
            },
        ));
    }
    let mut fields = vec![UID_LEN];
    if instance & 1 == 1 {
        fields.push(UID_LEN);
    }
    fields.push(trailer);
    Ok(fields)
}
