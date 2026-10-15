#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Rights management (IRM) — recognised from the data spaces a CFB container declares,
//! [MS-OFFCRYPTO] §2.1.6 and §2.2.
//!
//! A rights-managed document is encrypted, but not with a password: the key is held by
//! a rights-management server, so no offline implementation opens it. Before this module,
//! `classify` had no way to say so. An IRM-protected `.docx` has no `EncryptionInfo`, so
//! it came back `Unknown`; worse, an IRM-protected `.doc`, `.xls` or `.ppt` carries an
//! **unencrypted placeholder document** beside the protected content (Appendix A <2>:
//! "a short message to the user indicating that the actual document contents are
//! encrypted"), so it classified as `Unencrypted`, and `decrypt_binary_office` answered
//! `NotEncrypted` — telling a caller to keep a placeholder in place of the document.
//!
//! What marks one, from the spec:
//!
//! - **ECMA-376**: a `DataSpaceMap` entry whose data space is named
//!   `DRMEncryptedDataSpace`, mapping the `EncryptedPackage` stream (§2.2, the ECMA-376
//!   IRM data space definition and its `DataSpaceMap` entry).
//! - **Binary documents**: a data space named `\x09DRMDataSpace` — or
//!   `\x09LZXDRMDataSpace`, the compressed variant Appendix A <3> names for §2.2.1 —
//!   mapping the `\x09DRMContent` stream, which [MS-DOC]'s Protected Content Stream
//!   section also names.
//!   The stream on its own is taken as the marker too: LibreOffice's PowerPoint filter
//!   checks exactly that name (`sd/source/filter/sdpptwrp.cxx:161`, MPL, behaviour only).
//!
//! The parse is tolerant, as everything `classify` runs is: a map it cannot read yields
//! no names, never an error and never a panic, and a stream over
//! [`DATA_SPACE_MAP_READ_CAP`] is not read at all. Every length is checked before it
//! indexes, and a name is read only from inside its entry's declared extent. That is
//! also why the walk ends: an entry yields its name only when its extent holds the 8
//! bytes of fixed fields and a 4-byte length prefix, and the walk then advances past
//! it; any entry that does not is the end of the walk. (A separate `Length >= 12` check
//! stood here and was removed: deleting it failed no test, because the extent check
//! below already refuses everything it refused.)

use crate::cfb_reader::read_capped;
use crate::limits::DATA_SPACE_MAP_READ_CAP;
use std::io::{Read, Seek};

/// `\x06DataSpaces\DataSpaceMap` — [MS-OFFCRYPTO] §2.1.6.
const DATA_SPACE_MAP: &str = "/\u{6}DataSpaces/DataSpaceMap";
/// The binary protected content stream — §2.2, and [MS-DOC]'s Protected Content Stream.
const DRM_CONTENT: &str = "/\u{9}DRMContent";
/// The ECMA-376 IRM data space — §2.2.
const ECMA376_DATA_SPACE: &str = "DRMEncryptedDataSpace";
/// The binary-document IRM data spaces — §2.2, and Appendix A <3>.
const BINARY_DATA_SPACES: [&str; 2] = ["\u{9}DRMDataSpace", "\u{9}LZXDRMDataSpace"];

/// `DataSpaceMap.HeaderLength` — §2.1.6: "MUST be equal to 0x00000008".
const HEADER_LENGTH: u32 = 8;
/// A `DataSpaceMapEntry`'s `Length` and `ReferenceComponentCount`, before its components.
const ENTRY_FIXED_LEN: usize = 8;

/// Which kind of rights-managed document a container is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RightsManagement {
    /// An OOXML package under `DRMEncryptedDataSpace`.
    Ecma376,
    /// A `.doc`, `.xls` or `.ppt` whose real content is in `\x09DRMContent`.
    Binary,
}

/// Whether `data` is a rights-managed document, and which kind. `None` for anything else,
/// including a container that does not open.
#[cfg(test)]
pub(crate) fn rights_management(data: &[u8]) -> Option<RightsManagement> {
    let mut cfb = cfb::CompoundFile::open(std::io::Cursor::new(data)).ok()?;
    rights_management_in(&mut cfb)
}

/// [`rights_management`] over an open container.
pub(crate) fn rights_management_in<F: Read + Seek>(
    cfb: &mut cfb::CompoundFile<F>,
) -> Option<RightsManagement> {
    let names = cfb
        .open_stream(DATA_SPACE_MAP)
        .ok()
        .and_then(|s| read_capped(s, DATA_SPACE_MAP_READ_CAP, "DataSpaceMap").ok())
        .map(|map| data_space_names(&map))
        .unwrap_or_default();
    if names.iter().any(|n| n == ECMA376_DATA_SPACE) {
        return Some(RightsManagement::Ecma376);
    }
    if names
        .iter()
        .any(|n| BINARY_DATA_SPACES.contains(&n.as_str()))
        || cfb.is_stream(DRM_CONTENT)
    {
        return Some(RightsManagement::Binary);
    }
    None
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    let bytes = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// A `UNICODE-LP-P4` at `at` — §2.1.2: a `u32` byte count, that many bytes of UTF-16LE,
/// zero padding to a multiple of four — and the offset just past it, or `None` when it
/// does not fit within `end`.
fn lp_p4(b: &[u8], at: usize, end: usize) -> Option<(String, usize)> {
    let len = usize::try_from(le32(b, at)?).ok()?;
    let start = at.checked_add(4)?;
    let stop = start.checked_add(len)?;
    if len % 2 != 0 || stop > end {
        return None;
    }
    let units: Vec<u16> = b
        .get(start..stop)?
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let next = stop.checked_add((4 - len % 4) % 4)?;
    Some((String::from_utf16_lossy(&units), next))
}

/// Every `DataSpaceName` in a `DataSpaceMap`, in order, up to the first entry that does
/// not parse.
pub(crate) fn data_space_names(map: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    if le32(map, 0) != Some(HEADER_LENGTH) {
        return names;
    }
    let Some(count) = le32(map, 4) else {
        return names;
    };
    let mut at = HEADER_LENGTH as usize;
    for _ in 0..count {
        // `Length` counts the whole entry, itself included, as the writer in
        // `dataspaces` writes it and Word, Excel and PowerPoint read it.
        let Some(entry_len) = le32(map, at).and_then(|n| usize::try_from(n).ok()) else {
            break;
        };
        let Some(end) = at.checked_add(entry_len) else {
            break;
        };
        if end > map.len() {
            break;
        }
        let Some(components) = le32(map, at + 4) else {
            break;
        };
        let mut p = at + ENTRY_FIXED_LEN;
        let mut ok = true;
        for _ in 0..components {
            // ReferenceComponentType(4), then the component's name.
            match p.checked_add(4).and_then(|q| lp_p4(map, q, end)) {
                Some((_, next)) => p = next,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            break;
        }
        match lp_p4(map, p, end) {
            Some((name, _)) => names.push(name),
            None => break,
        }
        at = end;
    }
    names
}

#[cfg(test)]
#[path = "data_space_map_tests.rs"]
mod tests;
