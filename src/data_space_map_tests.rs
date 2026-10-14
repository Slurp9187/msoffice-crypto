#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Tests for [`crate::data_space_map`]: the `DataSpaceMap` reader on maps built here, and
//! the rights-management verdict on containers built here. No fixture: nothing on this
//! machine can write an IRM file, so every container is constructed, each from the
//! section of [MS-OFFCRYPTO] its module docs cite.

use super::*;
use std::io::Write;

/// `UNICODE-LP-P4`, the way `dataspaces::write_lp_p4` writes it.
fn lp_p4(text: &str) -> Vec<u8> {
    let units: Vec<u16> = text.encode_utf16().collect();
    let mut out = ((units.len() * 2) as u32).to_le_bytes().to_vec();
    for u in units {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.resize(out.len() + (4 - (out.len() % 4)) % 4, 0);
    out
}

/// A `DataSpaceMapEntry` mapping one stream to `data_space`.
fn entry(component: &str, data_space: &str) -> Vec<u8> {
    let mut body = 1u32.to_le_bytes().to_vec(); // ReferenceComponentCount
    body.extend_from_slice(&0u32.to_le_bytes()); // ReferenceComponentType: stream
    body.extend_from_slice(&lp_p4(component));
    body.extend_from_slice(&lp_p4(data_space));
    let mut out = ((body.len() + 4) as u32).to_le_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

fn map(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = 8u32.to_le_bytes().to_vec();
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        out.extend_from_slice(e);
    }
    out
}

/// A CFB holding `streams`, storages created as their paths need them.
fn container(streams: &[(&str, &[u8])]) -> Vec<u8> {
    let mut cfb = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).unwrap();
    for (name, bytes) in streams {
        if let Some((parent, _)) = name.rsplit_once('/') {
            if !parent.is_empty() && !cfb.exists(parent) {
                cfb.create_storage(parent).unwrap();
            }
        }
        let mut s = cfb.create_stream(name).unwrap();
        s.write_all(bytes).unwrap();
    }
    cfb.flush().unwrap();
    cfb.into_inner().into_inner()
}

#[test]
fn the_writers_own_map_reads_back_its_one_name() {
    assert_eq!(
        data_space_names(&crate_written_map()),
        ["StrongEncryptionDataSpace"]
    );
}

/// The 112-byte map `dataspaces::data_space_map` writes, rebuilt here so the detection
/// build (which does not compile `dataspaces`) can test against the same bytes.
fn crate_written_map() -> Vec<u8> {
    let m = map(&[entry("EncryptedPackage", "StrongEncryptionDataSpace")]);
    assert_eq!(m.len(), 112, "the size dataspaces.rs documents");
    m
}

#[test]
fn every_entry_is_read_and_a_malformed_one_ends_the_walk() {
    let two = map(&[
        entry("EncryptedPackage", "DRMEncryptedDataSpace"),
        entry("\u{9}DRMContent", "\u{9}DRMDataSpace"),
    ]);
    assert_eq!(
        data_space_names(&two),
        ["DRMEncryptedDataSpace", "\u{9}DRMDataSpace"]
    );

    // A second entry whose Length runs past the map: the first name survives.
    let mut cut = two.clone();
    cut.truncate(two.len() - 3);
    assert_eq!(data_space_names(&cut), ["DRMEncryptedDataSpace"]);

    // HeaderLength must be 8.
    let mut header = two.clone();
    header[0] = 9;
    assert!(data_space_names(&header).is_empty());
}

#[test]
fn hostile_counts_and_lengths_end_the_walk_without_panicking() {
    let one = entry("EncryptedPackage", "DRMEncryptedDataSpace");

    // EntryCount far past what the bytes hold.
    let mut m = map(&[one.clone()]);
    m[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(data_space_names(&m), ["DRMEncryptedDataSpace"]);

    // An entry Length below its own fixed fields, and one of zero, which would not
    // advance the walk.
    for len in [0u32, 11] {
        let mut m = map(&[one.clone()]);
        m[8..12].copy_from_slice(&len.to_le_bytes());
        assert!(data_space_names(&m).is_empty(), "Length {len}");
    }

    // ReferenceComponentCount of u32::MAX: the components run out, the entry is dropped.
    let mut m = map(&[one.clone()]);
    m[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(data_space_names(&m).is_empty());

    // An odd LP-P4 byte count, which UTF-16 cannot have.
    let mut m = map(&[one.clone()]);
    let name_len_at = 8 + 4 + 4 + 4 + lp_p4("EncryptedPackage").len();
    m[name_len_at..name_len_at + 4].copy_from_slice(&41u32.to_le_bytes());
    assert!(data_space_names(&m).is_empty());

    // Every prefix of a valid map.
    let full = map(&[one.clone(), one]);
    for cut in 0..full.len() {
        let _ = data_space_names(&full[..cut]);
    }
}

#[test]
fn rights_management_is_named_by_its_data_space_and_by_its_stream() {
    const MAP: &str = "/\u{6}DataSpaces/DataSpaceMap";

    let ecma = container(&[
        (
            MAP,
            &map(&[entry("EncryptedPackage", "DRMEncryptedDataSpace")]),
        ),
        ("/EncryptedPackage", &[0u8; 64]),
    ]);
    assert_eq!(rights_management(&ecma), Some(RightsManagement::Ecma376));

    for space in ["\u{9}DRMDataSpace", "\u{9}LZXDRMDataSpace"] {
        let binary = container(&[(MAP, &map(&[entry("\u{9}DRMContent", space)]))]);
        assert_eq!(
            rights_management(&binary),
            Some(RightsManagement::Binary),
            "{space:?}"
        );
    }

    // The protected content stream alone.
    let stream_only = container(&[("/\u{9}DRMContent", &[0u8; 64])]);
    assert_eq!(
        rights_management(&stream_only),
        Some(RightsManagement::Binary)
    );

    // Controls: standard encryption's own data space is not rights management, and
    // neither is a container with no data spaces at all.
    let standard = container(&[
        (MAP, &crate_written_map()),
        ("/EncryptedPackage", &[0u8; 64]),
    ]);
    assert_eq!(rights_management(&standard), None);
    assert_eq!(
        rights_management(&container(&[("/WordDocument", &[0u8; 64])])),
        None
    );
    assert_eq!(rights_management(b"not a container"), None);
}

/// A map longer than [`DATA_SPACE_MAP_READ_CAP`] is not read: the verdict falls back to
/// what the rest of the container says.
#[test]
fn a_map_over_the_cap_is_not_read() {
    let mut big = map(&[entry("EncryptedPackage", "DRMEncryptedDataSpace")]);
    big.resize(DATA_SPACE_MAP_READ_CAP + 1, 0);
    let c = container(&[("/\u{6}DataSpaces/DataSpaceMap", &big)]);
    assert_eq!(rights_management(&c), None);

    let mut at_cap = map(&[entry("EncryptedPackage", "DRMEncryptedDataSpace")]);
    at_cap.resize(DATA_SPACE_MAP_READ_CAP, 0);
    let c = container(&[("/\u{6}DataSpaces/DataSpaceMap", &at_cap)]);
    assert_eq!(rights_management(&c), Some(RightsManagement::Ecma376));
}
