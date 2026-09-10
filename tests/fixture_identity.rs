//! No fixture carries the identity of whoever generated it.
//!
//! Nine fixtures in `tests/fixtures/` were written by real Microsoft Office over COM, and
//! Office stamps `Application.UserName` into everything it saves. The `include` allowlist
//! no longer ships them — only the two `classify`'s doc examples need — so the crates.io
//! exposure is closed from that direction. **This test is still the guard**, because the
//! repository itself is going public: the fixtures are as readable in a clone as they
//! would have been in a tarball, and unlike a tarball a git history cannot be withdrawn.
//!
//! # The invariant, and why it is not a search for a name
//!
//! The obvious test greps the fixtures for the name that leaked, and by doing so writes
//! that name into the repository permanently — which is the thing being prevented. So this
//! asserts the opposite: every author field is **empty or absent**. No person's name is
//! written down here, the check catches any name rather than one specific name, and the
//! failure output never echoes the value it found.
//!
//! Empty rather than a placeholder is what Office's own Document Inspector produces, and
//! it is what the six regenerated fixtures carry.
//!
//! # Why a raw scan of `tests/fixtures/` is not enough
//!
//! Measured 2026-09-05: the name sat in four places with three different visibility rules,
//! and `grep -r` over the directory finds only the first.
//!
//! | where | which fixtures | visible to a raw scan? |
//! |---|---|---|
//! | `SummaryInformation` → `Author` / `LastAuthor` | every binary `.doc` / `.xls` / `.ppt` | **yes** — outside the encrypted region even in the password-protected ones |
//! | `WriteAccess` (BIFF `0x005C`) in `Workbook` | every `.xls` | only while the workbook is unencrypted |
//! | `SttbSavedBy` in `1Table`, UTF-16LE | every `.doc` | only while the document is unencrypted |
//! | `docProps/core.xml` | the three Office-written agile packages | **no** — the payload is ciphertext, and `core.xml` is deflated inside it |
//!
//! The last row is the trap: `grep -r` calls `word16_agile.docx`, `excel16_agile.xlsx` and
//! `powerpoint16_agile.pptx` completely clean while the name sits in all three. They are
//! where it is *most* exposed, the password being published in the README.
//!
//! So this decrypts what it must through this crate's own public API and inflates what it
//! must, which makes it a small end-to-end exercise of both decrypt paths as well.
#![cfg(all(feature = "crypto-ops", feature = "legacy-binary"))]

use std::io::{Cursor, Read};
use std::path::Path;

/// Every fixture Office wrote, plus `excel97_xor.xls`, which `tools/gen_xor_fixture.py`
/// derives from `excel97_plain.xls` and which therefore inherits its metadata.
const OFFICE_WRITTEN: &[&str] = &[
    "word16_agile.docx",
    "excel16_agile.xlsx",
    "powerpoint16_agile.pptx",
    "word97_plain.doc",
    "word97_password.doc",
    "excel97_plain.xls",
    "excel97_password.xls",
    "excel97_xor.xls",
    "powerpoint97_plain.ppt",
    "powerpoint97_password.ppt",
];

/// `[MS-OLEPS]` §2.18: `Author` and `LastAuthor` in the `SummaryInformation` property set.
const PID_AUTHOR: u32 = 0x04;
const PID_LAST_AUTHOR: u32 = 0x08;
/// `VT_LPSTR` — a `u32` length then that many bytes, the terminating NUL included.
const VT_LPSTR: u32 = 0x1E;

fn read(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// The bytes a reader can actually reach: the file, and — when it is encrypted — its
/// plaintext through this crate's public API. Both, because the binary formats leak in two
/// directions at once: `SummaryInformation` sits outside the encrypted region while
/// `WriteAccess` and `SttbSavedBy` sit inside it.
fn readable_forms(name: &str) -> Vec<(&'static str, Vec<u8>)> {
    let raw = read(name);
    let mut forms = vec![("as committed", raw.clone())];
    let plain = if name.ends_with(".doc") || name.ends_with(".xls") || name.ends_with(".ppt") {
        msoffice_crypto::decrypt_binary_office(&raw, "testpass").ok()
    } else {
        msoffice_crypto::decrypt_ooxml(&raw, "testpass").ok()
    };
    if let Some(p) = plain {
        forms.push(("decrypted", p));
    }
    forms
}

/// `Author` and `LastAuthor` out of a CFB container's `SummaryInformation`, as
/// `(field name, value)`. Parsed rather than searched, so "empty" is a thing that can be
/// asserted at all — a substring search can only ever find what is there, never prove a
/// field is blank.
fn summary_authors(data: &[u8]) -> Vec<(&'static str, String)> {
    let Ok(mut cfb) = cfb::CompoundFile::open(Cursor::new(data.to_vec())) else {
        return Vec::new();
    };
    let path = cfb
        .walk()
        .find(|e| e.is_stream() && e.name().ends_with("SummaryInformation"))
        .map(|e| e.path().to_path_buf());
    let Some(path) = path else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    if cfb
        .open_stream(&path)
        .and_then(|mut s| s.read_to_end(&mut buf))
        .is_err()
    {
        return Vec::new();
    }

    // PropertySetStream: byteOrder 2, version 2, sysId 4, CLSID 16, count 4, then
    // (FMTID 16, offset 4) per set. One set is all SummaryInformation carries.
    let Some(set_at) = le32(&buf, 28 + 16).map(|v| v as usize) else {
        return Vec::new();
    };
    let Some(count) = le32(&buf, set_at + 4) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for i in 0..count as usize {
        let pair = set_at + 8 + i * 8;
        let (Some(pid), Some(rel)) = (le32(&buf, pair), le32(&buf, pair + 4)) else {
            continue;
        };
        let field = match pid {
            PID_AUTHOR => "Author",
            PID_LAST_AUTHOR => "LastAuthor",
            _ => continue,
        };
        let at = set_at + rel as usize;
        if le32(&buf, at) != Some(VT_LPSTR) {
            continue;
        }
        let Some(len) = le32(&buf, at + 4).map(|v| v as usize) else {
            continue;
        };
        let Some(raw) = buf.get(at + 8..at + 8 + len) else {
            continue;
        };
        let s = String::from_utf8_lossy(raw)
            .trim_end_matches('\0')
            .to_string();
        out.push((field, s));
    }
    out
}

fn core_xml(package: &[u8]) -> Option<String> {
    let mut zip = zip::ZipArchive::new(Cursor::new(package.to_vec())).ok()?;
    let mut f = zip.by_name("docProps/core.xml").ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    Some(s)
}

/// The element's text, or `None` when the element is absent. An element written
/// `<dc:creator/>` is present and empty, and reads as `Some("")`.
fn xml_element(xml: &str, tag: &str) -> Option<String> {
    if xml.contains(&format!("<{tag}/>")) {
        return Some(String::new());
    }
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

/// Every author field of every Office-written fixture is empty.
///
/// The failure names the fixture, the form and the field, and deliberately **not** the
/// value — printing it would put the leaked name in CI logs, which is the same mistake as
/// putting it in the test.
#[test]
fn no_office_written_fixture_carries_its_authors_identity() {
    let mut failures = Vec::new();
    let mut unexamined = Vec::new();

    for name in OFFICE_WRITTEN {
        // Per fixture, not summed across them. An aggregate threshold is satisfiable by
        // the binary fixtures alone: each carries SummaryInformation in the clear, so
        // seven of them supply ~14 fields whatever the other three do. An agile package
        // that fails to decrypt contributes its `raw` form only, `core_xml` finds nothing
        // in ciphertext, and it silently contributes zero — while the sum still clears any
        // threshold. Measured 2026-09-09: flipping one byte in `word16_agile.docx` breaks
        // decryption (`real_office_fixtures` fails on it) and this test still passed.
        // That is the whole hiding place this file exists to search.
        let mut checked = 0usize;

        for (form, bytes) in readable_forms(name) {
            if let Some(xml) = core_xml(&bytes) {
                for tag in ["dc:creator", "cp:lastModifiedBy"] {
                    if let Some(v) = xml_element(&xml, tag) {
                        checked += 1;
                        if !v.trim().is_empty() {
                            failures.push(format!(
                                "{name} ({form}): <{tag}> is not empty — {} character(s)",
                                v.chars().count()
                            ));
                        }
                    }
                }
            }
            for (field, v) in summary_authors(&bytes) {
                checked += 1;
                if !v.trim().is_empty() {
                    failures.push(format!(
                        "{name} ({form}): SummaryInformation.{field} is not empty — {} \
                         character(s)",
                        v.chars().count()
                    ));
                }
            }
        }

        if checked == 0 {
            unexamined.push(*name);
        }
    }

    assert!(
        unexamined.is_empty(),
        "no author field could be read from {} of {} fixtures, so nothing was proved about \
         them. For an encrypted package this means the decrypt failed and its deflated \
         docProps/core.xml — the one place a name hides from `grep` — was never opened:\n  {}",
        unexamined.len(),
        OFFICE_WRITTEN.len(),
        unexamined.join("\n  ")
    );
    assert!(
        failures.is_empty(),
        "{} author field(s) still carry an identity. Clear them in Office \
         (File ▸ Info ▸ Check for Issues ▸ Inspect Document ▸ Document Properties), or \
         regenerate with Application.UserName set to an empty string:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// The script-generated fixtures name their library and no person.
#[test]
fn the_generated_fixtures_name_only_the_library_that_wrote_them() {
    for name in [
        "plain.docx",
        "agile_encrypted.docx",
        "standard_encrypted.docx",
        "agile_aes128_sha1.docx",
        "agile_aes128_sha384.docx",
        "agile_aes192_sha384.docx",
        "agile_aes256_sha256.docx",
        "agile_aes256_sha384.docx",
    ] {
        let xml = readable_forms(name)
            .iter()
            .find_map(|(_, b)| core_xml(b))
            .unwrap_or_else(|| panic!("{name}: no readable docProps/core.xml"));
        assert_eq!(
            xml_element(&xml, "dc:creator").as_deref(),
            Some("python-docx"),
            "{name}: dc:creator must be the generating library, not a person"
        );
    }
}
