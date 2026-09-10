//! The fixtures Microsoft Office itself wrote: six with a password, three without.
//!
//! Every other fixture in this crate was produced by `msoffcrypto-tool` (see
//! `tools/gen_agile_fixtures.py`, and the original commit that says so). That is
//! cross-implementation evidence: two open-source readings of [MS-OFFCRYPTO] agreeing.
//! It is *not* interop evidence, because neither of them is Office.
//!
//! The six asserted here were saved by Microsoft 365 build 16.0.19127.20302 — Word,
//! Excel and PowerPoint — with password `testpass`. The three `*_plain` twins were saved
//! by the same three applications on the same build with no password
//! (`tools/gen_plain_binary_fixtures.ps1`); they exercise detection alone and so are
//! asserted in `src/classify_tests.rs`, which compiles in every configuration. Together
//! they are the only files here written by the implementation everything else is
//! compatible *with*.
//!
//! # What is asserted, and why a hash rather than a golden file
//!
//! The expected SHA-256 of each decrypted package was produced by **`msoffcrypto-tool`,
//! not by this crate**. So a passing assertion means an independent implementation and
//! this one recover byte-identical plaintext from a file Microsoft wrote — the strongest
//! evidence in the crate, and the only place all three parties are represented.
//!
//! A committed decrypted twin for each would be equally strong and ~64 KB heavier in the
//! published tarball, for a regression guard a 32-byte digest already provides. The
//! trade is deliberate; the ZIP-shape checks below keep a failure diagnosable rather than
//! reducing it to "the hash moved".
//!
//! # The three legacy fixtures: detected here, decrypted under `legacy-binary`
//!
//! `.doc`, `.xls` and `.ppt` are RC4 CryptoAPI (`EncryptionHeader` v4.2, `AlgID` 0x6801,
//! 128-bit, SHA-1 — measured, not assumed). Their decryption is GH #4's
//! `decrypt_binary_office`, a different function over a different feature, asserted
//! byte for byte against the same oracle in `tests/legacy_binary_fixtures.rs`. What this
//! file pins about them is the half every build shares: `classify` names all three
//! `Rc4CryptoApi (4, 2)` — the `.ppt` too, since detection follows its persist directory
//! to the `CryptSession10Container` — and `decrypt_ooxml` refuses them with a distinct
//! error rather than misdiagnosing them.
//!
//! Naming them matters. LibreOffice makes the *worse* mistake on the same `.ppt` — it
//! reports "Incorrect file version", because its PowerPoint filter never checks for
//! encryption before parsing — and a caller here learns instead that it is holding an
//! encrypted PowerPoint 97-2003 document, and which entry point opens it.

#![cfg(feature = "crypto-ops")]

use msoffice_crypto::{
    classify, Container, Document, Family, IntegrityDeclaration, OoXmlCryptoError,
};
use sha2::{Digest, Sha256};

const PASSWORD: &str = "testpass";

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {name} must be present: {e}"))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// `(fixture, expected SHA-256 of the decrypted package, expected length)`.
///
/// Digests computed with `py -3 -m msoffcrypto -p testpass <fixture> out`, i.e. by the
/// independent implementation, never by this crate. Regenerate the same way if a fixture
/// is ever replaced — deriving them from our own output would make this test circular and
/// worthless.
const AGILE_GOLDENS: &[(&str, &str, usize)] = &[
    (
        "word16_agile.docx",
        "a33ecce2da87ff8b385335ae0a063a16be378b90f0a520a6338f68d46041de45",
        15772,
    ),
    (
        "excel16_agile.xlsx",
        "3cca2429aef4f340d7a5355c4d28d5ba40fc8666bfb00a3ccb5c8ccc37dd8305",
        12118,
    ),
    (
        "powerpoint16_agile.pptx",
        "a27a9e2aec407ce43b9e696214214911949cbde03a953bc7d6d2b857fd196e9e",
        38956,
    ),
];

const LEGACY_FIXTURES: &[&str] = &[
    "word97_password.doc",
    "excel97_password.xls",
    "powerpoint97_password.ppt",
];

#[test]
fn office_written_agile_files_decrypt_to_what_an_independent_implementation_gets() {
    for (name, expected_sha, expected_len) in AGILE_GOLDENS {
        let plain = msoffice_crypto::decrypt_ooxml(&fixture(name), PASSWORD)
            .unwrap_or_else(|e| panic!("{name} must decrypt under the default policy: {e}"));

        assert_eq!(
            plain.len(),
            *expected_len,
            "{name}: decrypted length changed; msoffcrypto-tool gets {expected_len}"
        );
        assert_eq!(
            sha256_hex(&plain),
            *expected_sha,
            "{name}: this crate and msoffcrypto-tool no longer agree byte for byte"
        );

        // Shape checks so a future failure says *what* broke rather than only that a
        // digest moved. The decrypted package is the original OOXML zip.
        assert!(
            plain.starts_with(b"PK\x03\x04"),
            "{name}: decrypted output is not a zip"
        );
        assert!(
            plain.windows(19).any(|w| w == b"[Content_Types].xml"),
            "{name}: decrypted zip has no [Content_Types].xml, so it is not an OOXML package"
        );
    }
}

#[test]
fn office_writes_one_agile_tuple_across_all_three_applications() {
    // Word, Excel and PowerPoint were driven separately and all three produced the same
    // parameters. This is what makes AES-256/SHA-512 safe to treat as the modern default,
    // and it is why the registry experiment recorded in GH #13 could not coax anything
    // else out of Office 16.
    for (name, _, _) in AGILE_GOLDENS {
        let c = classify(&fixture(name));
        assert_eq!(c.container, Container::Cfb, "{name}");
        assert_eq!(c.version, Some((4, 4)), "{name}");
        assert_eq!(c.family, Family::Agile, "{name}");

        let pk = c
            .password_key
            .as_ref()
            .unwrap_or_else(|| panic!("{name}: no password encryptor parameters"));
        assert_eq!(pk.key_bits, Some(256), "{name}");
        assert_eq!(pk.spin_count, Some(100_000), "{name}");
    }
}

#[test]
fn office_always_declares_a_data_integrity_tag() {
    // The evidence GH #12's fail-closed default rests on: the writer every other
    // implementation is compatible with emits the element unconditionally, so its absence
    // on an agile file is a tampered or malformed file rather than an old one.
    for (name, _, _) in AGILE_GOLDENS {
        assert_eq!(
            classify(&fixture(name)).data_integrity,
            IntegrityDeclaration::Declared,
            "{name}: real Office is expected to declare dataIntegrity"
        );
    }
}

#[test]
fn legacy_binary_fixtures_are_refused_by_the_ooxml_entry_point_without_misdiagnosing() {
    // These are RC4 CryptoAPI binary documents; `decrypt_ooxml` reads OOXML packages and
    // is the wrong function for them (`decrypt_binary_office` is the right one, GH #4).
    // What matters here is that the refusal is a clean error rather than a panic, a
    // hang, or -- the failure this crate has already made once, in GH #11 -- a
    // *misleading* error blaming the user's password.
    for name in LEGACY_FIXTURES {
        let err = msoffice_crypto::decrypt_ooxml(&fixture(name), PASSWORD).expect_err(
            "a binary document is not an OOXML package; this must not appear to succeed",
        );

        assert!(
            !matches!(err, OoXmlCryptoError::WrongPassword),
            "{name}: refused with WrongPassword, but the password is correct -- the file \
             is simply not an OOXML package. That is the GH #11 failure mode and it must \
             not come back."
        );
    }
}

#[test]
fn legacy_binary_fixtures_classify_by_format_and_scheme() {
    // This test previously asserted `family: Unknown` and said, in a comment, that it
    // SHOULD fail once the gap was wired. It did, and this is the replacement.
    //
    // `document` names the format and `family` names the scheme, because the two vary
    // independently: ECMA-376 standard encryption can also carry an RC4 AlgID, so
    // `Rc4CryptoApi` alone would not distinguish a `.doc` from a `.docx`.
    let expected = [
        // (fixture, document, family, version, key_bits)
        (
            "word97_password.doc",
            Document::WordBinary,
            Family::Rc4CryptoApi,
            Some((4u16, 2u16)),
            Some(128u32),
        ),
        (
            "excel97_password.xls",
            Document::ExcelBinary,
            Family::Rc4CryptoApi,
            Some((4, 2)),
            Some(128),
        ),
        // PowerPoint keeps its EncryptionHeader inside a CryptSession10Container rather
        // than at a fixed offset. Detection reported `Unsupported` for it until GH #4;
        // it now follows the UserEditAtom's encryptSessionPersistIdRef through the
        // persist directory, in a handful of seeks, and names the same scheme and key
        // size as the other two.
        (
            "powerpoint97_password.ppt",
            Document::PowerPointBinary,
            Family::Rc4CryptoApi,
            Some((4, 2)),
            Some(128),
        ),
    ];

    for (name, document, family, version, key_bits) in expected {
        let c = classify(&fixture(name));
        assert_eq!(c.container, Container::Cfb, "{name}: container");
        assert_eq!(c.document, document, "{name}: document format");
        assert_eq!(c.family, family, "{name}: encryption family");
        assert_eq!(c.version, version, "{name}: EncryptionVersionInfo");
        assert_eq!(
            c.key_data.as_ref().and_then(|k| k.key_bits),
            key_bits,
            "{name}: EncryptionHeader.KeySize"
        );
        assert!(
            c.is_encrypted(),
            "{name}: every legacy fixture here is password-protected"
        );
    }
}

#[test]
fn a_decrypted_binary_document_is_not_reported_as_encrypted() {
    // The control that makes the test above mean something. Without it, detection that
    // returned "encrypted" unconditionally would pass every assertion there.
    //
    // Built at runtime rather than committed: the plaintext of a fixture is derivable from
    // the fixture, and a second .ppt would add ~200 KB to the tarball to prove a boolean.
    let out = std::env::temp_dir().join("msoffice_crypto_plain_ppt_control.ppt");
    let ok = std::process::Command::new("py")
        .args(["-3", "-m", "msoffcrypto", "-p", PASSWORD])
        .arg(format!(
            "{}/tests/fixtures/powerpoint97_password.ppt",
            env!("CARGO_MANIFEST_DIR")
        ))
        .arg(&out)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !ok {
        // msoffcrypto-tool is a developer convenience, not a build dependency. Skipping is
        // acceptable HERE and only here: this is a control for a property already asserted
        // positively above, not the assertion itself.
        eprintln!("msoffcrypto-tool unavailable; skipping the decrypted-ppt control");
        return;
    }

    let c = classify(&std::fs::read(&out).expect("msoffcrypto wrote the plaintext"));
    assert_eq!(c.document, Document::PowerPointBinary, "still a .ppt");
    assert_eq!(
        c.family,
        Family::Unencrypted,
        "a decrypted .ppt must not be reported as encrypted -- if this fails, PowerPoint          detection is returning a constant rather than reading the UserEditAtom"
    );
    assert!(!c.is_encrypted());
    let _ = std::fs::remove_file(&out);
}

#[test]
fn every_real_office_fixture_survives_truncation_without_panicking() {
    // classify() runs on whatever a caller hands it, and these are the only real-Office
    // byte layouts available to fuzz against. Truncation is the cheapest way to reach a
    // parser with a structurally valid prefix and nothing behind it.
    let all: Vec<&str> = AGILE_GOLDENS
        .iter()
        .map(|(n, _, _)| *n)
        .chain(LEGACY_FIXTURES.iter().copied())
        .collect();

    for name in all {
        let data = fixture(name);
        for cut in [0usize, 1, 7, 8, 16, 63, 64, 512, 4096, data.len() / 2] {
            let _ = classify(&data[..cut.min(data.len())]);
            let _ = msoffice_crypto::decrypt_ooxml(&data[..cut.min(data.len())], PASSWORD);
        }
    }
}
