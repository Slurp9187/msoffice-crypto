//! The 97-2003 binary fixtures, decrypted and compared byte for byte with what the
//! independent implementation writes for them.
//!
//! Three of the four were saved by Microsoft 365 build 16.0.19127.20302 — Word, Excel
//! and PowerPoint — with password `testpass`, and are RC4 CryptoAPI at 128 bits
//! (`EncryptionHeader` v4.2, `AlgID` 0x6801, `AlgIDHash` 0x8004; measured, not assumed).
//! The fourth, `excel97_xor.xls`, is `excel97_plain.xls` under XOR obfuscation, written
//! by `tools/gen_xor_fixture.py`: Excel 16 writes XOR only into the Excel 5.0/95
//! format, which the oracle cannot read, so the fixture is generated — with the key
//! material coming from the oracle's own `DocumentXOR`, and the key and verifier for
//! `testpass` being the two words Excel itself put into that 5.0/95 file. Program
//! output carries no upstream licence.
//!
//! # What is asserted, and why a hash rather than a golden file
//!
//! The expected SHA-256 of each decrypted container was produced by **`msoffcrypto-tool`
//! 6.0.0, not by this crate**:
//!
//! ```text
//! py -3 -m msoffcrypto -p testpass tests/fixtures/<fixture> out
//! sha256sum out
//! ```
//!
//! A passing assertion therefore means an independent implementation and this one
//! rewrite the same bytes into the same container — every persist object, every BIFF
//! record body, every stream, and nothing else. A decrypted `.doc` is the same size as
//! its source, so a committed twin would double the legacy corpus for a guard a digest
//! provides; the shape checks keep a failure diagnosable.
//!
//! **The `.ppt` is the one exception, and it is four bytes wide.** msoffcrypto's rewrite
//! of the persist directory leaves an entry with `cPersist = 0`, which [MS-PPT] §2.3.5
//! forbids and PowerPoint 16 refuses (`0x80048242`); this crate leaves the directory
//! alone and PowerPoint opens the result. So the `.ppt` is pinned twice: to this crate's
//! own digest, and — by re-applying msoffcrypto's edit to this crate's output — to
//! msoffcrypto's. The second is what keeps the differential evidence: everything but
//! that word is the oracle's, byte for byte. See `src/powerpoint97.rs` for the
//! bisection.
//!
//! The second oracle is the real application: each test writes its output beside the
//! system temp directory for `tools/office_com_check_binary.ps1`, which opens it in
//! Word, Excel or PowerPoint **with no password** and asserts on the content. Its
//! verdicts are recorded in CHANGELOG.md, since no CI runner has Office.

#![cfg(feature = "legacy-binary")]

use msoffice_crypto::{classify, decrypt_binary_office, Document, Error, Family};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Seek, SeekFrom, Write};

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

/// `(fixture, SHA-256 of the decrypted container, its length, document, family)`.
///
/// Three digests are msoffcrypto-tool's; the `.ppt`'s is this crate's, tied to
/// msoffcrypto's by [`powerpoint_output_is_msoffcryptos_but_for_the_persist_count`].
/// Regenerate the oracle's digests the same way if a fixture is ever replaced — deriving
/// them from this crate's own output would make the test circular and worthless.
const GOLDENS: &[(&str, &str, usize, Document, Family)] = &[
    (
        "word97_password.doc",
        "ec66234a7d716b0d0d048f0e736910d884e8dab768f9d1a771b27b14da9d1499",
        29_696,
        Document::WordBinary,
        Family::Rc4CryptoApi,
    ),
    (
        "excel97_password.xls",
        "922ed3e95fd29a3613b42b84861a37b2b2790f2c7386c5abd7ab10ea192e1e99",
        31_744,
        Document::ExcelBinary,
        Family::Rc4CryptoApi,
    ),
    (
        "powerpoint97_password.ppt",
        PPT_THIS_CRATE_SHA,
        39_936,
        Document::PowerPointBinary,
        Family::Rc4CryptoApi,
    ),
    (
        "excel97_xor.xls",
        "2c97ecdbd8759eb75efd76513ae72498cc5a638b2c9a954537993a5ca8ac7c75",
        25_600,
        Document::ExcelBinary,
        Family::XorObfuscation,
    ),
];

/// This crate's own output for the `.ppt` — the bytes PowerPoint 16 opens.
const PPT_THIS_CRATE_SHA: &str = "b6cb44712585f0a537afee42bbca050d72bc80058786ba808cc55214a6b1d32d";
/// msoffcrypto-tool's output for the `.ppt` — the bytes PowerPoint 16 refuses.
const PPT_MSOFFCRYPTO_SHA: &str =
    "4e13de2678f1a8d6fba2f6c396df34c4cf42c75dcbe83bed31875346095523a7";

/// The `.ppt` output equals msoffcrypto's once msoffcrypto's one edit is applied to it:
/// the first `PersistDirectoryEntry` word with `cPersist`, its high 12 bits, decremented
/// by one. Nothing else differs, which is the differential evidence for every persist
/// object, the container, the atom and the header token.
///
/// The word's offset is **read out of the file**. It was `202 349 + 8`, measured with
/// olefile, until the fixture was regenerated to clear its author metadata: the document
/// stream went from 202 461 bytes to 39 936 and the constant pointed past the end. The
/// walk below is the one [MS-PPT] specifies — `CurrentUserAtom.offsetToCurrentEdit`
/// (§2.3.2) to the `UserEditAtom` (§2.3.3), whose `offsetPersistDirectory` reaches the
/// `PersistDirectoryAtom` (§2.3.4) — and it is what `binary_office::persist_directory`
/// does in production. `cPersist` is likewise whatever the file says rather than a number
/// written down here, so the assertion is that msoffcrypto drops exactly one.
/// Where the first `PersistDirectoryEntry` word sits in a decrypted `.ppt`, from the file.
///
/// See [`powerpoint_output_is_msoffcryptos_but_for_the_persist_count`] for why this is
/// derived rather than measured.
fn persist_directory_word(cfb: &mut cfb::CompoundFile<&mut Cursor<Vec<u8>>>) -> u64 {
    fn le32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
    }
    // Fully qualified, as the rest of this file does: `Read` is not imported here.
    let mut current_user = Vec::new();
    std::io::Read::read_to_end(
        &mut cfb.open_stream("/Current User").unwrap(),
        &mut current_user,
    )
    .unwrap();
    let mut doc = Vec::new();
    std::io::Read::read_to_end(
        &mut cfb.open_stream("/PowerPoint Document").unwrap(),
        &mut doc,
    )
    .unwrap();

    let edit_at = le32(&current_user, 16) as usize;
    assert_eq!(
        u16::from_le_bytes([doc[edit_at + 2], doc[edit_at + 3]]),
        0x0FF5,
        "offsetToCurrentEdit must land on a UserEditAtom"
    );
    let directory_at = le32(&doc, edit_at + 8 + 12) as usize;
    assert_eq!(
        u16::from_le_bytes([doc[directory_at + 2], doc[directory_at + 3]]),
        0x1772,
        "offsetPersistDirectory must land on a PersistDirectoryAtom"
    );
    // Record header 8 bytes, then the first entry word.
    directory_at as u64 + 8
}

#[test]
fn powerpoint_output_is_msoffcryptos_but_for_the_persist_count() {
    let ours = decrypt_binary_office(&fixture("powerpoint97_password.ppt"), PASSWORD).unwrap();
    assert_eq!(sha256_hex(&ours), PPT_THIS_CRATE_SHA);

    let mut cursor = Cursor::new(ours);
    {
        let mut cfb = cfb::CompoundFile::open(&mut cursor).unwrap();
        let mut doc = cfb.open_stream("/PowerPoint Document").unwrap();
        let word_at = persist_directory_word(&mut cfb);
        doc.seek(SeekFrom::Start(word_at)).unwrap();
        let mut word = [0u8; 4];
        std::io::Read::read_exact(&mut doc, &mut word).unwrap();
        let word = u32::from_le_bytes(word);
        let counted = word >> 20;
        assert!(counted > 1, "the directory must count more than one object");
        let edited = (word & 0x000F_FFFF) | ((counted - 1) << 20);
        doc.seek(SeekFrom::Start(word_at)).unwrap();
        doc.write_all(&edited.to_le_bytes()).unwrap();
        doc.flush().unwrap();
    }
    assert_eq!(
        sha256_hex(&cursor.into_inner()),
        PPT_MSOFFCRYPTO_SHA,
        "with msoffcrypto's decrement re-applied, the two outputs must be identical"
    );
}

#[test]
fn legacy_fixtures_decrypt_to_what_msoffcrypto_writes_byte_for_byte() {
    for (name, expected_sha, expected_len, document, _) in GOLDENS {
        let data = fixture(name);
        let plain = decrypt_binary_office(&data, PASSWORD)
            .unwrap_or_else(|e| panic!("{name} must decrypt: {e}"));

        assert_eq!(
            plain.len(),
            *expected_len,
            "{name}: a binary document is decrypted in place, so the size is its own"
        );
        assert_eq!(
            sha256_hex(&plain),
            *expected_sha,
            "{name}: this crate and msoffcrypto-tool no longer agree byte for byte"
        );

        // Shape checks, so a future failure says what broke. The output is still the
        // same kind of document, and detection — which reads the same markers the
        // decrypt cleared — now calls it unencrypted.
        let c = classify(&plain);
        assert_eq!(c.document, *document, "{name}: still a {document:?}");
        assert_eq!(
            c.family,
            Family::Unencrypted,
            "{name}: the decrypted document must classify as unencrypted"
        );
        assert!(!c.is_encrypted(), "{name}");

        // The artifact the Office-side oracle opens; see the module docs.
        let out = std::env::temp_dir().join(format!("msoffice_crypto_decrypted_{name}"));
        std::fs::write(&out, &plain).expect("the artifact must be writable");
    }
}

/// The negative control every scheme needs: the same bytes under another password are
/// refused with the one variant that means "wrong password", and no other. RC4
/// CryptoAPI's verifier is a SHA-1 under the block-0 key; XOR's is the 16-bit
/// `verificationBytes` word beside its key in `FILEPASS`.
#[test]
fn every_scheme_names_a_wrong_password() {
    for (name, _, _, _, _) in GOLDENS {
        let got = decrypt_binary_office(&fixture(name), "wrongpass").map(|p| p.len());
        assert!(
            matches!(got, Err(Error::WrongPassword)),
            "{name}: expected WrongPassword, got {got:?}"
        );
    }
    // And a password XOR obfuscation could never have used — over 15 characters — is
    // a wrong password too, not a parameter problem: the file is fine.
    assert!(matches!(
        decrypt_binary_office(&fixture("excel97_xor.xls"), "sixteen-char-pw!"),
        Err(Error::WrongPassword)
    ));
}

/// The unprotected twins Office wrote with no password are refused as not encrypted —
/// distinct from every other refusal, because a caller acts on it by keeping the bytes.
#[test]
fn unprotected_documents_are_reported_not_encrypted() {
    for name in [
        "word97_plain.doc",
        "excel97_plain.xls",
        "powerpoint97_plain.ppt",
    ] {
        let got = decrypt_binary_office(&fixture(name), PASSWORD).map(|p| p.len());
        assert!(
            matches!(got, Err(Error::NotEncrypted)),
            "{name}: expected NotEncrypted, got {got:?}"
        );
    }
    // A decrypted fixture is unprotected too: decrypting it again is the same answer.
    let once = decrypt_binary_office(&fixture("word97_password.doc"), PASSWORD).unwrap();
    assert!(matches!(
        decrypt_binary_office(&once, PASSWORD),
        Err(Error::NotEncrypted)
    ));
}

/// Detection names every scheme the decrypt path reads, and only those. The PowerPoint
/// row is new with GH #4: its header sits inside a `CryptSession10Container` reached
/// through the persist directory, which detection now follows.
#[test]
fn legacy_fixtures_classify_as_the_schemes_the_decrypt_path_reads() {
    for (name, _, _, document, family) in GOLDENS {
        let c = classify(&fixture(name));
        assert_eq!(c.document, *document, "{name}");
        assert_eq!(c.family, *family, "{name}");
        assert!(c.is_encrypted(), "{name}");
        assert!(c.is_supported(), "{name}: the decrypt path reads this pair");
        if *family == Family::Rc4CryptoApi {
            assert_eq!(c.version, Some((4, 2)), "{name}");
            assert_eq!(
                c.key_data.and_then(|k| k.key_bits),
                Some(128),
                "{name}: EncryptionHeader.KeySize"
            );
        } else {
            assert_eq!(c.version, None, "{name}: XOR obfuscation has no version");
        }
    }
}

/// The OOXML entry point still refuses these files, and still never blames the
/// password: they are a different format with a different function.
#[test]
fn the_ooxml_entry_point_still_refuses_binary_documents_without_misdiagnosing() {
    for (name, _, _, _, _) in GOLDENS {
        let err = msoffice_crypto::decrypt_ooxml(&fixture(name), PASSWORD)
            .expect_err("a binary document is not an OOXML package");
        assert!(
            !matches!(err, Error::WrongPassword),
            "{name}: refused with WrongPassword, but the password is correct"
        );
    }
}

/// Every prefix of every fixture is a file somebody could hand this function, and none
/// of them may panic. The cuts land inside the CFB header, the FAT, the directory, and
/// each format's own structures.
///
/// No verdict is asserted, deliberately: `cfb` tolerates a container missing the tail of
/// its last sector — measured, the `.doc` cut one byte short still decrypts — so "any
/// truncation is an error" is not a property of the format. Panic-freedom is, and it is
/// what a caller running this on an upload depends on. The specific refusals for each
/// structural cut are in `src/legacy_malformed.rs`, where the cut is placed on purpose
/// and the variant is named.
#[test]
fn every_truncation_of_every_legacy_fixture_survives_without_panicking() {
    for (name, _, len, _, _) in GOLDENS {
        let data = fixture(name);
        for cut in [
            0usize,
            1,
            7,
            8,
            16,
            63,
            64,
            511,
            512,
            513,
            1024,
            4096,
            len / 2,
            len - 1,
        ] {
            let _ = decrypt_binary_office(&data[..cut.min(data.len())], PASSWORD);
            let _ = classify(&data[..cut.min(data.len())]);
        }
    }
}
