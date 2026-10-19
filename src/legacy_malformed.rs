//! Every number a `.doc`, `.xls` or `.ppt` declares about itself must produce an error —
//! never a panic, never a hang — and every refusal must name what it refused.
//!
//! The binary formats are worse than the OOXML ones in this respect: their offsets and
//! lengths index the streams the decrypt rewrites, and an unbounded one is a slice panic
//! or, for PowerPoint's persist objects, a decrypt of the whole stream repeated once per
//! directory entry. Each test here poisons one field, asserts the variant, and carries a
//! control differing only in that field, so a green result cannot come from the synthetic
//! container being refused for an unrelated reason (CLAUDE.md § Testing Rules).
//!
//! Two kinds of input. Tampered fixtures: the real Office-written files with one field
//! rewritten in place through `cfb`, which is the cheapest way to reach a parser with
//! everything else valid. Synthetic streams: built from record headers where the shape
//! under test is not one a fixture has. Neither is committed, for the reason
//! `malformed_input.rs` gives.

use crate::{decrypt_binary_office, Error};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

const PASSWORD: &str = "testpass";

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {name} must be present: {e}"))
}

/// `data` with `bytes` written at `at` inside stream `name`, nothing else changed.
fn patch_stream(data: &[u8], name: &str, at: u64, bytes: &[u8]) -> Vec<u8> {
    let mut cursor = Cursor::new(data.to_vec());
    {
        let mut cfb = cfb::CompoundFile::open(&mut cursor).expect("a CFB container");
        let mut stream = cfb.open_stream(name).expect("the stream exists");
        stream.seek(SeekFrom::Start(at)).unwrap();
        stream.write_all(bytes).unwrap();
        stream.flush().unwrap();
    }
    cursor.into_inner()
}

/// One stream of a container, whole.
fn read_stream(data: &[u8], name: &str) -> Vec<u8> {
    let mut cfb = cfb::CompoundFile::open(Cursor::new(data)).expect("a CFB container");
    let mut out = Vec::new();
    cfb.open_stream(name)
        .expect("the stream exists")
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// A CFB container holding the named streams, and nothing else.
fn cfb_with(streams: &[(&str, &[u8])]) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut container = cfb::CompoundFile::create(&mut cursor).unwrap();
        for (name, bytes) in streams {
            let mut stream = container.create_stream(name).unwrap();
            stream.write_all(bytes).unwrap();
            stream.flush().unwrap();
        }
        container.flush().unwrap();
    }
    cursor.into_inner()
}

/// A BIFF stream: each record is a 2-byte id, a 2-byte body length, then the body.
fn biff(records: &[(u16, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (id, body) in records {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&(body.len() as u16).to_le_bytes());
        out.extend_from_slice(body);
    }
    out
}

/// Refused as `field`, with a problem `problem` accepts: the structured value, never a
/// message (#47).
fn bad_parameters_naming(
    got: &Result<Vec<u8>, Error>,
    field: crate::FileField,
    problem: fn(&crate::FileProblem) -> bool,
) -> bool {
    matches!(got, Err(Error::BadParameters { field: f, problem: p }) if *f == field && problem(p))
}

// ---- Word ------------------------------------------------------------------------------
//
// word97_password.doc, measured with olefile: FIB flags 0x13F0 at offset 0x0A, lKey 0xC6
// at 0x0E; the 1Table stream is 9 754 bytes and opens with the 198-byte encryption
// header structure, whose EncryptionHeader.KeySize sits at 12 + 16 = 28.

const DOC: &str = "word97_password.doc";
const FIB_FLAGS_AT: u64 = 0x0A;
const FIB_L_KEY_AT: u64 = 0x0E;
const DOC_TABLE_LEN: u32 = 9_754;
const TABLE_KEY_SIZE_AT: u64 = 28;

/// `FibBase.lKey` is a length the file declares over the table stream. Past the stream,
/// past the structure cap, and too short to hold a version are each refused by name;
/// the untouched value is the control.
#[test]
#[cfg_attr(
    not(fixture_corpus),
    ignore = "needs the fixture corpus, which the published crate does not ship"
)]
fn word_l_key_is_bounded_before_it_slices_the_table_stream() {
    let doc = fixture(DOC);
    let over: fn(&crate::FileProblem) -> bool =
        |p| matches!(p, crate::FileProblem::OutOfRange { .. });
    let short: fn(&crate::FileProblem) -> bool =
        |p| matches!(p, crate::FileProblem::Truncated { .. });
    for (what, l_key, field, problem) in [
        ("u32::MAX", u32::MAX, crate::FileField::FibLKey, over),
        (
            "over the structure cap",
            crate::limits::ENCRYPTION_HEADER_STRUCTURE_MAX as u32 + 1,
            crate::FileField::FibLKey,
            over,
        ),
        (
            "too short for a version",
            3,
            crate::FileField::EncryptionVersionInfo,
            short,
        ),
    ] {
        let tampered = patch_stream(&doc, "/WordDocument", FIB_L_KEY_AT, &l_key.to_le_bytes());
        let got = decrypt_binary_office(&tampered, PASSWORD);
        assert!(bad_parameters_naming(&got, field, problem), "{what}: {got:?}");
    }
    // Under the cap but past the stream: the fixture's own lKey over a table stream cut
    // to 100 bytes. The cap cannot catch this one; only the check against the stream can.
    let word = read_stream(&doc, "/WordDocument");
    let short_table = read_stream(&doc, "/1Table")[..100].to_vec();
    let got = decrypt_binary_office(
        &cfb_with(&[("/WordDocument", &word), ("/1Table", &short_table)]),
        PASSWORD,
    );
    assert!(
        bad_parameters_naming(&got, crate::FileField::FibLKey, |p| matches!(p, crate::FileProblem::OutOfBounds { .. })),
        "{got:?}"
    );
    // Control: the fixture decrypts as it is, so the refusals above are the field's.
    assert!(decrypt_binary_office(&doc, PASSWORD).is_ok());
    let _ = DOC_TABLE_LEN;
    // And an lKey that is merely *larger* than the structure but within the stream is
    // accepted: the parser reads the structure by its own size fields.
    let generous = patch_stream(&doc, "/WordDocument", FIB_L_KEY_AT, &400u32.to_le_bytes());
    assert!(decrypt_binary_office(&generous, PASSWORD).is_ok());
}

/// The two FIB bits the format decides encryption by, each flipped alone.
#[test]
#[cfg_attr(
    not(fixture_corpus),
    ignore = "needs the fixture corpus, which the published crate does not ship"
)]
fn word_fib_flags_decide_not_encrypted_and_xor_by_name() {
    let doc = fixture(DOC);
    let flags = 0x13F0u16;
    // fEncrypted clear: nothing to decrypt, whatever the table stream holds.
    let plain = patch_stream(
        &doc,
        "/WordDocument",
        FIB_FLAGS_AT,
        &(flags & !0x0100).to_le_bytes(),
    );
    assert!(matches!(
        decrypt_binary_office(&plain, PASSWORD),
        Err(Error::NotEncrypted)
    ));
    // fObfuscated set: Word's XOR method, refused by name and never as a wrong password.
    let xor = patch_stream(
        &doc,
        "/WordDocument",
        FIB_FLAGS_AT,
        &(flags | 0x8000).to_le_bytes(),
    );
    assert!(matches!(
        decrypt_binary_office(&xor, PASSWORD),
        Err(Error::UnsupportedAlgorithm {
            what: "FibBase.fObfuscated",
            ..
        })
    ));
}

/// `EncryptionHeader.KeySize` is authenticated by the verifier and bounded before it
/// derives a key: 0 reads as 40 and then fails the password check (the file was written
/// at 128), a value off the grid is refused by name.
#[test]
#[cfg_attr(
    not(fixture_corpus),
    ignore = "needs the fixture corpus, which the published crate does not ship"
)]
fn word_key_size_is_bounded_and_verified() {
    let doc = fixture(DOC);
    let forty = patch_stream(&doc, "/1Table", TABLE_KEY_SIZE_AT, &0u32.to_le_bytes());
    assert!(matches!(
        decrypt_binary_office(&forty, PASSWORD),
        Err(Error::WrongPassword)
    ));
    for bits in [8u32, 136, 1024] {
        let tampered = patch_stream(&doc, "/1Table", TABLE_KEY_SIZE_AT, &bits.to_le_bytes());
        let got = decrypt_binary_office(&tampered, PASSWORD);
        assert!(
            bad_parameters_naming(&got, crate::FileField::EncryptionHeaderKeySize, |p| matches!(p, crate::FileProblem::NotInSet { .. })),
            "KeySize {bits}: {got:?}"
        );
    }
    // The version pair, refused by name.
    let versioned = patch_stream(&doc, "/1Table", 0, &[5, 0, 2, 0]);
    assert!(matches!(
        decrypt_binary_office(&versioned, PASSWORD),
        Err(Error::UnsupportedEncryptionVersion(5, 2))
    ));
}

/// A `WordDocument` stream shorter than the FIB, and one that is not a FIB at all.
#[test]
#[cfg_attr(
    not(fixture_corpus),
    ignore = "needs the fixture corpus, which the published crate does not ship"
)]
fn word_document_shorter_than_the_fib_is_refused() {
    let table = read_stream(&fixture(DOC), "/1Table");
    let mut short = read_stream(&fixture(DOC), "/WordDocument");
    short.truncate(0x30);
    let got = decrypt_binary_office(
        &cfb_with(&[("/WordDocument", &short), ("/1Table", &table)]),
        PASSWORD,
    );
    assert!(
        matches!(got, Err(Error::MissingStream(m)) if m.contains("68-byte")),
        "{got:?}"
    );

    let not_a_fib = vec![0u8; 0x44];
    let got = decrypt_binary_office(
        &cfb_with(&[("/WordDocument", &not_a_fib), ("/1Table", &table)]),
        PASSWORD,
    );
    assert!(bad_parameters_naming(&got, crate::FileField::FibWIdent, |p| matches!(p, crate::FileProblem::BadSignature)), "{got:?}");
}

/// Office 97/2000 RC4 end to end, on a container built with a test-side writer over the
/// production key schedule.
///
/// No fixture exists (see `rc4_office97`'s docs for why); the schedule's KDF and
/// verifier are pinned against msoffcrypto's vector there, so what this adds is the
/// wiring: the `1.1` dispatch in `word97`, the 512-byte block loop over three streams,
/// the clear FIB put back with its flags and `lKey` cleared. Self-agreement only for
/// the container layout, and labelled so.
#[test]
fn word_office97_rc4_container_decrypts_and_reports_a_wrong_password() {
    use crate::rc4::{decrypt_in_blocks, BlockKeySchedule, Keystream};
    use crate::rc4_office97::Office97KeySchedule;
    use md5::{Digest, Md5};

    let salt = [0x11u8; 16];
    let schedule = Office97KeySchedule::new(PASSWORD, &salt);

    // Verifier and its MD5, both under the block-0 keystream, continued.
    let verifier = [0x5Au8; 16];
    let mut keystream = Keystream::new(&schedule.block_key(0)).unwrap();
    let mut encrypted_verifier = verifier;
    keystream.apply(&mut encrypted_verifier);
    let mut encrypted_hash: [u8; 16] = Md5::digest(verifier).into();
    keystream.apply(&mut encrypted_hash);

    let mut header = vec![1u8, 0, 1, 0];
    header.extend_from_slice(&salt);
    header.extend_from_slice(&encrypted_verifier);
    header.extend_from_slice(&encrypted_hash);
    assert_eq!(header.len(), 52);

    // A FIB with fEncrypted | fWhichTblStm and lKey = 52, then 1 000 bytes of "document".
    let mut fib = vec![0u8; 0x44];
    fib[..2].copy_from_slice(&0xA5ECu16.to_le_bytes());
    fib[0x0A..0x0C].copy_from_slice(&0x0300u16.to_le_bytes());
    fib[0x0E..0x12].copy_from_slice(&52u32.to_le_bytes());
    let body: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();

    let mut word = fib.clone();
    word.extend_from_slice(&body);
    let mut table = header.clone();
    table.extend_from_slice(&body);
    let mut data = body.clone();
    // Encrypt whole (RC4 is symmetric), then restore the clear FIB and header.
    for stream in [&mut word, &mut table, &mut data] {
        decrypt_in_blocks(&schedule, stream, 0x200).unwrap();
    }
    word[..0x44].copy_from_slice(&fib);
    table[..52].copy_from_slice(&header);

    let container = cfb_with(&[
        ("/WordDocument", &word),
        ("/1Table", &table),
        ("/Data", &data),
    ]);
    let plain = decrypt_binary_office(&container, PASSWORD).expect("must decrypt");

    let word_plain = read_stream(&plain, "/WordDocument");
    assert_eq!(&word_plain[0x44..], &body[..], "the document body decrypts");
    assert_eq!(
        &word_plain[..2],
        &0xA5ECu16.to_le_bytes(),
        "the FIB survives"
    );
    assert_eq!(
        &word_plain[0x0A..0x0C],
        &0x0200u16.to_le_bytes(),
        "fEncrypted cleared, fWhichTblStm kept"
    );
    assert_eq!(&word_plain[0x0E..0x12], &[0, 0, 0, 0], "lKey cleared");
    assert_eq!(
        &read_stream(&plain, "/1Table")[52..],
        &body[..],
        "the table stream decrypts past the header"
    );
    assert_eq!(
        read_stream(&plain, "/Data"),
        body,
        "the Data stream decrypts whole"
    );

    assert!(matches!(
        decrypt_binary_office(&container, "not-the-password"),
        Err(Error::WrongPassword)
    ));
}

// ---- Excel -----------------------------------------------------------------------------
//
// excel97_password.xls: Workbook opens BOF (16-byte body), then FILEPASS at offset 20 with
// a 200-byte body: wEncryptionType 1, then the same 198-byte structure the .doc carries.
// excel97_xor.xls: FILEPASS at 20 with a 6-byte body: type 0, key 0xA6CE, verifier 0x9727.

const XLS: &str = "excel97_password.xls";
const XLS_XOR: &str = "excel97_xor.xls";
const BOF: u16 = 0x0809;
const FILEPASS: u16 = 0x002F;
const INTERFACEHDR: u16 = 0x00E1;
const MMS: u16 = 0x00C1;
const BOF_BODY: [u8; 16] = [
    0x00, 0x06, 0x05, 0x00, 0x5A, 0x4F, 0xCD, 0x07, 0xC1, 0x00, 0x02, 0x00, 0x06, 0x08, 0x00, 0x00,
];

/// The fixture's own FILEPASS body: public bytes, and the only way to build a synthetic
/// workbook that passes the verifier under `testpass`.
fn rc4_filepass_body() -> Vec<u8> {
    let book = read_stream(&fixture(XLS), "/Workbook");
    assert_eq!(&book[20..22], &FILEPASS.to_le_bytes());
    let len = u16::from_le_bytes([book[22], book[23]]) as usize;
    book[24..24 + len].to_vec()
}

/// A record whose declared length overshoots the stream, and a stream cut inside a
/// header: both refused by name, before any decrypt. The control is the same records
/// with the length honest.
#[test]
#[cfg_attr(
    not(fixture_corpus),
    ignore = "needs the fixture corpus, which the published crate does not ship"
)]
fn excel_record_length_past_the_stream_is_refused() {
    let filepass = rc4_filepass_body();
    let honest = biff(&[(BOF, &BOF_BODY), (FILEPASS, &filepass), (MMS, &[0, 0])]);
    assert!(decrypt_binary_office(&cfb_with(&[("/Workbook", &honest)]), PASSWORD).is_ok());

    let mut overshoot = biff(&[(BOF, &BOF_BODY), (FILEPASS, &filepass)]);
    overshoot.extend_from_slice(&MMS.to_le_bytes());
    overshoot.extend_from_slice(&0x4000u16.to_le_bytes()); // claims 16 KiB, has none
    let got = decrypt_binary_office(&cfb_with(&[("/Workbook", &overshoot)]), PASSWORD);
    assert!(
        bad_parameters_naming(&got, crate::FileField::BiffRecord, |p| matches!(p, crate::FileProblem::Unreadable { .. })),
        "{got:?}"
    );

    let mut cut = biff(&[(BOF, &BOF_BODY), (FILEPASS, &filepass)]);
    cut.extend_from_slice(&[0xC1]); // one byte of the next record id
    let got = decrypt_binary_office(&cfb_with(&[("/Workbook", &cut)]), PASSWORD);
    assert!(bad_parameters_naming(&got, crate::FileField::BiffRecord, |p| matches!(p, crate::FileProblem::Unreadable { .. })), "{got:?}");

    // A FILEPASS whose own body is cut short: detection still says "encrypted", but a
    // decrypt needs the body and refuses.
    let mut short = biff(&[(BOF, &BOF_BODY)]);
    short.extend_from_slice(&FILEPASS.to_le_bytes());
    short.extend_from_slice(&200u16.to_le_bytes());
    let got = decrypt_binary_office(&cfb_with(&[("/Workbook", &short)]), PASSWORD);
    assert!(
        bad_parameters_naming(&got, crate::FileField::BiffRecord, |p| matches!(p, crate::FileProblem::Unreadable { .. })),
        "{got:?}"
    );
}

/// FILEPASS after a record the format requires to be encrypted is neither an encrypted
/// workbook nor a plain one, and is refused by name; a workbook with no FILEPASS at all
/// is not encrypted. The control is FILEPASS after the records the format permits ahead
/// of it, which decrypts.
#[test]
#[cfg_attr(
    not(fixture_corpus),
    ignore = "needs the fixture corpus, which the published crate does not ship"
)]
fn excel_filepass_out_of_order_is_refused_and_absence_is_not_encrypted() {
    let filepass = rc4_filepass_body();
    let in_order = biff(&[
        (BOF, &BOF_BODY),
        (INTERFACEHDR, &[0xB0, 0x04]),
        (FILEPASS, &filepass),
        (MMS, &[0, 0]),
    ]);
    assert!(decrypt_binary_office(&cfb_with(&[("/Workbook", &in_order)]), PASSWORD).is_ok());
    assert!(matches!(
        decrypt_binary_office(&cfb_with(&[("/Workbook", &in_order)]), "wrongpass"),
        Err(Error::WrongPassword)
    ));

    let out_of_order = biff(&[(BOF, &BOF_BODY), (MMS, &[0, 0]), (FILEPASS, &filepass)]);
    let got = decrypt_binary_office(&cfb_with(&[("/Workbook", &out_of_order)]), PASSWORD);
    assert!(
        bad_parameters_naming(&got, crate::FileField::Filepass, |p| matches!(p, crate::FileProblem::OutOfOrder { after_record: 0x00C1 })),
        "{got:?}"
    );

    let plain = biff(&[
        (BOF, &BOF_BODY),
        (INTERFACEHDR, &[0xB0, 0x04]),
        (MMS, &[0, 0]),
    ]);
    assert!(matches!(
        decrypt_binary_office(&cfb_with(&[("/Workbook", &plain)]), PASSWORD),
        Err(Error::NotEncrypted)
    ));

    let not_bof = biff(&[(MMS, &[0, 0]), (FILEPASS, &filepass)]);
    let got = decrypt_binary_office(&cfb_with(&[("/Workbook", &not_bof)]), PASSWORD);
    assert!(bad_parameters_naming(&got, crate::FileField::WorkbookBof, |p| matches!(p, crate::FileProblem::Missing)), "{got:?}");
}

/// The FILEPASS body's own discriminators: an `wEncryptionType` that is neither scheme,
/// an XOR body too short for its two words, an RC4 body with no version, a version pair
/// this crate does not read, and a BIFF5 `Book` stream — each refused by name.
#[test]
#[cfg_attr(
    not(fixture_corpus),
    ignore = "needs the fixture corpus, which the published crate does not ship"
)]
fn excel_filepass_shapes_are_refused_by_name() {
    let mut rc4 = rc4_filepass_body();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("wEncryptionType 2", {
            let mut b = rc4.clone();
            b[0] = 2;
            b
        }),
        ("XOR with one word", vec![0, 0, 0xCE, 0xA6]),
        ("RC4 with no version", vec![1, 0]),
    ];
    for (what, body) in cases {
        let got = decrypt_binary_office(
            &cfb_with(&[("/Workbook", &biff(&[(BOF, &BOF_BODY), (FILEPASS, &body)]))]),
            PASSWORD,
        );
        assert!(
            matches!(got, Err(Error::BadParameters { .. })),
            "{what}: {got:?}"
        );
    }
    rc4[2] = 5; // vMajor 5
    let got = decrypt_binary_office(
        &cfb_with(&[("/Workbook", &biff(&[(BOF, &BOF_BODY), (FILEPASS, &rc4)]))]),
        PASSWORD,
    );
    assert!(
        matches!(got, Err(Error::UnsupportedEncryptionVersion(5, 2))),
        "{got:?}"
    );

    let book = read_stream(&fixture(XLS), "/Workbook");
    let got = decrypt_binary_office(&cfb_with(&[("/Book", &book)]), PASSWORD);
    assert!(
        matches!(
            got,
            Err(Error::UnsupportedAlgorithm {
                what: "Book stream",
                ..
            })
        ),
        "{got:?}"
    );
}

/// XOR's verifier is two words, and both are checked: a key that does not match the
/// password is refused even beside a verifier that does, and vice versa.
#[test]
#[cfg_attr(
    not(fixture_corpus),
    ignore = "needs the fixture corpus, which the published crate does not ship"
)]
fn excel_xor_key_and_verifier_are_both_checked() {
    let xls = fixture(XLS_XOR);
    let book = read_stream(&xls, "/Workbook");
    assert_eq!(
        &book[24..30],
        &[0, 0, 0xCE, 0xA6, 0x27, 0x97],
        "the fixture's FILEPASS"
    );
    assert!(decrypt_binary_office(&xls, PASSWORD).is_ok());

    let bad_key = patch_stream(&xls, "/Workbook", 26, &0xA6CFu16.to_le_bytes());
    assert!(matches!(
        decrypt_binary_office(&bad_key, PASSWORD),
        Err(Error::WrongPassword)
    ));
    let bad_verifier = patch_stream(&xls, "/Workbook", 28, &0x9726u16.to_le_bytes());
    assert!(matches!(
        decrypt_binary_office(&bad_verifier, PASSWORD),
        Err(Error::WrongPassword)
    ));
}

// ---- PowerPoint ------------------------------------------------------------------------

const PPT: &str = "powerpoint97_password.ppt";
const PPT_DOC: &str = "/PowerPoint Document";
const PPT_CURRENT_USER: &str = "/Current User";

/// Where the structures these tests tamper with actually are, **read out of the fixture**
/// rather than written down.
///
/// These were five hardcoded constants measured with olefile, and they were right until
/// the fixture was regenerated to clear its author metadata: the document stream went from
/// 202 461 bytes to 36 090, and every one of them pointed past the end. The tests failed
/// with `Cannot seek to 202179 bytes from start, because stream length is only 36090`,
/// which is a fixture-shaped failure wearing a bug's clothes.
///
/// They are file-derived numbers, so the file is what should derive them. The walk is the
/// one [MS-PPT] specifies and the one `binary_office::persist_directory` makes in
/// production: `CurrentUserAtom.offsetToCurrentEdit` (§2.3.2) locates the `UserEditAtom`
/// (§2.3.3), whose `offsetPersistDirectory` locates the `PersistDirectoryAtom` (§2.3.4),
/// whose entries map a persist id to a stream offset; the container this file encrypts
/// with is the one `encryptSessionPersistIdRef` names.
struct PptOffsets {
    /// The whole `PowerPoint Document` stream — one past the last byte a test may patch.
    doc_len: u32,
    /// The `UserEditAtom`. Its record header is 8 bytes, so its fields start at `+8`.
    edit_at: u64,
    /// The `PersistDirectoryAtom`. Record header 8 bytes, then one entry word.
    directory_at: u64,
    /// The first `rgPersistOffset` in that entry: header 8 + the entry word 4.
    first_offset_at: u64,
    /// `EncryptionHeader.KeySize` inside the `CryptSession10Container`: the container's
    /// record header is 8 bytes, `EncryptionVersionInfo` 4, `Flags` 4 and
    /// `EncryptionHeaderSize` 4, then the header itself, whose `KeySize` is 16 in —
    /// container + 36, measured 128 on this fixture.
    key_size_at: u64,
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(b)
}

fn ppt_offsets(ppt: &[u8]) -> PptOffsets {
    let current_user = read_stream(ppt, PPT_CURRENT_USER);
    let doc = read_stream(ppt, PPT_DOC);

    // CurrentUserAtom: record header 8, size 4, headerToken 4, then offsetToCurrentEdit.
    let edit_at = le32(&current_user, 16) as usize;
    assert_eq!(
        u16::from_le_bytes([doc[edit_at + 2], doc[edit_at + 3]]),
        0x0FF5,
        "offsetToCurrentEdit must land on a UserEditAtom"
    );
    // UserEditAtom fields, past its 8-byte header: lastSlideIdRef 4, version 2, minor 1,
    // major 1, offsetLastEdit 4, then offsetPersistDirectory.
    let directory_at = le32(&doc, edit_at + 8 + 12) as usize;
    assert_eq!(
        u16::from_le_bytes([doc[directory_at + 2], doc[directory_at + 3]]),
        0x1772,
        "offsetPersistDirectory must land on a PersistDirectoryAtom"
    );
    // ... and, 0x1C past the header, the persist id of the encryption container.
    let encrypt_ref = le32(&doc, edit_at + 8 + 0x1C);

    // Walk the directory for that id. Each entry is a packed word — persistId in the low
    // 20 bits, a run length in the high 12 — followed by that many 4-byte offsets.
    let dir_end = directory_at + 8 + le32(&doc, directory_at + 4) as usize;
    let mut at = directory_at + 8;
    let mut container = None;
    while at + 4 <= dir_end {
        let word = le32(&doc, at);
        at += 4;
        let (first_id, run) = (word & 0xF_FFFF, word >> 20);
        for i in 0..run {
            if at + 4 > dir_end {
                break;
            }
            if first_id + i == encrypt_ref {
                container = Some(le32(&doc, at) as usize);
            }
            at += 4;
        }
    }
    let container = container.expect("the persist directory names the encryption container");
    assert_eq!(
        u16::from_le_bytes([doc[container + 2], doc[container + 3]]),
        0x2F14,
        "encryptSessionPersistIdRef must land on a CryptSession10Container"
    );

    PptOffsets {
        doc_len: doc.len() as u32,
        edit_at: edit_at as u64,
        directory_at: directory_at as u64,
        first_offset_at: directory_at as u64 + 12,
        key_size_at: container as u64 + 36,
    }
}

#[test]
#[cfg_attr(
    not(fixture_corpus),
    ignore = "needs the fixture corpus, which the published crate does not ship"
)]
fn powerpoint_offsets_are_bounded_before_they_are_followed() {
    let ppt = fixture(PPT);
    let o = ppt_offsets(&ppt);
    assert!(decrypt_binary_office(&ppt, PASSWORD).is_ok(), "control");

    // offsetToCurrentEdit past the stream, and at a byte that is not a UserEditAtom.
    for (what, offset) in [
        ("past the stream", o.doc_len),
        ("u32::MAX", u32::MAX),
        ("mid-stream garbage", 1000),
    ] {
        let tampered = patch_stream(&ppt, "/Current User", 16, &offset.to_le_bytes());
        let got = decrypt_binary_office(&tampered, PASSWORD);
        assert!(
            bad_parameters_naming(&got, crate::FileField::UserEditAtom, |p| matches!(p, crate::FileProblem::Unreadable { .. })),
            "{what}: {got:?}"
        );
    }

    // offsetPersistDirectory at something that is not a PersistDirectoryAtom.
    let tampered = patch_stream(&ppt, PPT_DOC, o.edit_at + 8 + 12, &0u32.to_le_bytes());
    let got = decrypt_binary_office(&tampered, PASSWORD);
    assert!(
        bad_parameters_naming(&got, crate::FileField::PersistDirectory, |p| matches!(p, crate::FileProblem::Unreadable { .. })),
        "{got:?}"
    );

    // A PersistDirectoryAtom whose recLen exceeds the read cap.
    let tampered = patch_stream(&ppt, PPT_DOC, o.directory_at + 4, &u32::MAX.to_le_bytes());
    let got = decrypt_binary_office(&tampered, PASSWORD);
    assert!(
        bad_parameters_naming(&got, crate::FileField::PersistDirectory, |p| matches!(p, crate::FileProblem::Unreadable { .. })),
        "{got:?}"
    );

    // An entry with cPersist = 0, which [MS-PPT] §2.3.5 forbids: the atom is unreadable,
    // not a directory of nothing whose offsets are then parsed as further entries.
    let tampered = patch_stream(&ppt, PPT_DOC, o.directory_at + 8, &1u32.to_le_bytes());
    let got = decrypt_binary_office(&tampered, PASSWORD);
    assert!(
        bad_parameters_naming(&got, crate::FileField::PersistDirectory, |p| matches!(p, crate::FileProblem::Unreadable { .. })),
        "{got:?}"
    );

    // A persist object offset at or past the directory — the bound that keeps every
    // object's extent inside the stream and disjoint from the atoms after it.
    for offset in [o.directory_at as u32, o.doc_len, u32::MAX] {
        let tampered = patch_stream(&ppt, PPT_DOC, o.first_offset_at, &offset.to_le_bytes());
        let got = decrypt_binary_office(&tampered, PASSWORD);
        assert!(
            bad_parameters_naming(&got, crate::FileField::PersistObject, |p| matches!(p, crate::FileProblem::OutOfRange { .. })),
            "offset {offset}: {got:?}"
        );
    }

    // encryptSessionPersistIdRef naming an object the directory does not have.
    let tampered = patch_stream(&ppt, PPT_DOC, o.edit_at + 8 + 0x1C, &999u32.to_le_bytes());
    let got = decrypt_binary_office(&tampered, PASSWORD);
    assert!(
        bad_parameters_naming(&got, crate::FileField::EncryptSessionPersistIdRef, |p| matches!(p, crate::FileProblem::Unrecognized { .. })),
        "{got:?}"
    );

    // ...or one that is not a CryptSession10Container (persist object 1 is the
    // DocumentContainer, encrypted, so its header is noise).
    let tampered = patch_stream(&ppt, PPT_DOC, o.edit_at + 8 + 0x1C, &1u32.to_le_bytes());
    let got = decrypt_binary_office(&tampered, PASSWORD);
    assert!(
        bad_parameters_naming(&got, crate::FileField::CryptSession10Container, |p| matches!(p, crate::FileProblem::Unreadable { .. })),
        "{got:?}"
    );
}

/// [MS-PPT] §2.3.7: an encrypted presentation contains exactly one user edit. A second
/// is refused rather than half-decrypted; the plain atom shape is "not encrypted".
#[test]
#[cfg_attr(
    not(fixture_corpus),
    ignore = "needs the fixture corpus, which the published crate does not ship"
)]
fn powerpoint_user_edit_shapes_decide_by_name() {
    let ppt = fixture(PPT);
    let o = ppt_offsets(&ppt);
    let chained = patch_stream(&ppt, PPT_DOC, o.edit_at + 8 + 8, &1u32.to_le_bytes());
    let got = decrypt_binary_office(&chained, PASSWORD);
    assert!(
        bad_parameters_naming(&got, crate::FileField::OffsetLastEdit, |p| matches!(p, crate::FileProblem::NotRequiredValue { .. })),
        "{got:?}"
    );

    let plain = patch_stream(&ppt, PPT_DOC, o.edit_at + 4, &0x1Cu32.to_le_bytes());
    assert!(matches!(
        decrypt_binary_office(&plain, PASSWORD),
        Err(Error::NotEncrypted)
    ));

    let odd = patch_stream(&ppt, PPT_DOC, o.edit_at + 4, &0x30u32.to_le_bytes());
    let got = decrypt_binary_office(&odd, PASSWORD);
    assert!(bad_parameters_naming(&got, crate::FileField::UserEditAtom, |p| matches!(p, crate::FileProblem::Unreadable { .. })), "{got:?}");
}

/// The header inside the container is parsed with the same bounds as Word's: KeySize 0
/// reads as 40 and fails the verifier, a value off the grid is refused by name.
#[test]
#[cfg_attr(
    not(fixture_corpus),
    ignore = "needs the fixture corpus, which the published crate does not ship"
)]
fn powerpoint_key_size_is_bounded_and_verified() {
    let ppt = fixture(PPT);
    let o = ppt_offsets(&ppt);
    let forty = patch_stream(&ppt, PPT_DOC, o.key_size_at, &0u32.to_le_bytes());
    assert!(matches!(
        decrypt_binary_office(&forty, PASSWORD),
        Err(Error::WrongPassword)
    ));
    let off_grid = patch_stream(&ppt, PPT_DOC, o.key_size_at, &200u32.to_le_bytes());
    let got = decrypt_binary_office(&off_grid, PASSWORD);
    assert!(bad_parameters_naming(&got, crate::FileField::EncryptionHeaderKeySize, |p| matches!(p, crate::FileProblem::NotInSet { .. })), "{got:?}");
}

/// A container that is a CFB but none of the three formats, and one that is not a CFB.
#[test]
fn something_that_is_not_a_binary_document_is_named() {
    assert!(matches!(
        decrypt_binary_office(&fixture("agile_encrypted.docx"), PASSWORD),
        Err(Error::MissingStream(_))
    ));
    assert!(matches!(
        decrypt_binary_office(&fixture("plain.docx"), PASSWORD),
        Err(Error::NotACfbFile)
    ));
    assert!(matches!(
        decrypt_binary_office(b"", PASSWORD),
        Err(Error::NotACfbFile)
    ));
}

// ---- The encrypted summary stream ([MS-OFFCRYPTO] §2.3.5.4) ----------------------------
//
// Synthetic streams, encrypted here under a fixed salt with the crate's own RC4 (which
// is its own inverse), so every field the parser reads can be set on purpose. The shape
// is what Office writes — measured on the three `*_encprops` fixtures — and the control
// `a_well_formed_encrypted_summary_decrypts` is that shape unpoisoned.

mod encrypted_summary_input {
    use crate::encrypted_summary::{
        decrypt_stream, DOCUMENT_SUMMARY_INFORMATION, SUMMARY_INFORMATION,
    };
    use crate::rc4::decrypt_with_block;
    use crate::rc4_cryptoapi::CryptoApiKeySchedule;
    use crate::Error;

    fn schedule() -> CryptoApiKeySchedule {
        CryptoApiKeySchedule::new(super::PASSWORD, &[7u8; 16], 128).unwrap()
    }

    struct Desc {
        offset: u32,
        size: u32,
        block: u16,
        name: &'static str,
        flags: u8,
    }

    fn descriptor_bytes(d: &Desc) -> Vec<u8> {
        let units: Vec<u16> = d.name.encode_utf16().collect();
        let mut out = Vec::new();
        out.extend_from_slice(&d.offset.to_le_bytes());
        out.extend_from_slice(&d.size.to_le_bytes());
        out.extend_from_slice(&d.block.to_le_bytes());
        out.push(units.len() as u8);
        out.push(d.flags);
        out.extend_from_slice(&[0; 4]);
        for u in units {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out.extend_from_slice(&[0, 0]);
        out
    }

    /// `streams` are written after the 8-byte prefix, each encrypted under the block its
    /// descriptor names; `array_plain` and `prefix_plain` are encrypted under block 0.
    fn assemble(
        streams: &[(&[u8], u16)],
        array_plain: &[u8],
        prefix_plain: Option<[u32; 2]>,
    ) -> Vec<u8> {
        let s = schedule();
        let mut body = Vec::new();
        for (plain, block) in streams {
            let mut b = plain.to_vec();
            decrypt_with_block(&s, &mut b, u32::from(*block)).unwrap();
            body.extend_from_slice(&b);
        }
        let array_offset = 8 + body.len() as u32;
        let [off, size] = prefix_plain.unwrap_or([array_offset, array_plain.len() as u32]);
        let mut prefix = [off.to_le_bytes(), size.to_le_bytes()].concat();
        decrypt_with_block(&s, &mut prefix, 0).unwrap();
        let mut array = array_plain.to_vec();
        decrypt_with_block(&s, &mut array, 0).unwrap();
        [prefix, body, array].concat()
    }

    fn array(count: u32, descs: &[Desc]) -> Vec<u8> {
        let mut out = count.to_le_bytes().to_vec();
        for d in descs {
            out.extend_from_slice(&descriptor_bytes(d));
        }
        out
    }

    const SI: &[u8] = b"\xFE\xFF\x00\x00summary information";
    const DSI: &[u8] = b"\xFE\xFF\x00\x00document summary information";

    fn office_shape() -> Vec<Desc> {
        vec![
            Desc {
                offset: 8,
                size: SI.len() as u32,
                block: 0,
                name: "\u{5}SummaryInformation",
                flags: 1,
            },
            Desc {
                offset: 8 + SI.len() as u32,
                size: DSI.len() as u32,
                block: 1,
                name: "\u{5}DocumentSummaryInformation",
                flags: 1,
            },
        ]
    }

    fn run(
        streams: &[(&[u8], u16)],
        array_plain: &[u8],
        prefix: Option<[u32; 2]>,
    ) -> Result<Vec<(&'static str, Vec<u8>)>, Error> {
        decrypt_stream(&assemble(streams, array_plain, prefix), &schedule())
    }

    fn bad_naming<T: std::fmt::Debug>(
        got: &Result<T, Error>,
        field: crate::FileField,
        problem: fn(&crate::FileProblem) -> bool,
    ) -> bool {
        matches!(got, Err(Error::BadParameters { field: f, problem: p }) if *f == field && problem(p))
    }

    #[test]
    fn a_well_formed_encrypted_summary_decrypts() {
        let got = run(&[(SI, 0), (DSI, 1)], &array(2, &office_shape()), None).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], (SUMMARY_INFORMATION, SI.to_vec()));
        assert_eq!(got[1], (DOCUMENT_SUMMARY_INFORMATION, DSI.to_vec()));
    }

    #[test]
    fn the_prefix_and_the_array_must_lie_inside_the_stream() {
        let s = schedule();
        let got = decrypt_stream(&[0u8; 7], &s);
        assert!(bad_naming(&got, crate::FileField::SummaryStream, |p| matches!(p, crate::FileProblem::Truncated { .. })), "{got:?}");

        let arr = array(2, &office_shape());
        let end = 8 + (SI.len() + DSI.len()) as u32;
        // Past the end by one byte.
        let got = run(
            &[(SI, 0), (DSI, 1)],
            &arr,
            Some([end, arr.len() as u32 + 1]),
        );
        assert!(bad_naming(&got, crate::FileField::SummaryDescriptorArray, |p| matches!(p, crate::FileProblem::OutOfBounds { .. })), "{got:?}");
        // Inside the prefix.
        let got = run(&[(SI, 0), (DSI, 1)], &arr, Some([4, arr.len() as u32]));
        assert!(bad_naming(&got, crate::FileField::SummaryDescriptorArray, |p| matches!(p, crate::FileProblem::OutOfBounds { .. })), "{got:?}");
        // Wrapping.
        let got = run(&[(SI, 0), (DSI, 1)], &arr, Some([u32::MAX, u32::MAX]));
        assert!(bad_naming(&got, crate::FileField::SummaryDescriptorArray, |p| matches!(p, crate::FileProblem::OutOfBounds { .. })), "{got:?}");
        // Too small for its count.
        let got = run(&[(SI, 0), (DSI, 1)], &arr, Some([end, 3]));
        assert!(bad_naming(&got, crate::FileField::SummaryDescriptorArray, |p| matches!(p, crate::FileProblem::Truncated { .. })), "{got:?}");
    }

    #[test]
    fn the_count_is_bounded_by_the_array_before_any_descriptor_is_read() {
        // A count the array could hold at its smallest descriptors, but these are not the
        // smallest: the third runs off the end, and is named.
        let got = run(&[(SI, 0), (DSI, 1)], &array(3, &office_shape()), None);
        assert!(bad_naming(&got, crate::FileField::SummaryDescriptor, |p| matches!(p, crate::FileProblem::Truncated { .. })), "{got:?}");
        // One it could not hold however short the names: refused before the loop.
        let got = run(&[(SI, 0), (DSI, 1)], &array(1_000, &office_shape()), None);
        assert!(
            bad_naming(&got, crate::FileField::SummaryDescriptorCount, |p| matches!(p, crate::FileProblem::OutOfRange { got: 1000, .. })),
            "{got:?}"
        );
        let got = run(
            &[(SI, 0), (DSI, 1)],
            &array(u32::MAX, &office_shape()),
            None,
        );
        assert!(
            bad_naming(&got, crate::FileField::SummaryDescriptorCount, |p| matches!(p, crate::FileProblem::OutOfRange { .. })),
            "{got:?}"
        );
    }

    #[test]
    fn a_name_must_fit_the_array_and_be_terminated() {
        let mut arr = array(2, &office_shape());
        arr[4 + 10] = 200; // the first NameSize, past the array
        let got = run(&[(SI, 0), (DSI, 1)], &arr, None);
        assert!(
            bad_naming(&got, crate::FileField::SummaryStreamName, |p| matches!(p, crate::FileProblem::OutOfBounds { .. })),
            "{got:?}"
        );

        let mut arr = array(2, &office_shape());
        let nul = 4 + 16 + 2 * "\u{5}SummaryInformation".encode_utf16().count();
        arr[nul] = b'x';
        let got = run(&[(SI, 0), (DSI, 1)], &arr, None);
        assert!(bad_naming(&got, crate::FileField::SummaryStreamName, |p| matches!(p, crate::FileProblem::Unterminated)), "{got:?}");
    }

    #[test]
    fn a_storage_or_a_foreign_stream_is_refused_by_name_not_skipped() {
        let mut descs = office_shape();
        descs[1].flags = 0;
        let got = run(&[(SI, 0), (DSI, 1)], &array(2, &descs), None);
        assert!(
            matches!(got, Err(Error::UnsupportedEncryptedContent(m)) if m.contains("storage")),
            "{got:?}"
        );

        let mut descs = office_shape();
        descs[1].name = "\u{5}DocumentSummaryInformatioN";
        let got = run(&[(SI, 0), (DSI, 1)], &array(2, &descs), None);
        assert!(
            matches!(got, Err(Error::UnsupportedEncryptedContent(m)) if m.contains("other than the two")),
            "{got:?}"
        );
    }

    #[test]
    fn stream_extents_are_bounded_unique_and_disjoint() {
        let mut descs = office_shape();
        descs[1].name = "\u{5}SummaryInformation";
        let got = run(&[(SI, 0), (DSI, 1)], &array(2, &descs), None);
        assert!(bad_naming(&got, crate::FileField::SummaryDescriptor, |p| matches!(p, crate::FileProblem::Duplicate)), "{got:?}");

        let mut descs = office_shape();
        descs[1].size += 1; // into the descriptor array
        let got = run(&[(SI, 0), (DSI, 1)], &array(2, &descs), None);
        assert!(
            bad_naming(&got, crate::FileField::SummaryStreamExtent, |p| matches!(p, crate::FileProblem::OutOfBounds { .. })),
            "{got:?}"
        );

        let mut descs = office_shape();
        descs[0].offset = 0; // over the prefix
        let got = run(&[(SI, 0), (DSI, 1)], &array(2, &descs), None);
        assert!(
            bad_naming(&got, crate::FileField::SummaryStreamExtent, |p| matches!(p, crate::FileProblem::OutOfBounds { .. })),
            "{got:?}"
        );

        let mut descs = office_shape();
        descs[1].offset -= 1; // one byte into the first
        let got = run(&[(SI, 0), (DSI, 1)], &array(2, &descs), None);
        assert!(bad_naming(&got, crate::FileField::SummaryStreamExtent, |p| matches!(p, crate::FileProblem::Overlaps)), "{got:?}");
    }

    /// Each stream is read under its descriptor's block, not under the step-2 text's 0:
    /// with the second descriptor claiming block 0, its bytes come back as noise.
    #[test]
    fn each_stream_is_decrypted_under_its_own_block() {
        let mut descs = office_shape();
        descs[1].block = 0;
        let got = run(&[(SI, 0), (DSI, 1)], &array(2, &descs), None).unwrap();
        assert_ne!(
            got[1].1, DSI,
            "block 1's bytes under block 0 must not decrypt"
        );
    }

    /// The fixture whose header has `fDocProps` clear, with its `encryption` stream
    /// removed: the properties have nowhere to come from, and the decrypt says which
    /// stream is missing rather than returning a file with no properties at all.
    #[test]
    #[cfg_attr(
        not(fixture_corpus),
        ignore = "needs the fixture corpus, which the published crate does not ship"
    )]
    fn a_missing_encrypted_summary_stream_is_named() {
        let mut cursor = std::io::Cursor::new(super::fixture("word97_encprops.doc"));
        {
            let mut cfb = cfb::CompoundFile::open(&mut cursor).unwrap();
            cfb.remove_stream("/encryption").unwrap();
            cfb.flush().unwrap();
        }
        let got = crate::decrypt_binary_office(&cursor.into_inner(), super::PASSWORD);
        assert!(
            matches!(got, Err(Error::MissingStream(m)) if m.starts_with("encryption")),
            "{:?}",
            got.map(|p| p.len())
        );
        // Control: the untouched fixture decrypts.
        assert!(crate::decrypt_binary_office(
            &super::fixture("word97_encprops.doc"),
            super::PASSWORD
        )
        .is_ok());
    }
}

// ---- The PowerPoint `Pictures` stream ([MS-PPT] §2.1.3) --------------------------------

mod pictures_input {
    use crate::powerpoint97::decrypt_pictures;
    use crate::rc4::decrypt_with_block;
    use crate::rc4_cryptoapi::CryptoApiKeySchedule;
    use crate::Error;

    fn schedule() -> CryptoApiKeySchedule {
        CryptoApiKeySchedule::new(super::PASSWORD, &[9u8; 16], 128).unwrap()
    }

    /// One blip record, encrypted field by field the way PowerPoint writes it: the
    /// header, then each fixed field, then the data, each from a fresh block-0 keystream.
    fn blip(rec_type: u16, instance: u16, fields: &[&[u8]], rec_len: Option<u32>) -> Vec<u8> {
        let s = schedule();
        let body_len: usize = fields.iter().map(|f| f.len()).sum();
        let ver_inst = instance << 4;
        let mut header = [
            ver_inst.to_le_bytes().as_slice(),
            &rec_type.to_le_bytes(),
            &rec_len.unwrap_or(body_len as u32).to_le_bytes(),
        ]
        .concat();
        decrypt_with_block(&s, &mut header, 0).unwrap();
        let mut out = header;
        for f in fields {
            let mut f = f.to_vec();
            decrypt_with_block(&s, &mut f, 0).unwrap();
            out.extend_from_slice(&f);
        }
        out
    }

    const UID: &[u8] = &[0xAB; 16];
    const PNG_DATA: &[u8] = b"\x89PNG\r\n\x1a\nnot really a picture";

    fn png() -> Vec<u8> {
        blip(0xF01E, 0x6E0, &[UID, &[0xFF], PNG_DATA], None)
    }

    fn bad_naming(
        got: &Result<(), Error>,
        field: crate::FileField,
        problem: fn(&crate::FileProblem) -> bool,
    ) -> bool {
        matches!(got, Err(Error::BadParameters { field: f, problem: p }) if *f == field && problem(p))
    }

    #[test]
    fn well_formed_blips_decrypt_field_by_field() {
        // One UID and a tag; two UIDs (the odd instance) and a metafile header.
        let header = [0x11u8; 34];
        let mut stream = [
            png(),
            blip(0xF01A, 0x3D5, &[UID, UID, &header, b"emf bytes"], None),
        ]
        .concat();
        decrypt_pictures(&schedule(), &mut stream).unwrap();
        assert_eq!(&stream[8 + 16 + 1..8 + 16 + 1 + PNG_DATA.len()], PNG_DATA);
        assert!(stream.ends_with(b"emf bytes"));
        let emf_at = 8 + 16 + 1 + PNG_DATA.len();
        assert_eq!(&stream[emf_at + 2..emf_at + 4], &0xF01Au16.to_le_bytes());
        assert_eq!(&stream[emf_at + 8 + 32..emf_at + 8 + 32 + 34], &header);
    }

    #[test]
    fn a_record_must_fit_the_stream() {
        let mut stream = png();
        stream.extend_from_slice(&[0; 5]);
        let got = decrypt_pictures(&schedule(), &mut stream);
        assert!(bad_naming(&got, crate::FileField::PicturesRecord, |p| matches!(p, crate::FileProblem::Truncated { .. })), "{got:?}");

        let mut stream = blip(0xF01E, 0x6E0, &[UID, &[0xFF], PNG_DATA], Some(1_000));
        let got = decrypt_pictures(&schedule(), &mut stream);
        assert!(bad_naming(&got, crate::FileField::PicturesRecord, |p| matches!(p, crate::FileProblem::OutOfBounds { len: 1000, .. })), "{got:?}");

        let mut stream = blip(0xF01E, 0x6E0, &[&UID[..10]], None);
        let got = decrypt_pictures(&schedule(), &mut stream);
        assert!(bad_naming(&got, crate::FileField::PicturesRecord, |p| matches!(p, crate::FileProblem::Truncated { .. })), "{got:?}");
    }

    #[test]
    fn what_is_not_a_known_blip_is_refused_not_left_encrypted() {
        let mut stream = blip(0xF007, 0x002, &[&[0; 36]], None);
        let got = decrypt_pictures(&schedule(), &mut stream);
        assert!(
            matches!(got, Err(Error::UnsupportedEncryptedContent(m)) if m.contains("OfficeArtFBSE")),
            "{got:?}"
        );

        let mut stream = blip(0xF020, 0x6E0, &[UID, &[0xFF]], None);
        let got = decrypt_pictures(&schedule(), &mut stream);
        assert!(
            matches!(got, Err(Error::UnsupportedEncryptedContent(m)) if m.contains("does not define")),
            "{got:?}"
        );

        let mut stream = blip(0x1234, 0, &[UID], None);
        let got = decrypt_pictures(&schedule(), &mut stream);
        assert!(bad_naming(&got, crate::FileField::PicturesRecord, |p| matches!(p, crate::FileProblem::NotInSet { .. })), "{got:?}");

        // A PNG with a JPEG's instance.
        let mut stream = blip(0xF01E, 0x46A, &[UID, &[0xFF]], None);
        let got = decrypt_pictures(&schedule(), &mut stream);
        assert!(bad_naming(&got, crate::FileField::PicturesRecord, |p| matches!(p, crate::FileProblem::Unrecognized { .. })), "{got:?}");
    }
}

// ---- Rights management and Word 6.0/95, refused by name (0.1.0-rc.6) -----------------

mod refused_by_name {
    use crate::Error;
    use std::io::{Cursor, Seek, SeekFrom, Write};

    fn add_stream(data: Vec<u8>, name: &str, bytes: &[u8]) -> Vec<u8> {
        let mut cursor = Cursor::new(data);
        {
            let mut cfb = cfb::CompoundFile::open(&mut cursor).unwrap();
            cfb.create_stream(name).unwrap().write_all(bytes).unwrap();
            cfb.flush().unwrap();
        }
        cursor.into_inner()
    }

    /// The IRM placeholder is an unencrypted document, so without the rights-management
    /// check the walk answers `NotEncrypted` and a caller keeps the placeholder.
    #[test]
    #[cfg_attr(
        not(fixture_corpus),
        ignore = "needs the fixture corpus, which the published crate does not ship"
    )]
    fn a_rights_managed_binary_document_is_refused_not_called_unencrypted() {
        let plain = super::fixture("word97_plain.doc");
        // Control: the placeholder alone.
        assert!(matches!(
            crate::decrypt_binary_office(&plain, super::PASSWORD),
            Err(Error::NotEncrypted)
        ));
        let irm = add_stream(plain, "/\u{9}DRMContent", &[0u8; 512]);
        let got = crate::decrypt_binary_office(&irm, super::PASSWORD).map(|p| p.len());
        assert!(
            matches!(got, Err(Error::UnsupportedEncryptedContent(m)) if m.contains("IRM")),
            "{got:?}"
        );
    }

    /// The Excel 5.0/95 workbook Excel 16 writes: refused by name, not misread as BIFF8
    /// and not called unencrypted.
    #[test]
    #[cfg_attr(
        not(fixture_corpus),
        ignore = "needs the fixture corpus, which the published crate does not ship"
    )]
    fn an_excel_95_workbook_is_refused_by_name() {
        let got =
            crate::decrypt_binary_office(&super::fixture("excel95_plain.xls"), super::PASSWORD)
                .map(|p| p.len());
        assert!(
            matches!(&got, Err(Error::UnsupportedAlgorithm { name, .. }) if name.to_string().contains("BIFF5")),
            "{got:?}"
        );
    }

    #[test]
    #[cfg_attr(
        not(fixture_corpus),
        ignore = "needs the fixture corpus, which the published crate does not ship"
    )]
    fn a_word_95_document_is_refused_by_name() {
        for (fixture, n_fib, refused) in [
            ("word97_plain.doc", 0x0069u16, true),
            ("word97_password.doc", 0x0065, true),
            // Control: the same edit to a Word 97 nFib is not this refusal.
            ("word97_password.doc", 0x00C1, false),
        ] {
            let mut cursor = Cursor::new(super::fixture(fixture));
            {
                let mut cfb = cfb::CompoundFile::open(&mut cursor).unwrap();
                let mut s = cfb.open_stream("/WordDocument").unwrap();
                s.seek(SeekFrom::Start(2)).unwrap();
                s.write_all(&n_fib.to_le_bytes()).unwrap();
                s.flush().unwrap();
            }
            let got = crate::decrypt_binary_office(&cursor.into_inner(), super::PASSWORD)
                .map(|p| p.len());
            let is_refusal = matches!(
                &got,
                Err(Error::UnsupportedAlgorithm { name, .. }) if name.to_string().contains("Word 6.0/95")
            );
            assert_eq!(is_refusal, refused, "{fixture} nFib {n_fib:#06x}: {got:?}");
        }
    }

    /// An IRM package has no `EncryptionInfo`; the OOXML path names rights management
    /// rather than a missing stream.
    #[test]
    fn a_rights_managed_package_is_refused_by_the_ooxml_path_by_name() {
        let mut cfb = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        cfb.create_storage("/\u{6}DataSpaces").unwrap();
        // One entry: EncryptedPackage -> DRMEncryptedDataSpace.
        let mut map = 8u32.to_le_bytes().to_vec();
        map.extend_from_slice(&1u32.to_le_bytes());
        let mut body = 1u32.to_le_bytes().to_vec();
        body.extend_from_slice(&0u32.to_le_bytes());
        for text in ["EncryptedPackage", "DRMEncryptedDataSpace"] {
            let units: Vec<u16> = text.encode_utf16().collect();
            let mut lp = ((units.len() * 2) as u32).to_le_bytes().to_vec();
            units
                .iter()
                .for_each(|u| lp.extend_from_slice(&u.to_le_bytes()));
            lp.resize(lp.len() + (4 - lp.len() % 4) % 4, 0);
            body.extend_from_slice(&lp);
        }
        map.extend_from_slice(&((body.len() + 4) as u32).to_le_bytes());
        map.extend_from_slice(&body);
        cfb.create_stream("/\u{6}DataSpaces/DataSpaceMap")
            .unwrap()
            .write_all(&map)
            .unwrap();
        cfb.create_stream("/EncryptedPackage")
            .unwrap()
            .write_all(&[0u8; 64])
            .unwrap();
        cfb.flush().unwrap();
        let irm = cfb.into_inner().into_inner();

        let got = crate::decrypt_ooxml(&irm, super::PASSWORD).map(|p| p.len());
        assert!(
            matches!(&got, Err(Error::UnsupportedAlgorithm { name, .. }) if name.to_string().contains("IRM")),
            "{got:?}"
        );
        // Control: the map removed, the same container is a missing EncryptionInfo.
        let mut cursor = Cursor::new(irm);
        {
            let mut cfb = cfb::CompoundFile::open(&mut cursor).unwrap();
            cfb.remove_stream("/\u{6}DataSpaces/DataSpaceMap").unwrap();
            cfb.flush().unwrap();
        }
        let got = crate::decrypt_ooxml(&cursor.into_inner(), super::PASSWORD).map(|p| p.len());
        assert!(matches!(got, Err(Error::MissingStream(_))), "{got:?}");
    }
}
