//! The standard writer, put through the real read path and the external oracles.
//!
//! The load-bearing tests are the ones that do not consult this module's own idea of the
//! format: `standard::parse_encryption_info` → `derive_standard_key` → `verify_password`
//! on what `write_encryption_info` wrote, the full `decrypt_ooxml` round trip, a diff of
//! the header against the committed fixture, and `office-crypto` reading the container.
//! Real Word 16 and `msoffcrypto-tool` are run on the artifact the last test writes, and
//! their verdicts are recorded in `CHANGELOG.md` against the commit that produced it.

use super::*;
use crate::standard;
use rand::SeedableRng;
use std::io::Read;

const PASSWORD: &str = "testpass";

/// The seed every golden below is measured under. All-zero, so it is obviously arbitrary
/// and obviously not chosen to make an assertion pass.
const SEED: [u8; 32] = [0u8; 32];

fn seeded() -> chacha20::ChaCha12Rng {
    chacha20::ChaCha12Rng::from_seed(SEED)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("fixture {name} must be present, not optional: {e}"))
}

fn plain_docx() -> Vec<u8> {
    fixture("plain.docx")
}

/// Read one stream out of a CFB container held in memory.
fn stream_of(data: &[u8], path: &str) -> Vec<u8> {
    let mut container =
        cfb::CompoundFile::open(std::io::Cursor::new(data)).expect("input is a CFB container");
    let mut bytes = Vec::new();
    container
        .open_stream(path)
        .unwrap_or_else(|e| panic!("container has no {path}: {e}"))
        .read_to_end(&mut bytes)
        .expect("in-memory read");
    bytes
}

/// Byte-exact material under a seeded RNG — plan D3's payoff at the key-schedule level.
///
/// Pins the draw order (salt, then verifier — nothing in the format enforces it, and
/// swapping the two moves every value below) and the derivation: any change to the KDF,
/// the verifier construction or the ECB calls moves these bytes. Measured, not computed
/// by hand; if a deliberate change moves them, re-measure with the same seed and say in
/// the commit what moved and why.
#[test]
fn the_material_is_byte_exact_under_a_seeded_rng() {
    let m = generate(PASSWORD, &mut seeded()).unwrap();
    // One tuple, so a failure reports every value at once rather than the first.
    assert_eq!(
        (
            hex(&m.salt),
            m.key.with_secret(|k| hex(k)),
            hex(&m.encrypted_verifier),
            hex(&m.encrypted_verifier_hash),
        ),
        (
            // The salt is the seed's first 16 bytes -- the same bytes agile's password
            // salt draws under the same seed, which is what "same RNG, same draw" means.
            "9bf49a6a0755f953811fce125f2683d5".to_string(),
            "4fc16bef730947b705f403c5c0cc1e29".to_string(),
            "f27051fb20ffee956d61b12c6d6f767f".to_string(),
            "1f00f5d638f4cd5c3a2a59eaac8daeb146963fe038681093f6f066e95fbe8e8c".to_string(),
        ),
        "(salt, key, EncryptedVerifier, EncryptedVerifierHash)"
    );
}

/// **Write, parse, derive, verify — the four functions a decrypt actually runs.**
///
/// `generate` produces the encryptor, `write_encryption_info` serialises it,
/// `standard::parse_encryption_info` reads it back from bytes, and
/// `standard::verify_password` — the function `decrypt` calls, unmodified — accepts the
/// password against a key re-derived from the parsed salt. Nothing is re-derived here
/// for the test's benefit, so a writer that disagreed with the reader about the salt,
/// the KDF, the verifier hash or its padding fails.
///
/// The wrong-password case is the control. Without it this would pass on a
/// `verify_password` that accepted everything.
#[test]
fn the_generated_encryptor_verifies_through_the_real_path() {
    let m = generate(PASSWORD, &mut seeded()).unwrap();
    let stream = write_encryption_info(&m.salt, &m.encrypted_verifier, &m.encrypted_verifier_hash);

    let params = standard::parse_encryption_info(&stream[8..])
        .expect("the writer's output must parse -- that is the writer's contract");
    assert_eq!(params.salt, &m.salt);
    assert_eq!(params.encrypted_verifier, &m.encrypted_verifier);
    assert_eq!(params.encrypted_verifier_hash, &m.encrypted_verifier_hash);
    assert_eq!(params.key_size_bytes, AES128_KEY_LEN);

    let key = derive_standard_key(PASSWORD, params.salt, params.key_size_bytes).unwrap();
    standard::verify_password(&key, &params)
        .expect("the password used to generate the encryptor must verify against it");

    // The control.
    let wrong =
        derive_standard_key("not the password", params.salt, params.key_size_bytes).unwrap();
    assert!(
        matches!(
            standard::verify_password(&wrong, &params),
            Err(Error::WrongPassword)
        ),
        "a wrong password must be refused, and by name"
    );
}

/// The decrypt-side view of the two blobs: `EncryptedVerifierHash` unwraps to
/// `SHA1(verifier)` followed by **twelve zero bytes** — the whole 32-byte blob, not just
/// its first 20.
///
/// `verify_password` cannot see the tail (it compares the digest's 20 bytes), so a
/// writer padding with `0x36` would pass every test above and produce a file Word reads
/// as a wrong password — the GH #13 finding, on this format. This is the assertion that
/// catches it.
#[test]
fn the_verifier_hash_blob_is_sha1_of_the_verifier_zero_padded_to_the_whole_blob() {
    let m = generate(PASSWORD, &mut seeded()).unwrap();
    let verifier = m
        .key
        .with_secret(|k| standard::aes128_ecb_decrypt(k, &m.encrypted_verifier))
        .unwrap();
    let hash_blob = m
        .key
        .with_secret(|k| standard::aes128_ecb_decrypt(k, &m.encrypted_verifier_hash))
        .unwrap();

    let mut expected = Sha1::digest(&verifier).to_vec();
    expected.resize(ENCRYPTED_VERIFIER_HASH_LEN, 0);
    assert_eq!(
        hash_blob, expected,
        "SHA1(verifier) || 0x00 * 12, the whole blob"
    );
    assert_eq!(
        &hash_blob[SHA1_LEN..],
        &[0u8; 12],
        "the tail is zero, as Word requires"
    );
    assert_eq!(verifier.len(), VERIFIER_LEN);
}

/// The header is the fixture's layout, byte for byte, with exactly three fields
/// replaced — the three where the fixture is non-conforming — plus the random-derived
/// ones.
///
/// `standard_encrypted.docx` declares `Flags 0x36` and RC4's `AlgID 0x6801` under
/// `fAES`, a pair [MS-OFFCRYPTO] §2.3.2 forbids, and a zero `Flags` copy where the spec
/// says "a copy". The writer emits the conforming `0x24` / `0x660E` / `0x24`. Everything
/// else — the version pair, `EncryptionHeaderSize`, `SizeExtra`, `AlgIDHash`, `KeySize`,
/// `ProviderType`, both reserved words, the CSP name and its terminator, `SaltSize`,
/// `VerifierHashSize`, the 224-byte total — must match the fixture exactly. The
/// fixture's original values are asserted first so the deviation is documented rather
/// than assumed.
#[test]
#[cfg_attr(
    not(fixture_corpus),
    ignore = "needs the fixture corpus, which the published crate does not ship"
)]
fn the_encryption_info_is_the_fixtures_layout_with_the_spec_values_where_it_deviates() {
    let m = generate(PASSWORD, &mut seeded()).unwrap();
    let ours = write_encryption_info(&m.salt, &m.encrypted_verifier, &m.encrypted_verifier_hash);

    let mut expected = stream_of(&fixture("standard_encrypted.docx"), "/EncryptionInfo");
    assert_eq!(expected.len(), 224, "the fixture's stream length");

    let u32_at = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    assert_eq!(u32_at(&expected, 4), 0, "the fixture's Flags copy is zero");
    assert_eq!(u32_at(&expected, 8), 140, "EncryptionHeaderSize");
    assert_eq!(u32_at(&expected, 12), 0x36, "the fixture's Flags");
    assert_eq!(
        u32_at(&expected, 20),
        0x6801,
        "the fixture's AlgID is RC4's"
    );

    // The three non-conforming fields, replaced with the spec's values.
    expected[4..8].copy_from_slice(&FLAGS.to_le_bytes());
    expected[12..16].copy_from_slice(&FLAGS.to_le_bytes());
    expected[20..24].copy_from_slice(&ALG_ID_AES_128.to_le_bytes());

    // The verifier's three random-derived fields. 12 + 140 = the verifier's offset.
    let v = 12 + 140;
    expected[v + 4..v + 20].copy_from_slice(&m.salt);
    expected[v + 20..v + 36].copy_from_slice(&m.encrypted_verifier);
    expected[v + 40..v + 72].copy_from_slice(&m.encrypted_verifier_hash);

    assert_eq!(ours.len(), expected.len());
    assert_eq!(
        ours, expected,
        "the header differs from the fixture somewhere it must not"
    );
}

/// The `EncryptedPackage` stream: the prefix is the plaintext length (not the padded
/// length), the body is the plaintext rounded up to a block, and ECB means the body is
/// the same whether it was chunked or not.
#[test]
fn the_encrypted_package_is_the_length_prefix_and_a_block_padded_body() {
    let key = DerivedKey::new(vec![0x5Au8; 16]);
    for len in [0usize, 1, 15, 16, 17, 4095, 4096, 4097, 10_000] {
        let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let stream = encrypt_package(&plain, &key).unwrap();
        let declared = u64::from_le_bytes(stream[..8].try_into().unwrap());
        assert_eq!(declared as usize, len, "the prefix is the plaintext length");
        assert_eq!(
            stream.len() - 8,
            len.div_ceil(16) * 16,
            "the body is the plaintext rounded up to a block"
        );

        // Chunk-independence: one ECB pass over the zero-padded whole is the same bytes.
        let mut padded = plain.clone();
        padded.resize(len.div_ceil(16) * 16, 0);
        let whole = key.with_secret(|k| aes128_ecb_encrypt(k, &padded)).unwrap();
        assert_eq!(&stream[8..], &whole[..], "len={len}");
    }
}

/// What this crate writes, this crate reads back — byte for byte, reporting the
/// integrity outcome the format allows — and a wrong password is a wrong password.
#[test]
fn encrypt_ooxml_standard_round_trips_and_reports_no_integrity_element() {
    let plain = plain_docx();
    let container = crate::encrypt_ooxml_standard(&plain, PASSWORD).expect("encrypt");
    assert!(crate::is_cfb_office(&container));

    let (back, outcome) =
        crate::decrypt_ooxml_with_policy(&container, PASSWORD, crate::IntegrityPolicy::default())
            .expect("what this crate wrote, it must read");
    assert_eq!(outcome, crate::IntegrityOutcome::NotApplicable);
    assert!(
        !outcome.is_authenticated(),
        "the format cannot authenticate"
    );
    assert_eq!(
        back, plain,
        "the package must survive the round trip byte for byte"
    );
    assert_eq!(crate::decrypt_ooxml(&container, PASSWORD).unwrap(), plain);

    assert!(matches!(
        crate::decrypt_ooxml(&container, "not the password"),
        Err(Error::WrongPassword)
    ));
    // A caller demanding a guarantee the format cannot give is refused by name.
    assert!(matches!(
        crate::decrypt_ooxml_with_policy(&container, PASSWORD, crate::IntegrityPolicy::Require),
        Err(Error::IntegrityUnavailable(_))
    ));
}

/// **The negative control against the agile suite.** A flipped ciphertext byte in a
/// standard file is not detected — the format defines nothing that could detect it —
/// so the same tamper that is `IntegrityCheckFailed` for `encrypt_ooxml`'s output
/// *decrypts*, to the wrong bytes, with `NotApplicable`. Pinned so the difference between
/// the two entry points is a test rather than a sentence in a doc comment.
#[test]
fn a_tampered_standard_file_decrypts_to_the_wrong_bytes_because_the_format_cannot_tell() {
    use std::io::{Seek, SeekFrom, Write};
    let plain = plain_docx();
    let mut cursor = std::io::Cursor::new(crate::encrypt_ooxml_standard(&plain, PASSWORD).unwrap());
    {
        let mut cfb = cfb::CompoundFile::open(&mut cursor).expect("we wrote a CFB");
        let mut stream = cfb
            .open_stream("/EncryptedPackage")
            .expect("we wrote the stream");
        // Deep in the ciphertext body, past the prefix and the ZIP local header.
        let at = 8 + 4096 + 100;
        stream.seek(SeekFrom::Start(at)).unwrap();
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).unwrap();
        stream.seek(SeekFrom::Start(at)).unwrap();
        stream.write_all(&[b[0] ^ 0x01]).unwrap();
        stream.flush().unwrap();
        cfb.flush().unwrap();
    }
    let tampered = cursor.into_inner();

    let (wrong, outcome) =
        crate::decrypt_ooxml_with_policy(&tampered, PASSWORD, crate::IntegrityPolicy::default())
            .expect("standard encryption has no tag to fail");
    assert_eq!(outcome, crate::IntegrityOutcome::NotApplicable);
    assert_eq!(wrong.len(), plain.len());
    assert_ne!(wrong, plain, "the flipped byte must change the plaintext");
    // ECB: the damage is exactly one 16-byte block, and every other byte survives.
    let differing = wrong.iter().zip(&plain).filter(|(a, b)| a != b).count();
    assert!(
        (1..=16).contains(&differing),
        "{differing} bytes differ; ECB confines it to one block"
    );
}

/// `classify` sees exactly the file Office 2007 would have written: standard, AES-128,
/// SHA-1, `4.2`, 16-byte salt, no integrity element to declare. The detection half of the
/// crate and the encrypt half agree about what a file is.
#[test]
fn encrypt_ooxml_standard_output_classifies_as_office_2007_aes_128() {
    let c = crate::classify(&crate::encrypt_ooxml_standard(&plain_docx(), PASSWORD).unwrap());
    assert_eq!(c.container, crate::Container::Cfb);
    assert_eq!(c.document, crate::Document::OoxmlPackage);
    assert_eq!(c.version, Some(STANDARD_VERSION));
    assert_eq!(c.family, crate::Family::Standard);
    assert_eq!(c.data_integrity, crate::IntegrityDeclaration::NotApplicable);
    assert!(c.is_encrypted() && c.is_supported());
    assert_eq!(
        c.key_data.expect("the EncryptionHeader is present"),
        crate::AlgorithmParams {
            cipher: Some(crate::CipherAlgorithm::Aes),
            hash: Some(crate::HashAlgorithm::Sha1),
            key_bits: Some(128),
            block_size: None,
            salt_size: Some(16),
            spin_count: None,
        }
    );
    assert!(c.password_key.is_none());
}

/// The degenerate package: an 8-byte `EncryptedPackage` of nothing but its prefix, and
/// it round-trips to an empty `Vec`.
#[test]
fn an_empty_package_round_trips() {
    let container = crate::encrypt_ooxml_standard(&[], PASSWORD).unwrap();
    assert_eq!(stream_of(&container, "/EncryptedPackage").len(), 8);
    let (back, outcome) =
        crate::decrypt_ooxml_with_policy(&container, PASSWORD, crate::IntegrityPolicy::default())
            .unwrap();
    assert_eq!(outcome, crate::IntegrityOutcome::NotApplicable);
    assert!(back.is_empty());
}

/// The whole write path under a seeded RNG is byte-stable, and this is its golden —
/// `EncryptionInfo`, `EncryptedPackage`, the four `DataSpaces` blobs and the CFB
/// directory `cfb` builds around them, timestamps zeroed. A change to any step moves
/// this digest.
///
/// Measured, not computed. If a deliberate change moves it, re-measure with the same
/// seed and say in the commit what moved and why. The plaintext is `plain.docx`, the
/// file the committed standard fixture decrypts to, so the fixture tests and this golden
/// are about the same bytes.
#[test]
fn the_whole_container_is_byte_exact_under_a_seeded_rng() {
    use sha2::{Digest as _, Sha256};
    let plain = plain_docx();
    let container = encrypt(&plain, PASSWORD, &mut seeded()).unwrap();
    let digest = hex(&Sha256::digest(&container));
    assert_eq!(
        (container.len(), digest.as_str()),
        (GOLDEN_LEN, GOLDEN_SHA256),
        "the container's (length, SHA-256) under the seeded RNG"
    );

    // And the same seed reproduces it exactly; a golden that only held once is a fluke.
    let again = encrypt(&plain, PASSWORD, &mut seeded()).unwrap();
    assert_eq!(container, again);
}

/// Measured on 2026-09-05 under `SEED`, `PASSWORD` and `plain.docx`.
const GOLDEN_LEN: usize = 40960;
const GOLDEN_SHA256: &str = "491298746ce1e46aed2c98b7bc9c061d97ccedf578062a901aa32f2249bc7e42";

/// The same seed reproduces everything; a different seed reproduces nothing — so the
/// generator is consuming the RNG rather than deriving from the password alone, which
/// would hand every document written with one password the same salt and key.
#[test]
fn the_rng_decides_the_output_and_the_seed_decides_the_rng() {
    let a = generate(PASSWORD, &mut seeded()).unwrap();
    let b = generate(PASSWORD, &mut seeded()).unwrap();
    assert_eq!(a.salt, b.salt);
    assert_eq!(a.encrypted_verifier, b.encrypted_verifier);
    assert_eq!(a.encrypted_verifier_hash, b.encrypted_verifier_hash);
    assert!(a.key.with_secret(|x| b.key.with_secret(|y| x == y)));

    let c = generate(PASSWORD, &mut chacha20::ChaCha12Rng::from_seed([1u8; 32])).unwrap();
    assert_ne!(a.salt, c.salt);
    assert_ne!(a.encrypted_verifier, c.encrypted_verifier);
    assert_ne!(a.encrypted_verifier_hash, c.encrypted_verifier_hash);
    assert!(
        a.key.with_secret(|x| c.key.with_secret(|y| x != y)),
        "a different salt derives a different key from the same password"
    );
}

/// The public entry point works and is not accidentally deterministic: two calls must
/// differ, or the system RNG is not being consumed.
#[test]
fn the_public_entry_point_produces_a_fresh_file_each_call() {
    let a = crate::encrypt_ooxml_standard(b"PK\x03\x04 not really a zip", PASSWORD).unwrap();
    let b = crate::encrypt_ooxml_standard(b"PK\x03\x04 not really a zip", PASSWORD).unwrap();
    assert_ne!(
        a, b,
        "two encryptions of the same input must not share a salt"
    );
    assert_eq!(a.len(), b.len(), "but they are the same shape");
}

/// **An independent implementation reads a file this crate generated** — header,
/// verifier, package, container, all ours. `office-crypto` is a separate MIT crate with
/// its own CFB reader and its own parse of [MS-OFFCRYPTO] §2.3.4.5, so agreeing with it
/// is evidence about the file. The other external readers are run on the artifact the
/// last test writes, and recorded.
#[test]
fn an_independent_implementation_reads_what_encrypt_ooxml_standard_wrote() {
    let plain = plain_docx();
    let container = crate::encrypt_ooxml_standard(&plain, PASSWORD).unwrap();
    let theirs = office_crypto::decrypt_from_bytes(container, PASSWORD)
        .expect("office-crypto must open a file this crate wrote");
    assert_eq!(theirs, plain);
}

/// A package over the ceiling is refused before any key is derived or byte encrypted.
/// The allocation is lazy on every platform this runs on, so the test costs an
/// inequality, not a gigabyte.
#[test]
fn a_package_over_the_ceiling_is_refused_before_any_work() {
    let big = vec![0u8; crate::limits::PAYLOAD_CEILING + 1];
    let got = crate::encrypt_ooxml_standard(&big, PASSWORD).map(|c| c.len());
    assert!(
        matches!(&got, Err(Error::BadParameters(msg)) if msg.contains("PAYLOAD_CEILING")),
        "over the ceiling must be refused by name, got: {got:?}"
    );
}

/// Writes the artifact the external readers are run against — real Word over COM and
/// `msoffcrypto-tool` — and prints where. `cargo test` cannot drive those; their verdicts
/// are recorded in `CHANGELOG.md` against this exact file. Reproduce with
/// `tools/word_com_check.ps1 -Path <this path>`.
#[test]
fn encrypt_ooxml_standard_writes_the_artifact_the_external_readers_are_run_on() {
    let path = std::env::temp_dir().join("msoffice_crypto_encrypt_ooxml_standard.docx");
    std::fs::write(
        &path,
        crate::encrypt_ooxml_standard(&plain_docx(), PASSWORD).unwrap(),
    )
    .unwrap();
    println!(
        "encrypt_ooxml_standard artifact written to {}",
        path.display()
    );
}
