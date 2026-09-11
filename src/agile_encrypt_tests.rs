//! The generated encryptor, put through the real verification path.
//!
//! The load-bearing test here is [`the_generated_encryptor_verifies_through_the_real_path`]:
//! serialise the material with `encryption_info::write`, parse it back with
//! `agile::parse_encryption_info`, and hand the result to `agile::verify_password` — the
//! same three functions a decrypt runs, in the same order, with nothing re-derived for the
//! test's convenience. A generator that agreed with a bespoke check written beside it would
//! prove nothing; this one has to satisfy the code that opens files.
//!
//! What is *not* proven here, and waits for #8: that another implementation accepts it.
//! Steps 5 and 6 assemble a whole file, and `office-crypto` and `msoffcrypto-tool` are the
//! oracles that make the claim external. Everything below is self-consistency plus a
//! committed golden, which is what step 4 can honestly offer.

use super::*;
use crate::agile;
use crate::encryption_info::{self, EncryptionInfoParams};
use rand::SeedableRng;

const PASSWORD: &str = "testpass";
const SPIN_COUNT: u32 = 100_000;

/// The seed every golden below is measured under. All-zero, so it is obviously arbitrary
/// and obviously not chosen to make an assertion pass.
const SEED: [u8; 32] = [0u8; 32];

fn seeded() -> chacha20::ChaCha12Rng {
    chacha20::ChaCha12Rng::from_seed(SEED)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Byte-exact output under a seeded RNG — plan D3's payoff.
///
/// Pins two things nothing else does. The **draw order**: password salt, verifier input,
/// session key, keyData salt, which is herumi's (`encode.hpp:167, 174, 180, 187`) and
/// which nothing in the format enforces — reorder two draws and every value below changes
/// while every other test in this file still passes. And the **derivation**: any change to
/// the spin hash, the block keys or the CBC calls moves these bytes.
///
/// Measured, not computed by hand. If a deliberate change moves them, re-measure with the
/// same seed and say in the commit what moved and why.
#[test]
fn the_material_is_byte_exact_under_a_seeded_rng() {
    let material = generate(PASSWORD, SPIN_COUNT, &mut seeded()).unwrap();

    assert_eq!(
        hex(&material.password_salt),
        "9bf49a6a0755f953811fce125f2683d5"
    );
    assert_eq!(
        hex(&material.key_data_salt),
        "0bd58841203e74fe86fc71338ce0173d"
    );
    assert_eq!(
        hex(&material.encrypted_verifier_hash_input),
        "0fe715e6275524574c2bc39c92ebec0b"
    );
    assert_eq!(
        hex(&material.encrypted_verifier_hash_value),
        "7984ae30716d67e29d21eaf75dd4e7d980c9565e89ba7f2d11e31cd74fc5c51f\
         53ae214d9799a2557393e8b758e5400b8f08135e84cb24a42917056a874c10f6"
    );
    assert_eq!(
        hex(&material.encrypted_key_value),
        "5c667ede00de124d64f6295629a3b9ec57521a0095fecd3c375b675aa3f7ba9a"
    );
    assert_eq!(
        material.session_key.with_secret(|k| hex(k)),
        "0564f879d27ae3c02ce82834acfa8c793a629f2ca0de6919610be82f411326be"
    );
}

/// Dummy `dataIntegrity` blobs, so step 3's writer can be driven before step 5 exists.
///
/// The writer requires them to be `roundUp(hashSize, blockSize)` = 64 bytes and does not
/// otherwise care; nothing in this file verifies an HMAC. Generating them for real is
/// step 5.
const NO_INTEGRITY_YET: [u8; 64] = [0u8; 64];

/// **Write, parse, verify — the three functions a decrypt actually runs.**
///
/// This is the test the module exists to pass. `generate` produces the encryptor,
/// `encryption_info::write` serialises it, `agile::parse_encryption_info` reads it back
/// from bytes, and `agile::verify_password` — the function `decrypt` calls, unmodified —
/// accepts the password. Nothing is re-derived here for the test's benefit, so a generator
/// that disagreed with the reader in any of the four places they must agree (salt, spin
/// hash, block key, CBC IV) fails.
///
/// The wrong-password case is the control. Without it this would pass on a
/// `verify_password` that accepted everything, which is the shape of the bug that makes a
/// verifier worthless.
#[test]
fn the_generated_encryptor_verifies_through_the_real_path() {
    let material = generate(PASSWORD, SPIN_COUNT, &mut seeded()).unwrap();

    let stream = encryption_info::write(&EncryptionInfoParams {
        key_data_salt: &material.key_data_salt,
        encrypted_hmac_key: &NO_INTEGRITY_YET,
        encrypted_hmac_value: &NO_INTEGRITY_YET,
        spin_count: SPIN_COUNT,
        password_salt: &material.password_salt,
        encrypted_verifier_hash_input: &material.encrypted_verifier_hash_input,
        encrypted_verifier_hash_value: &material.encrypted_verifier_hash_value,
        encrypted_key_value: &material.encrypted_key_value,
    })
    .expect("generated material must satisfy the writer's own length rules");

    let params = agile::parse_encryption_info(&stream[8..])
        .expect("the writer's output must parse -- that is step 3's contract");

    let h_final = agile::spin_hash(
        HashAlgorithm::Sha512,
        PASSWORD,
        &material.password_salt,
        SPIN_COUNT,
    );
    agile::verify_password(&params, &h_final)
        .expect("the password used to generate the encryptor must verify against it");

    // The control.
    let wrong = agile::spin_hash(
        HashAlgorithm::Sha512,
        "not the password",
        &material.password_salt,
        SPIN_COUNT,
    );
    assert!(
        matches!(
            agile::verify_password(&params, &wrong),
            Err(Error::WrongPassword)
        ),
        "a wrong password must be refused, and by name"
    );
}

/// Re-derive the three block keys from the password and unwrap all three blobs.
///
/// The decrypt-side view of what `generate` produced, using `agile`'s own
/// `derive_block_key` and `aes_cbc_decrypt`: the verifier pair must satisfy
/// `SHA512(input) == value`, which is the relation `verify_password` checks, and
/// `encryptedKeyValue` must unwrap to exactly the session key the material carries.
///
/// The second half is what the test above cannot see. `verify_password` never touches
/// `encryptedKeyValue` — a generator that wrapped the session key under the *wrong* block
/// key would pass every password check and produce a file whose package decrypts to noise,
/// with no `<dataIntegrity>` element obliged to say so.
#[test]
fn every_blob_unwraps_to_what_produced_it() {
    let material = generate(PASSWORD, SPIN_COUNT, &mut seeded()).unwrap();
    let h_final = agile::spin_hash(
        HashAlgorithm::Sha512,
        PASSWORD,
        &material.password_salt,
        SPIN_COUNT,
    );

    let unwrap_with = |block_key: &[u8; 8], blob: &[u8]| -> Vec<u8> {
        let key = agile::derive_block_key(HashAlgorithm::Sha512, &h_final, block_key, KEY_BITS)
            .expect("SHA-512 yields more than 32 bytes");
        key.with_secret(|k| agile::aes_cbc_decrypt(blob, k, &material.password_salt))
            .expect("the blob was encrypted under this key and IV")
    };

    let verifier_input = unwrap_with(
        &agile::BLOCK_VERIFIER_INPUT,
        &material.encrypted_verifier_hash_input,
    );
    let verifier_value = unwrap_with(
        &agile::BLOCK_VERIFIER_HASH,
        &material.encrypted_verifier_hash_value,
    );
    assert_eq!(
        HashAlgorithm::Sha512.digest(&verifier_input),
        verifier_value,
        "SHA512(verifierHashInput) must equal the decrypted verifierHashValue"
    );

    let key_value = unwrap_with(&agile::BLOCK_KEY_VALUE, &material.encrypted_key_value);
    assert_eq!(
        material.session_key.with_secret(|k| k.to_vec()),
        key_value,
        "encryptedKeyValue must unwrap to the session key it was made from"
    );

    // And the three block keys are genuinely three: wrapping every blob under one key
    // would satisfy neither assertion above by accident, but it is cheap to say outright.
    let keys: Vec<Vec<u8>> = [
        agile::BLOCK_VERIFIER_INPUT,
        agile::BLOCK_VERIFIER_HASH,
        agile::BLOCK_KEY_VALUE,
    ]
    .iter()
    .map(|bk| {
        agile::derive_block_key(HashAlgorithm::Sha512, &h_final, bk, KEY_BITS)
            .unwrap()
            .with_secret(|k| k.to_vec())
    })
    .collect();
    let mut unique = keys.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 3, "the three block keys must differ");
}

/// **The session key is 32 drawn bytes, never a short draw padded to length.**
///
/// The reference this module was ported from once drew `encryptedKey.saltSize` bytes and
/// `normalizeKey`d up to `keyBits / 8` — `resize(32, 0x36)`, an AES-256 key with 128 bits of
/// entropy and a constant top half. Nothing downstream noticed: the file decrypts perfectly
/// in every reader, because the key is whatever the writer says it is, so no round-trip test
/// in any implementation could find it. It was reported privately and **fixed upstream on
/// 2026-09-10** (herumi/msoffice `b5fed299`); see `agile_encrypt`'s module header.
///
/// The test stays, because the property is worth guarding on its own: a short draw padded to
/// length is a mistake any implementation can make, and this is the assertion that catches
/// it here. The last 16 bytes must not be a constant filler, and — the stronger form — every
/// byte position must vary across seeds, which a constant tail cannot do.
#[test]
fn the_session_key_is_fully_drawn_never_padded_to_length() {
    let material = generate(PASSWORD, SPIN_COUNT, &mut seeded()).unwrap();
    material.session_key.with_secret(|k| {
        assert_eq!(k.len(), 32, "AES-256 takes 32 bytes");
        assert_ne!(
            &k[16..],
            &[0x36u8; 16],
            "the top half must be entropy, not a constant filler"
        );
    });

    // Every byte position varies across seeds. A padded tail is constant at 16 positions,
    // so this fails on herumi's construction however the filler byte is chosen.
    let mut varies = [false; 32];
    let first = material.session_key.with_secret(|k| k.to_vec());
    for seed in 1u8..24 {
        let other = generate(
            PASSWORD,
            1, // a low spin count: this loop is about the RNG, not the KDF
            &mut chacha20::ChaCha12Rng::from_seed([seed; 32]),
        )
        .unwrap();
        other.session_key.with_secret(|k| {
            for i in 0..32 {
                varies[i] |= k[i] != first[i];
            }
        });
    }
    assert!(
        varies.iter().all(|v| *v),
        "some byte of the session key never changed across 23 seeds: {varies:?}"
    );
}

/// The same seed reproduces everything; a different seed reproduces nothing.
///
/// The first half is what makes the golden above meaningful, and the second is what says
/// the generator is actually consuming the RNG rather than deriving from the password
/// alone — which would compile, pass the verification test, and hand every document
/// written with one password the same salts and the same session key.
#[test]
fn the_rng_decides_the_output_and_the_seed_decides_the_rng() {
    let a = generate(PASSWORD, SPIN_COUNT, &mut seeded()).unwrap();
    let b = generate(PASSWORD, SPIN_COUNT, &mut seeded()).unwrap();
    assert_eq!(a.password_salt, b.password_salt);
    assert_eq!(a.key_data_salt, b.key_data_salt);
    assert_eq!(a.encrypted_key_value, b.encrypted_key_value);
    assert_eq!(
        a.session_key.with_secret(|k| k.to_vec()),
        b.session_key.with_secret(|k| k.to_vec())
    );

    let c = generate(
        PASSWORD,
        SPIN_COUNT,
        &mut chacha20::ChaCha12Rng::from_seed([1u8; 32]),
    )
    .unwrap();
    assert_ne!(a.password_salt, c.password_salt);
    assert_ne!(a.key_data_salt, c.key_data_salt);
    assert_ne!(
        a.encrypted_verifier_hash_input,
        c.encrypted_verifier_hash_input
    );
    assert_ne!(
        a.session_key.with_secret(|k| k.to_vec()),
        c.session_key.with_secret(|k| k.to_vec())
    );
}

/// The public entry point works and is not accidentally deterministic.
///
/// `crate::encrypt_ooxml` is one line over [`encrypt`] with the system RNG, which is the
/// point — but "the seeded path and the real path are the same code" is a claim, and an
/// untested wrapper is where that claim would quietly stop being true. Two calls must
/// differ; if they ever match, the system RNG is not being consumed.
#[test]
fn the_public_entry_point_produces_a_fresh_file_each_call() {
    let a = crate::encrypt_ooxml(b"PK\x03\x04 not really a zip", PASSWORD).unwrap();
    let b = crate::encrypt_ooxml(b"PK\x03\x04 not really a zip", PASSWORD).unwrap();
    assert_ne!(
        a, b,
        "two encryptions of the same input must not share salts or keys"
    );
    assert_eq!(a.len(), b.len(), "but they are the same shape");
}

/// The whole write path under a seeded RNG is byte-stable, and this is its golden.
///
/// Plan D3's payoff at the level that matters: not the key schedule alone but the
/// complete container — `EncryptionInfo`, `EncryptedPackage`, the four `DataSpaces`
/// blobs and the CFB directory `cfb` builds around them, which has no timestamps and no
/// random identifiers. A change to any step of the assembly moves this digest.
///
/// Measured, not computed. If a deliberate change moves it, re-measure with the same seed
/// and say in the commit what moved and why. The plaintext is `plain.docx`, the file the
/// standard fixture decrypts to, so the round-trip tests in `lib.rs` and this golden are
/// about the same bytes.
#[test]
fn the_whole_container_is_byte_exact_under_a_seeded_rng() {
    use sha2::{Digest, Sha256};
    let plain = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/plain.docx"
    ))
    .expect("plain.docx is committed");
    let container = encrypt(&plain, PASSWORD, SPIN_COUNT, &mut seeded()).unwrap();
    let digest = hex(&Sha256::digest(&container));
    assert_eq!(
        (container.len(), digest.as_str()),
        (GOLDEN_LEN, GOLDEN_SHA256),
        "the container's (length, SHA-256) under the seeded RNG"
    );

    // And the same seed reproduces it exactly; a golden that only held once is a fluke.
    let again = encrypt(&plain, PASSWORD, SPIN_COUNT, &mut seeded()).unwrap();
    assert_eq!(container, again);
}

/// Measured on 2026-09-05 under `SEED`, `PASSWORD`, `SPIN_COUNT` and `plain.docx`.
const GOLDEN_LEN: usize = 41984;
const GOLDEN_SHA256: &str = "b4cc009e94bddf00c6610e0b897e5ee0a4485bd5bc9e40a024131d9e789a2a6b";

/// Every generated blob is the length step 3's writer demands.
///
/// Stated directly as well as through the writer, because the writer's refusal names a
/// field and this names the rule: `roundUp(saltSize, blockSize)` for the verifier input,
/// `roundUp(hashSize, blockSize)` for its hash, `keyBits / 8` for the wrapped key.
#[test]
fn every_generated_length_is_the_one_the_format_fixes() {
    let m = generate(PASSWORD, SPIN_COUNT, &mut seeded()).unwrap();
    assert_eq!(m.password_salt.len(), SALT_LEN);
    assert_eq!(m.key_data_salt.len(), SALT_LEN);
    assert_eq!(m.encrypted_verifier_hash_input.len(), 16); // roundUp(16, 16)
    assert_eq!(m.encrypted_verifier_hash_value.len(), 64); // roundUp(64, 16)
    assert_eq!(m.encrypted_key_value.len(), SESSION_KEY_LEN);
    assert_eq!(KEY_BITS, 256);

    // The two salts are drawn independently. Equal salts would make the crossing bug
    // `AgileParams` is shaped to prevent invisible in every test that uses this material.
    assert_ne!(m.password_salt, m.key_data_salt);
}

// ---- the public entry point, end to end (GH #6 step 6) --------------------------------

fn plain_docx() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/plain.docx"
    ))
    .expect("plain.docx is committed")
}

/// Flip one byte of `/EncryptedPackage` inside a container this crate wrote, deep in the
/// ciphertext body — segment 1, so past the first 4096-byte segment and its IV — leaving
/// the header, the XML and the container untouched, so a refusal is the HMAC's and not a
/// parse failure's.
fn tampered(container: Vec<u8>) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut cursor = std::io::Cursor::new(container);
    {
        let mut cfb = cfb::CompoundFile::open(&mut cursor).expect("we wrote a CFB");
        let mut stream = cfb
            .open_stream("/EncryptedPackage")
            .expect("we wrote the stream");
        let at = 8 + 4096 + 100;
        stream.seek(SeekFrom::Start(at)).unwrap();
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).unwrap();
        stream.seek(SeekFrom::Start(at)).unwrap();
        stream.write_all(&[b[0] ^ 0x01]).unwrap();
        stream.flush().unwrap();
        cfb.flush().unwrap();
    }
    cursor.into_inner()
}

/// What this crate writes, this crate reads back — under the **fail-closed default**, so
/// the `dataIntegrity` element it wrote is required and verified, not merely tolerated —
/// and a wrong password is a wrong password.
#[test]
fn encrypt_ooxml_round_trips_under_the_fail_closed_default() {
    let plain = plain_docx();
    let container = crate::encrypt_ooxml(&plain, PASSWORD).expect("encrypt");
    assert!(crate::is_cfb_office(&container));

    let crate::Decrypted {
        package: back,
        integrity: outcome,
    } = crate::decrypt_ooxml_with_policy(&container, PASSWORD, crate::IntegrityPolicy::default())
        .expect("what this crate wrote, it must read");
    assert_eq!(outcome, crate::IntegrityOutcome::Verified);
    assert_eq!(
        back, plain,
        "the package must survive the round trip byte for byte"
    );

    assert!(matches!(
        crate::decrypt_ooxml(&container, "not the password"),
        Err(Error::WrongPassword)
    ));
}

/// The HMAC the writer produces is one the reader enforces: a flipped ciphertext byte is
/// refused by name under the default, and the `Skip` control decrypts the same file to
/// the wrong bytes — so the refusal is the tag's work and not some unrelated check.
#[test]
fn a_tampered_encrypt_ooxml_output_is_refused_by_the_hmac_it_wrote() {
    let plain = plain_docx();
    let bad = tampered(crate::encrypt_ooxml(&plain, PASSWORD).unwrap());
    assert!(matches!(
        crate::decrypt_ooxml(&bad, PASSWORD),
        Err(Error::IntegrityCheckFailed)
    ));
    let crate::Decrypted {
        package: wrong,
        integrity: outcome,
    } = crate::decrypt_ooxml_with_policy(&bad, PASSWORD, crate::IntegrityPolicy::Skip)
        .expect("Skip returns unauthenticated bytes");
    assert_eq!(outcome, crate::IntegrityOutcome::Skipped);
    assert_ne!(wrong, plain, "the flipped byte must change the plaintext");
}

/// `classify` sees exactly the file Office 16 would have written: agile, AES-256/SHA-512,
/// 100 000 rounds, `dataIntegrity` declared. The detection half of the crate and the
/// encrypt half agree about what a file is.
#[test]
fn encrypt_ooxml_output_classifies_as_the_tuple_office_writes() {
    let c = crate::classify(&crate::encrypt_ooxml(&plain_docx(), PASSWORD).unwrap());
    assert_eq!(c.container, crate::Container::Cfb);
    assert_eq!(c.document, crate::Document::OoxmlPackage);
    assert_eq!(c.family, crate::Family::Agile);
    assert_eq!(c.data_integrity, crate::IntegrityDeclaration::Declared);
    assert!(c.is_encrypted() && c.is_supported());
    let key_data = c.key_data.expect("agile declares <keyData>");
    assert_eq!(key_data.hash, Some(crate::HashAlgorithm::Sha512));
    assert_eq!(key_data.key_bits, Some(256));
    let password = c.password_key.expect("and a password key encryptor");
    assert_eq!(password.spin_count, Some(100_000));
}

/// The degenerate package. Zero segments, an 8-byte `EncryptedPackage` of nothing but
/// its prefix, an HMAC over those 8 bytes — and it round-trips to an empty `Vec`.
#[test]
fn an_empty_package_round_trips() {
    let container = crate::encrypt_ooxml(&[], PASSWORD).unwrap();
    let crate::Decrypted {
        package: back,
        integrity: outcome,
    } = crate::decrypt_ooxml_with_policy(&container, PASSWORD, crate::IntegrityPolicy::default())
        .unwrap();
    assert_eq!(outcome, crate::IntegrityOutcome::Verified);
    assert!(back.is_empty());
}

/// **An independent implementation reads a file this crate generated** — key material,
/// `EncryptionInfo`, `EncryptedPackage`, `dataIntegrity`, container, all ours.
///
/// Until this test every "another implementation reads it" claim in the crate was about a
/// container filled with streams lifted from a working fixture. `office-crypto` is a
/// separate MIT crate with its own CFB reader and its own parse of [MS-OFFCRYPTO];
/// agreeing with it is evidence about the file. It is one of GH #8's four readers; the
/// other three are run on the artifact the last test below writes, and recorded.
#[test]
fn an_independent_implementation_reads_what_encrypt_ooxml_wrote() {
    let plain = plain_docx();
    let container = crate::encrypt_ooxml(&plain, PASSWORD).unwrap();
    let theirs = office_crypto::decrypt_from_bytes(container, PASSWORD)
        .expect("office-crypto must open a file this crate wrote");
    assert_eq!(theirs, plain);
}

/// A package over the ceiling is refused before any key is derived or byte encrypted:
/// the same 1 GiB the decrypt side refuses, checked on the way in so that a file this
/// crate writes is a file it can read back. The allocation is lazy on every platform
/// this runs on, so the test costs an inequality, not a gigabyte.
#[test]
fn a_package_over_the_ceiling_is_refused_before_any_work() {
    let big = vec![0u8; crate::limits::PAYLOAD_CEILING + 1];
    let got = crate::encrypt_ooxml(&big, PASSWORD).map(|c| c.len());
    assert!(
        matches!(&got, Err(Error::BadParameters(msg)) if msg.contains("PAYLOAD_CEILING")),
        "over the ceiling must be refused by name, got: {got:?}"
    );
}

/// Writes the artifact GH #8's external readers are run against — real Word over COM,
/// LibreOffice over UNO, `msoffcrypto-tool` and `office-crypto` — and prints where.
/// `cargo test` cannot drive the first two; `tools/acceptance_gate.py` drives all four
/// and their verdicts are recorded in `CHANGELOG.md` against this exact file, the same
/// way the container spike's were.
///
/// The directory is `MSOFFICE_CRYPTO_ARTIFACT_DIR` when set, else the system temp
/// directory. Set it, and to a private directory: the file name is fixed, so every
/// session's `cargo test` on this machine writes the same path, and a gate pointed there
/// can measure another build's artifact — that happened during #8, and is why the
/// evidence in `CHANGELOG.md` is recorded against a SHA-256 rather than a path. CI's gate
/// job sets it for the same reason. The digest printed below is the one the gate prints
/// on its first line: if they differ, the gate did not read this run's file.
#[test]
fn encrypt_ooxml_writes_the_artifact_the_external_readers_are_run_on() {
    let dir = std::env::var_os("MSOFFICE_CRYPTO_ARTIFACT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let path = dir.join("msoffice_crypto_encrypt_ooxml.docx");
    let artifact = crate::encrypt_ooxml(&plain_docx(), PASSWORD).unwrap();
    let digest = hex(&crate::hash::HashAlgorithm::Sha256.digest(&artifact));
    std::fs::write(&path, &artifact).unwrap();
    println!(
        "encrypt_ooxml artifact written to {} ({} bytes, SHA-256 {digest})",
        path.display(),
        artifact.len()
    );
}
