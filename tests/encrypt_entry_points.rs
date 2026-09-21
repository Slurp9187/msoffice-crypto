//! The three encrypt entry points through the public API alone, from outside the crate
//! — the view a downstream consumer has when it wires the Office path up.
//!
//! Every other test of `encrypt_ooxml` and `encrypt_ooxml_standard` is a unit test inside
//! `src/`, with access to `pub(crate)` seams and the seeded RNG. This file is compiled as
//! a separate crate against the built library and can see only what a consumer sees, so
//! it pins the contract a consumer relies on: both entry points produce a file the
//! decrypt side opens, only the agile one can be authenticated, and the two are told
//! apart by `classify` and by the integrity policy rather than by which function was
//! called.
//!
//! # Why this file exists — a review finding on GH #7
//!
//! Cargo names this package's build artifacts by a hash that does not include the
//! checkout's path, and decides whether to rebuild by comparing source mtimes against the
//! last build. With one target directory shared between several checkouts of this
//! package, `cargo test` in one checkout can be handed the unit-test binary another
//! checkout built — and report that binary's green result, for a different set of tests.
//! The unit tests cannot notice: they are *inside* the binary that is missing them. That
//! is what a reviewer hit: a `165 passed` from a binary with no `standard_encrypt` tests
//! in it, and then, on adding an integration test like this one, a build that failed to
//! link with `cannot find function `encrypt_ooxml_standard` in crate `msoffice_crypto``
//! — the library artifact predated the function.
//!
//! A test here is compiled against that artifact, so when the artifact is stale and this
//! file is not, the run fails loudly instead of passing quietly. It is not a complete
//! guard — a stale integration binary is as silent as a stale unit binary — and the rule
//! that is the guard is one target directory per checkout, recorded in `CHANGELOG.md`.
//! What this file adds beyond that is the consumer-side contract above, which no unit
//! test states.

#![cfg(feature = "crypto-ops")]

use msoffice_crypto::{
    classify, decrypt_ooxml, decrypt_ooxml_with_policy, encrypt_ooxml, encrypt_ooxml_standard,
    encrypt_ooxml_with_params, is_cfb_office, EncryptParam, EncryptParamProblem, EncryptParams,
    Error, Family, IntegrityDeclaration, IntegrityOutcome, IntegrityPolicy,
};

const PASSWORD: &str = "testpass";

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {name} must be present: {e}"))
}

/// Both entry points round-trip through the public decrypt API; only the agile one is
/// authenticated; `Require` tells them apart by name; a wrong password is a wrong
/// password for both. The agile half of every assertion is the positive control for the
/// standard half — a suite in which `Require` refused everything would fail here.
#[test]
fn both_entry_points_round_trip_and_only_the_agile_one_authenticates() {
    let plain = fixture("plain.docx");
    let standard = encrypt_ooxml_standard(&plain, PASSWORD).expect("encrypt_ooxml_standard");
    let agile = encrypt_ooxml(&plain, PASSWORD).expect("encrypt_ooxml");

    // What a caller holding the bytes can learn before it has a password.
    assert!(is_cfb_office(&standard) && is_cfb_office(&agile));
    let (std_class, agile_class) = (classify(&standard), classify(&agile));
    assert_eq!(std_class.family, Family::Standard);
    assert_eq!(agile_class.family, Family::Agile);
    assert_eq!(
        std_class.data_integrity,
        IntegrityDeclaration::NotApplicable,
        "the standard format defines no integrity element"
    );
    assert_eq!(
        agile_class.data_integrity,
        IntegrityDeclaration::Declared,
        "the agile writer always declares one"
    );

    // The default policy opens both, and says which one it could authenticate.
    let opened = decrypt_ooxml_with_policy(&standard, PASSWORD, IntegrityPolicy::default())
        .expect("the standard file opens under the default policy");
    assert_eq!(
        opened.package, plain,
        "standard: the package must survive the round trip"
    );
    assert_eq!(opened.integrity, IntegrityOutcome::NotApplicable);
    assert!(!opened.integrity.is_authenticated());

    let opened = decrypt_ooxml_with_policy(&agile, PASSWORD, IntegrityPolicy::default())
        .expect("the agile file opens under the default policy");
    assert_eq!(
        opened.package, plain,
        "agile: the package must survive the round trip"
    );
    assert_eq!(opened.integrity, IntegrityOutcome::Verified);
    assert!(opened.integrity.is_authenticated());

    // `Require` refuses the format that cannot deliver, by name, and accepts the one
    // that can — the control without which the refusal proves nothing.
    assert!(
        matches!(
            decrypt_ooxml_with_policy(&standard, PASSWORD, IntegrityPolicy::Require),
            Err(Error::IntegrityUnavailable(_))
        ),
        "Require must refuse a standard file as IntegrityUnavailable"
    );
    let opened = decrypt_ooxml_with_policy(&agile, PASSWORD, IntegrityPolicy::Require)
        .expect("Require must accept an agile file this crate wrote");
    assert_eq!(opened.package, plain);
    assert_eq!(opened.integrity, IntegrityOutcome::Verified);

    // The one-argument API, and the wrong password on both.
    assert_eq!(decrypt_ooxml(&standard, PASSWORD).unwrap(), plain);
    assert_eq!(decrypt_ooxml(&agile, PASSWORD).unwrap(), plain);
    for (name, file) in [("standard", &standard), ("agile", &agile)] {
        assert!(
            matches!(
                decrypt_ooxml(file, "not the password"),
                Err(Error::WrongPassword)
            ),
            "{name}: a wrong password must be WrongPassword, not another variant"
        );
    }
}

/// An independent implementation opens what both public entry points wrote.
/// `office-crypto` is a separate MIT crate with its own CFB reader and its own parse of
/// both `EncryptionInfo` layouts, so agreeing with it is evidence about the files rather
/// than about this crate's reading of itself.
#[test]
fn an_independent_implementation_opens_what_both_entry_points_wrote() {
    let plain = fixture("plain.docx");
    for (name, container) in [
        (
            "standard",
            encrypt_ooxml_standard(&plain, PASSWORD).unwrap(),
        ),
        ("agile", encrypt_ooxml(&plain, PASSWORD).unwrap()),
    ] {
        let theirs = office_crypto::decrypt_from_bytes(container, PASSWORD).unwrap_or_else(|e| {
            panic!("{name}: office-crypto must open what this crate wrote: {e:?}")
        });
        assert_eq!(
            theirs, plain,
            "{name}: office-crypto must recover the package byte for byte"
        );
    }
}

/// A tuple that is not the default, submitted from outside the crate: it is accepted,
/// it reaches the bytes, and the file opens again under the strictest policy.
///
/// **This test's first job is to compile.** `..Default::default()` is struct-expression
/// syntax, which `#[non_exhaustive]` forbids across a crate boundary — so if
/// `EncryptParams` ever gains that attribute "for forward compatibility", this file
/// stops building and says so. `src/encrypt_params.rs` argues for omitting it; the
/// argument can only be *checked* from a separate crate, which is here and not there.
///
/// The second job is that the parameter is not merely accepted and dropped.
/// `classify` reads `p:encryptedKey/@keyBits` back out of the artifact, so the
/// assertion is about the file rather than about the call returning `Ok`. Comparing two
/// artifacts byte for byte could not do that — two encryptions differ on their random
/// salts whatever the tuple.
#[test]
fn a_non_default_tuple_reaches_the_file_and_opens_again() {
    let plain = fixture("plain.docx");

    // One field moved: a 128-bit KEK wrapping the default 256-bit package key. SHA-512's
    // 64-byte digest carries either size, so this is a tuple `validate` accepts, and it
    // is one no seeded golden in `src/` describes.
    let params = EncryptParams {
        password_key_bits: 128,
        ..Default::default()
    };
    params
        .validate()
        .expect("a 128-bit KEK under SHA-512 is a tuple this crate writes");

    let sealed =
        encrypt_ooxml_with_params(&plain, PASSWORD, params).expect("encrypt_ooxml_with_params");

    assert!(is_cfb_office(&sealed));
    let class = classify(&sealed);
    assert_eq!(class.family, Family::Agile);
    assert_eq!(
        class.password_key.and_then(|p| p.key_bits),
        Some(128),
        "the caller's keyBits must be what the file declares"
    );
    assert_eq!(
        class.key_data.and_then(|k| k.key_bits),
        Some(256),
        "and the other element's must be untouched — the two keyBits are separate"
    );
    assert_eq!(
        class.data_integrity,
        IntegrityDeclaration::Declared,
        "the dataIntegrity guarantee is not scoped to the default tuple"
    );

    // `Require` is the strict read: the HMAC over this tuple's ciphertext verifies, so
    // the key schedule agrees with the document that describes it.
    let opened = decrypt_ooxml_with_policy(&sealed, PASSWORD, IntegrityPolicy::Require)
        .expect("Require must accept an agile file this crate wrote, whatever the tuple");
    assert_eq!(opened.package, plain);
    assert_eq!(opened.integrity, IntegrityOutcome::Verified);

    // The negative control: a wrong password on a non-default tuple is still reported as
    // a wrong password, not as the parse failure a mis-sized blob would produce.
    assert!(
        matches!(
            decrypt_ooxml(&sealed, "not the password"),
            Err(Error::WrongPassword)
        ),
        "a non-default tuple must not turn a wrong password into another variant"
    );

    // And the default entry point still writes the default, which is what makes the
    // assertion above evidence that the parameter travelled rather than a coincidence.
    let default_sealed = encrypt_ooxml(&plain, PASSWORD).expect("encrypt_ooxml");
    assert_eq!(
        classify(&default_sealed)
            .password_key
            .and_then(|p| p.key_bits),
        Some(256)
    );
}

/// A tuple this crate will not write is refused with a typed verdict a consumer can
/// `match` — and refused before the password is used for anything.
///
/// The pair of cases is the point: 200 breaks AES's rule while satisfying the format's,
/// and 12 breaks the format's own. A consumer that renders these to a human says
/// different things about them, which it can only do if the two variants reach it.
#[test]
fn a_tuple_this_crate_will_not_write_is_refused_by_name() {
    let plain = fixture("plain.docx");

    for (bits, expected) in [
        (200, EncryptParamProblem::UnsupportedByCipher),
        (12, EncryptParamProblem::OutsideSpecRange),
    ] {
        let params = EncryptParams {
            password_key_bits: bits,
            ..Default::default()
        };
        let err = encrypt_ooxml_with_params(&plain, PASSWORD, params)
            .expect_err("keyBits this crate will not write must be refused");
        assert!(
            matches!(
                err,
                Error::EncryptParams {
                    param: EncryptParam::KeyBits,
                    problem,
                    got,
                    ..
                } if problem == expected && got == bits
            ),
            "keyBits {bits} must be refused as {expected:?}, got {err:?}"
        );
    }

    // The control: the same call with the same file and a tuple that is fine succeeds,
    // so the refusals above are about the parameters and not about the input.
    encrypt_ooxml_with_params(&plain, PASSWORD, EncryptParams::default())
        .expect("the default tuple must still be written");
}
