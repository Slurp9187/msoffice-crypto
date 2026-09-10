//! The two encrypt entry points through the public API alone, from outside the crate —
//! the view a downstream consumer has when it wires the Office path up.
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
    is_cfb_office, Family, IntegrityDeclaration, IntegrityOutcome, IntegrityPolicy,
    OoXmlCryptoError,
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
    let (back, outcome) =
        decrypt_ooxml_with_policy(&standard, PASSWORD, IntegrityPolicy::default())
            .expect("the standard file opens under the default policy");
    assert_eq!(
        back, plain,
        "standard: the package must survive the round trip"
    );
    assert_eq!(outcome, IntegrityOutcome::NotApplicable);
    assert!(!outcome.is_authenticated());

    let (back, outcome) = decrypt_ooxml_with_policy(&agile, PASSWORD, IntegrityPolicy::default())
        .expect("the agile file opens under the default policy");
    assert_eq!(
        back, plain,
        "agile: the package must survive the round trip"
    );
    assert_eq!(outcome, IntegrityOutcome::Verified);
    assert!(outcome.is_authenticated());

    // `Require` refuses the format that cannot deliver, by name, and accepts the one
    // that can — the control without which the refusal proves nothing.
    assert!(
        matches!(
            decrypt_ooxml_with_policy(&standard, PASSWORD, IntegrityPolicy::Require),
            Err(OoXmlCryptoError::IntegrityUnavailable(_))
        ),
        "Require must refuse a standard file as IntegrityUnavailable"
    );
    let (back, outcome) = decrypt_ooxml_with_policy(&agile, PASSWORD, IntegrityPolicy::Require)
        .expect("Require must accept an agile file this crate wrote");
    assert_eq!(back, plain);
    assert_eq!(outcome, IntegrityOutcome::Verified);

    // The one-argument API, and the wrong password on both.
    assert_eq!(decrypt_ooxml(&standard, PASSWORD).unwrap(), plain);
    assert_eq!(decrypt_ooxml(&agile, PASSWORD).unwrap(), plain);
    for (name, file) in [("standard", &standard), ("agile", &agile)] {
        assert!(
            matches!(
                decrypt_ooxml(file, "not the password"),
                Err(OoXmlCryptoError::WrongPassword)
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
