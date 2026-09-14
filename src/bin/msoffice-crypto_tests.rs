//! Unit tests for the CLI's own logic — the parts that are not the library and not clap.
//!
//! **Fixture-free, and that is a packaging constraint rather than a preference.**
//! `Cargo.toml`'s `include` allowlist ships `src/**/*.rs`, so this module is published,
//! while seventeen of the nineteen fixtures are not. A single `include_bytes!` here
//! would turn the published crate's `cargo test` red over a file the tarball
//! deliberately does not ship. Nothing below reads a fixture — not even one of the two
//! that do ship.
//!
//! End-to-end behaviour (exit codes as a process, argv handling, file side effects) is
//! `tests/cli.rs`'s job from S2 onward; that file never reaches the tarball and may read
//! all nineteen.

use super::*;

/// `AlgorithmParams` is `#[non_exhaustive]`, so from this crate it can be neither
/// struct-literalled nor built with `..Default::default()`. Field assignment after
/// `Default::default()` is the only route, and routing it through a closure keeps
/// `clippy::field_reassign_with_default` off the call sites.
fn params(fill: impl FnOnce(&mut AlgorithmParams)) -> AlgorithmParams {
    let mut p = AlgorithmParams::default();
    fill(&mut p);
    p
}

#[test]
fn the_command_definition_is_internally_consistent() {
    // clap's own audit: a duplicate id, a group naming an argument that does not exist,
    // a short flag used twice -- and a `default_value` outside its own value_parser's
    // possible values, which is how a hard-coded `--integrity` default would surface.
    cli().debug_assert();
}

#[test]
fn help_names_all_three_subcommands() {
    let text = cli().render_long_help().to_string();
    for name in ["classify", "decrypt", "encrypt"] {
        assert!(text.contains(name), "top-level help must name {name}");
    }
}

#[test]
fn the_exit_code_table_in_the_help_carries_all_ten_codes() {
    // The sibling's block stops at 7. Ported unchanged it would leave the two codes
    // this crate added undocumented in the one place a user looks for them.
    for text in [AFTER_HELP, PASSWORD_AFTER_HELP] {
        for token in [
            "0 ok",
            "1 usage",
            "2 io",
            "3 not-office",
            "4 wrong-password",
            "5 refused",
            "6 malformed",
            "7 internal",
            "8 integrity",
            "9 unsupported",
        ] {
            assert!(text.contains(token), "exit-code help must carry {token:?}");
        }
    }
}

#[test]
fn derived_output_inserts_before_the_extension() {
    assert_eq!(
        derived_output(Path::new("report.docx"), "decrypted"),
        PathBuf::from("report.decrypted.docx")
    );
    assert_eq!(
        derived_output(Path::new("/tmp/a/book.xlsx"), "encrypted"),
        PathBuf::from("/tmp/a/book.encrypted.xlsx")
    );
    // The legacy extensions survive too: `decrypt_binary_office` returns a rewritten
    // CFB, not a package, so the extension must not be normalised to anything.
    assert_eq!(
        derived_output(Path::new("memo.doc"), "decrypted"),
        PathBuf::from("memo.decrypted.doc")
    );
}

#[test]
fn derived_output_appends_when_there_is_no_extension() {
    assert_eq!(
        derived_output(Path::new("report"), "decrypted"),
        PathBuf::from("report.decrypted")
    );
}

#[test]
fn derived_output_keeps_a_dotted_stem() {
    // `a.b.docx` has stem `a.b`; the suffix goes before the real extension only.
    assert_eq!(
        derived_output(Path::new("a.b.docx"), "decrypted"),
        PathBuf::from("a.b.decrypted.docx")
    );
}

#[test]
fn first_line_strips_one_trailing_newline_and_no_more() {
    assert_eq!(first_line("testpass\n"), "testpass");
    assert_eq!(first_line("testpass\r\n"), "testpass");
    assert_eq!(first_line("testpass"), "testpass");
    // Only the first line: a file with more in it is not a multi-line password.
    assert_eq!(first_line("testpass\nignored\n"), "testpass");
    // Trailing spaces can be deliberate, so they survive.
    assert_eq!(first_line("testpass  \n"), "testpass  ");
    assert_eq!(first_line(""), "");
}

#[test]
fn exit_codes_map_every_error_class() {
    // `Error` has no `PartialEq` (deliberately), so every assertion here is on the u8
    // the mapping returned, never on the error value.
    assert_eq!(exit_code(&Error::NotACfbFile), EX_NOT_OFFICE);
    assert_eq!(
        exit_code(&Error::MissingStream("EncryptionInfo")),
        EX_MALFORMED
    );
    assert_eq!(
        exit_code(&Error::BadParameters(String::new())),
        EX_MALFORMED
    );
    assert_eq!(exit_code(&Error::Io(std::io::Error::other("x"))), EX_IO);
    assert_eq!(
        exit_code(&Error::UnsupportedEncryptionVersion(4, 3)),
        EX_UNSUPPORTED
    );
    assert_eq!(exit_code(&Error::XmlParse(String::new())), EX_MALFORMED);
    assert_eq!(exit_code(&Error::WrongPassword), EX_WRONG_PASSWORD);
    assert_eq!(exit_code(&Error::CipherError), EX_MALFORMED);
    assert_eq!(
        exit_code(&Error::UnsupportedAlgorithm {
            what: "p:encryptedKey/@hashAlgorithm",
            name: String::new()
        }),
        EX_UNSUPPORTED
    );
    assert_eq!(exit_code(&Error::IntegrityCheckFailed), EX_INTEGRITY);
    assert_eq!(exit_code(&Error::IntegrityElementMissing), EX_INTEGRITY);
    assert_eq!(exit_code(&Error::IntegrityUnavailable("x")), EX_INTEGRITY);
    assert_eq!(exit_code(&Error::RandomSource(String::new())), EX_INTERNAL);

    // Gated with the variant itself: `cli` does not enable `legacy-binary`, and
    // `Error::NotEncrypted` does not exist in that column.
    #[cfg(feature = "legacy-binary")]
    assert_eq!(exit_code(&Error::NotEncrypted), EX_REFUSED);
}

#[test]
fn the_four_facts_the_table_exists_for_stay_distinct() {
    // Collapsing any pair of these re-creates, at the process boundary, the bug
    // CLAUDE.md's cryptographic rules forbid inside the library.
    let codes = [
        EX_WRONG_PASSWORD,
        EX_REFUSED,
        EX_INTEGRITY,
        EX_UNSUPPORTED,
        EX_MALFORMED,
    ];
    for (i, a) in codes.iter().enumerate() {
        for b in &codes[i + 1..] {
            assert_ne!(a, b, "two distinct facts share one exit code");
        }
    }
}

#[test]
fn the_integrity_default_is_the_librarys_own_default() {
    // Not "the default is require-where-defined": that flip has already happened once
    // (GH #12), and a CLI with the old name typed in would have survived it looking
    // correct. What is pinned is that the flag's default IS whatever the library
    // defaults to, rendered through the table clap validates against.
    let rendered = policy_name(IntegrityPolicy::default());
    assert!(
        POLICY_NAMES.contains(&rendered),
        "the library default renders as {rendered:?}, which --integrity would reject"
    );
    let m = cli()
        .try_get_matches_from(["msoffice-crypto", "decrypt", "f.docx"])
        .expect("decrypt must parse with no --integrity");
    let sub = m.subcommand_matches("decrypt").expect("decrypt");
    assert_eq!(
        sub.get_one::<String>("integrity").map(String::as_str),
        Some(rendered)
    );
}

#[test]
fn the_equals_form_parses() {
    // The GNU `--flag=value` form the sibling's hand-rolled parser rejected outright.
    let m = cli()
        .try_get_matches_from(["msoffice-crypto", "decrypt", "f.docx", "--output=x.docx"])
        .expect("--flag=value must parse");
    let sub = m.subcommand_matches("decrypt").expect("decrypt");
    assert_eq!(
        sub.get_one::<String>("output").map(String::as_str),
        Some("x.docx")
    );
}

#[test]
fn exactly_one_password_source_is_accepted() {
    // clap's ArgGroup enforces it, so this pins the wiring rather than the rule.
    let two = cli().try_get_matches_from([
        "msoffice-crypto",
        "decrypt",
        "f.docx",
        "--password-stdin",
        "--password-env",
        "PW",
    ]);
    assert!(two.is_err(), "two password sources must be rejected");

    for one in [
        vec!["msoffice-crypto", "decrypt", "f.docx", "--password-stdin"],
        vec![
            "msoffice-crypto",
            "decrypt",
            "f.docx",
            "--password-env",
            "PW",
        ],
        vec![
            "msoffice-crypto",
            "decrypt",
            "f.docx",
            "--password-file",
            "p",
        ],
        // None is legal: it means "prompt".
        vec!["msoffice-crypto", "decrypt", "f.docx"],
    ] {
        assert!(
            cli().try_get_matches_from(&one).is_ok(),
            "{one:?} must parse"
        );
    }
}

#[test]
fn the_password_argument_is_hidden_but_recognised() {
    // Plan §2. It parses -- so S3's `cmd_crypt` can explain *why* it does not exist,
    // rather than clap reporting a generic unexpected argument -- and it never appears
    // in help, so it is never offered.
    let m = cli()
        .try_get_matches_from([
            "msoffice-crypto",
            "decrypt",
            "f.docx",
            "--password",
            "secret",
        ])
        .expect("the trap argument must parse");
    let sub = m.subcommand_matches("decrypt").expect("decrypt");
    assert_eq!(
        sub.get_one::<String>(PASSWORD_TRAP).map(String::as_str),
        Some("secret")
    );
}

#[test]
fn no_help_output_ever_offers_a_password_value_argument() {
    // The predicate is "no line DEFINES the option", not "the string never appears":
    // the after-help text mentions `--password VALUE` precisely to say it does not
    // exist, and a substring check would fail on that prose.
    let mut cmd = cli();
    let mut texts = vec![cmd.render_long_help().to_string()];
    for name in ["classify", "decrypt", "encrypt"] {
        texts.push(
            cmd.find_subcommand_mut(name)
                .expect("subcommand")
                .render_long_help()
                .to_string(),
        );
    }
    for text in texts {
        for line in text.lines() {
            let t = line.trim_start();
            assert!(
                !(t.starts_with("--password ") || t.starts_with("--password=")),
                "a `--password <VALUE>` option must never be defined in help: {line:?}"
            );
        }
    }
}

#[test]
fn help_advertises_the_three_real_password_sources() {
    // The other half of the test above: that one proves the trap is absent, this one
    // proves the replacements are present. Plan § 2 asks the help text to name the
    // sources that do exist, and `exactly_one_password_source_is_accepted` cannot
    // stand in for it — it parses argv, where a `.hide(true)` on one of the three is
    // invisible. Measured: hiding `--password-stdin` fails this test and only this
    // test (17 passed, 1 failed).
    let mut cmd = cli();
    for name in ["decrypt", "encrypt"] {
        let text = cmd
            .find_subcommand_mut(name)
            .expect("subcommand")
            .render_long_help()
            .to_string();
        for flag in ["--password-env", "--password-file", "--password-stdin"] {
            assert!(text.contains(flag), "{name} help must offer {flag}");
        }
    }
}

#[test]
fn the_enum_spellings_are_lower_kebab_and_stable() {
    // The greppable contract. A rename here is a breaking change for every script
    // parsing this output, so it is pinned rather than left to the renderer.
    assert_eq!(container_name(Container::Cfb), "cfb");
    assert_eq!(container_name(Container::Zip), "zip");
    assert_eq!(container_name(Container::Unknown), "unknown");

    assert_eq!(document_name(Document::OoxmlPackage), "ooxml-package");
    assert_eq!(document_name(Document::WordBinary), "word-binary");
    assert_eq!(document_name(Document::ExcelBinary), "excel-binary");
    assert_eq!(
        document_name(Document::PowerPointBinary),
        "powerpoint-binary"
    );
    assert_eq!(document_name(Document::Unknown), "unknown");

    assert_eq!(family_name(Family::Unencrypted), "unencrypted");
    assert_eq!(family_name(Family::Agile), "agile");
    assert_eq!(family_name(Family::Standard), "standard");
    assert_eq!(family_name(Family::Rc4CryptoApi), "rc4-cryptoapi");
    assert_eq!(family_name(Family::Rc4), "rc4");
    assert_eq!(family_name(Family::XorObfuscation), "xor-obfuscation");
    assert_eq!(family_name(Family::Unsupported), "unsupported");
    assert_eq!(family_name(Family::Unknown), "unknown");

    assert_eq!(integrity_name(IntegrityDeclaration::Declared), "declared");
    assert_eq!(
        integrity_name(IntegrityDeclaration::Incomplete),
        "incomplete"
    );
    assert_eq!(integrity_name(IntegrityDeclaration::Absent), "absent");
    assert_eq!(
        integrity_name(IntegrityDeclaration::NotApplicable),
        "not-applicable"
    );
    assert_eq!(integrity_name(IntegrityDeclaration::Unknown), "unknown");

    // Not kebab, deliberately: these are the spellings the spec and the file use.
    assert_eq!(cipher_name(CipherAlgorithm::Aes), "AES");
    assert_eq!(cipher_name(CipherAlgorithm::Rc4), "RC4");
    assert_eq!(hash_name(HashAlgorithm::Sha1), "SHA-1");
    assert_eq!(hash_name(HashAlgorithm::Sha256), "SHA-256");
    assert_eq!(hash_name(HashAlgorithm::Sha384), "SHA-384");
    assert_eq!(hash_name(HashAlgorithm::Sha512), "SHA-512");

    for (p, n) in [
        (IntegrityPolicy::Require, "require"),
        (
            IntegrityPolicy::RequireWhereDefined,
            "require-where-defined",
        ),
        (IntegrityPolicy::VerifyIfPresent, "verify-if-present"),
        (IntegrityPolicy::Skip, "skip"),
    ] {
        assert_eq!(policy_name(p), n);
    }
}

#[test]
fn human_output_answers_for_bytes_that_are_not_an_office_file() {
    // No fixture: `classify` answers every input, so sixteen bytes of junk is a legal
    // `Classification` and the only one this module can obtain (the struct is
    // `#[non_exhaustive]`, so it cannot be built by hand from here).
    let text = classification_human(&classify(b"not an office file"));
    assert_eq!(
        text,
        "container:    unknown\n\
         document:     unknown\n\
         family:       unknown\n\
         encrypted:    no\n\
         supported:    no\n\
         integrity:    unknown\n"
    );
    // A `None` field is omitted entirely, never printed as an empty value or a dash.
    assert!(!text.contains("version:"));
    assert!(!text.contains("key-"));
    assert!(!text.contains("pw-"));
}

#[test]
fn the_parameter_block_prints_six_fields_and_omits_the_absent_ones() {
    let p = params(|p| {
        p.cipher = Some(CipherAlgorithm::Aes);
        p.hash = Some(HashAlgorithm::Sha512);
        p.key_bits = Some(256);
        // block_size and salt_size left None on purpose: they must print nothing.
        p.spin_count = Some(100_000);
    });
    assert_eq!(
        params_lines("key", &p),
        "key-cipher:   AES\n\
         key-hash:     SHA-512\n\
         key-bits:     256\n\
         key-spin:     100000\n"
    );
    // The same six-field loop under the other prefix -- one function, run twice.
    assert_eq!(
        params_lines("pw", &params(|p| p.block_size = Some(16))),
        "pw-block:     16\n"
    );
    // An all-absent block prints nothing at all rather than six empty lines.
    assert_eq!(params_lines("key", &params(|_| {})), "");
}
