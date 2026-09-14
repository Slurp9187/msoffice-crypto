//! End-to-end tests for the `msoffice-crypto` binary's `classify` subcommand
//! (plan slice S2) — argument handling, exit codes and the `--json` output, driven as a
//! subprocess.
//!
//! **Outside the `include` allowlist, so it reads all eighteen Office fixtures directly**
//! (`Cargo.toml`'s `include` ships only two of nineteen); a missing one fails loudly by
//! name rather than being skipped, per CLAUDE.md's "fixtures are not optional" rule.
//! Nothing here carries a `fixture_corpus` gate: that gate exists so the *published*
//! crate's `cargo test` reports a missing corpus as "ignored, with a reason" rather than
//! failing outright, and this file never reaches the tarball at all, so the concern does
//! not apply — CLAUDE.md's Layout entry for this file says exactly that, and the pinned
//! `#[cfg_attr(not(fixture_corpus), ignore)]` count of 30 stays untouched by anything
//! below.
//!
//! `decrypt` and `encrypt` are still S1 stubs at this slice (S4/S5), so nothing here
//! drives them; that coverage lands with those slices.
#![cfg(feature = "cli")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

// Plan §3, mirrored from the binary's own constants (`src/bin/msoffice-crypto.rs`) --
// this file drives the binary as a subprocess, so it cannot `use` them directly.
const EX_OK: i32 = 0;
const EX_USAGE: i32 = 1;
const EX_IO: i32 = 2;

/// The eighteen Office fixtures `tests/fixtures/` is supposed to hold, named explicitly
/// so a single missing one fails **by name** rather than only moving a count. The
/// nineteenth entry in that directory, `plain_content.txt`, is not an Office file and is
/// not listed here.
const OFFICE_FIXTURE_NAMES: [&str; 18] = [
    "agile_aes128_sha1.docx",
    "agile_aes128_sha384.docx",
    "agile_aes192_sha384.docx",
    "agile_aes256_sha256.docx",
    "agile_aes256_sha384.docx",
    "agile_encrypted.docx",
    "excel16_agile.xlsx",
    "excel97_password.xls",
    "excel97_plain.xls",
    "excel97_xor.xls",
    "plain.docx",
    "powerpoint16_agile.pptx",
    "powerpoint97_password.ppt",
    "powerpoint97_plain.ppt",
    "standard_encrypted.docx",
    "word16_agile.docx",
    "word97_password.doc",
    "word97_plain.doc",
];

const OFFICE_FIXTURE_COUNT: usize = OFFICE_FIXTURE_NAMES.len();

/// Human column key -> the `--json` pointer ([RFC 6901]) it must agree with. Nineteen
/// rows, matching `classification_human`'s field table exactly (CONTRACT §4.1) --
/// differing from it in exactly one spelling: `integrity:` on the human side is
/// `/data_integrity` in JSON, because JSON keys are `Classification`'s own field names
/// and the human key is a column heading free to read shorter.
///
/// [RFC 6901]: https://www.rfc-editor.org/rfc/rfc6901
const FIELD_MAP: [(&str, &str); 19] = [
    ("container:", "/container"),
    ("document:", "/document"),
    ("version:", "/version"),
    ("family:", "/family"),
    ("encrypted:", "/encrypted"),
    ("supported:", "/supported"),
    ("integrity:", "/data_integrity"),
    ("key-cipher:", "/key_data/cipher"),
    ("key-hash:", "/key_data/hash"),
    ("key-bits:", "/key_data/key_bits"),
    ("key-block:", "/key_data/block_size"),
    ("key-salt:", "/key_data/salt_size"),
    ("key-spin:", "/key_data/spin_count"),
    ("pw-cipher:", "/password_key/cipher"),
    ("pw-hash:", "/password_key/hash"),
    ("pw-bits:", "/password_key/key_bits"),
    ("pw-block:", "/password_key/block_size"),
    ("pw-salt:", "/password_key/salt_size"),
    ("pw-spin:", "/password_key/spin_count"),
];

/// The nine top-level `--json` keys, alphabetised -- `serde_json::Map` is a `BTreeMap`
/// with no `preserve_order`, so this is the order they actually serialise in, and no
/// test may assume any other.
const TOP_LEVEL_KEYS: [&str; 9] = [
    "container",
    "data_integrity",
    "document",
    "encrypted",
    "family",
    "key_data",
    "password_key",
    "supported",
    "version",
];

/// The six keys every non-null parameter block carries, alphabetised.
const PARAM_KEYS: [&str; 6] = [
    "block_size",
    "cipher",
    "hash",
    "key_bits",
    "salt_size",
    "spin_count",
];

/// `CARGO_BIN_EXE_<name>` is set by Cargo for every binary target when building an
/// integration test, so this needs no path guessing and no `cargo run`.
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_msoffice-crypto")
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// A fixture by name, asserted present. Fails **by name**, never skips -- CLAUDE.md's
/// "fixtures are not optional" rule, and the whole reason this file discovers the corpus
/// at run time instead of trusting a count.
fn fixture(name: &str) -> PathBuf {
    let p = fixtures().join(name);
    assert!(
        p.is_file(),
        "fixture {name} is missing from {}; fixtures are not optional",
        fixtures().display()
    );
    p
}

/// The Office fixtures, discovered at run time by extension rather than hardcoded as a
/// list of paths, sorted for a stable iteration order. Asserts `len() == 18` **inside
/// the helper**, so every caller inherits the anti-empty-glob guard rather than each
/// writing its own count check that could drift from another's.
fn office_fixtures() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(fixtures())
        .expect("fixtures dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("docx" | "xlsx" | "pptx" | "doc" | "xls" | "ppt")
            )
        })
        .collect();
    v.sort();
    assert_eq!(
        v.len(),
        OFFICE_FIXTURE_COUNT,
        "expected {OFFICE_FIXTURE_COUNT} Office fixtures, found {}: {v:?}",
        v.len()
    );
    v
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("binary runs")
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("process exited normally")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn classify_human(path: &Path) -> Output {
    run(&["classify", path.to_str().expect("utf-8 path")])
}

fn classify_json(path: &Path) -> Output {
    run(&["classify", "--json", path.to_str().expect("utf-8 path")])
}

/// Reads one field out of the human `classify` form: `{key:<14}{value}\n`. Returns
/// `None` when no line starts with `key` -- an absent field, which the human renderer
/// omits entirely rather than printing as a dash.
fn human_field(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find(|l| l.starts_with(key))
        .map(|l| l[key.len()..].trim_start().to_string())
}

/// What the human form would have printed for one JSON scalar -- `null` maps to `None`
/// (an omitted line), a bool to `yes`/`no`, a string to itself, and a number to its
/// decimal text. Panics on anything else, because every field `FIELD_MAP` names is one
/// of these four JSON kinds by construction; a `version` emitted as `[4, 4]` instead of
/// `"4.4"` would panic here rather than compare unequal, which is a sharper failure for
/// exactly the mistake it is guarding against.
fn as_human_text(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::Bool(b) => Some(if *b { "yes" } else { "no" }.to_string()),
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        other => panic!("a classification field must be a scalar, got {other}"),
    }
}

/// A scratch directory that removes itself, so a failing test does not leave junk files
/// in the repo. No `tempfile` dev-dependency for the one test that needs a file this
/// crate did not ship (`tests/fixtures/` holds only real Office bytes).
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let mut d = std::env::temp_dir();
        d.push(format!("msoffice-crypto-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch dir");
        Scratch(d)
    }
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// --- C1: the corpus itself --------------------------------------------------

#[test]
fn every_office_fixture_is_present_by_name() {
    for name in OFFICE_FIXTURE_NAMES {
        fixture(name);
    }
    // And the directory holds *nothing else*: the eighteen above plus the one non-Office
    // entry, `plain_content.txt`. Deliberately not `office_fixtures().len() ==
    // OFFICE_FIXTURE_COUNT` -- that helper asserts its own length internally, so such a
    // line could never be the assertion that fires. This one enumerates the whole
    // directory, which nothing else here does, so it is the check that catches a
    // nineteenth *document* arriving under an extension office_fixtures()'s filter does
    // not match (`.docm`, `.xlsb`, `.pps`): invisible to the glob, invisible to the loop
    // above, and silently untested by every other test in this file.
    let mut entries: Vec<String> = std::fs::read_dir(fixtures())
        .expect("fixtures dir")
        .map(|e| e.expect("fixtures dir entry").file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .collect();
    entries.sort();
    let mut expected: Vec<String> = OFFICE_FIXTURE_NAMES.iter().map(|s| s.to_string()).collect();
    expected.push("plain_content.txt".to_string());
    expected.sort();
    assert_eq!(
        entries, expected,
        "tests/fixtures/ holds something other than the eighteen Office fixtures and \
         plain_content.txt"
    );
}

// --- C2/C3: carried forward from S1 -----------------------------------------

#[test]
fn classify_names_the_agile_family_and_its_declared_integrity() {
    let out = classify_human(&fixture("agile_encrypted.docx"));
    assert_eq!(code(&out), EX_OK);
    let s = stdout(&out);
    assert_eq!(human_field(&s, "family:").as_deref(), Some("agile"));
    assert_eq!(human_field(&s, "integrity:").as_deref(), Some("declared"));
}

#[test]
fn classify_reports_a_plain_package_as_an_answer_not_a_failure() {
    let out = classify_human(&fixture("plain.docx"));
    assert_eq!(
        code(&out),
        EX_OK,
        "an unencrypted package is an answer, not a failure"
    );
    assert_eq!(
        human_field(&stdout(&out), "encrypted:").as_deref(),
        Some("no")
    );
}

// --- C4/C5: shape of the JSON, across the whole corpus ----------------------

#[test]
fn json_is_exactly_one_object_for_every_fixture() {
    for f in office_fixtures() {
        let out = classify_json(&f);
        assert_eq!(code(&out), EX_OK, "{}", f.display());
        let s = stdout(&out);
        let v: Value = serde_json::from_str(&s)
            .unwrap_or_else(|e| panic!("{}: not one JSON object: {e}\n{s}", f.display()));
        assert!(
            v.is_object(),
            "{}: top level must be an object",
            f.display()
        );
    }
}

#[test]
fn the_json_key_set_is_invariant_across_every_fixture() {
    for f in office_fixtures() {
        let v: Value = serde_json::from_str(&stdout(&classify_json(&f))).expect("valid JSON");
        let o = v.as_object().expect("object");
        let mut keys: Vec<&str> = o.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, TOP_LEVEL_KEYS, "{}", f.display());

        for block in ["key_data", "password_key"] {
            if let Some(p) = o[block].as_object() {
                let mut pkeys: Vec<&str> = p.keys().map(String::as_str).collect();
                pkeys.sort_unstable();
                assert_eq!(pkeys, PARAM_KEYS, "{}: {block} block", f.display());
            }
            // A `null` block is equally valid (excel97_xor.xls's key_data, every
            // plain fixture's key_data and password_key) -- not every block is an
            // object, and that is by design, not a gap in this test.
        }
    }
}

// --- C6: human and JSON must agree, field by field --------------------------

#[test]
fn json_and_human_agree_field_by_field_for_every_fixture() {
    for f in office_fixtures() {
        let human = stdout(&classify_human(&f));
        let json: Value = serde_json::from_str(&stdout(&classify_json(&f))).expect("valid JSON");
        for (key, ptr) in FIELD_MAP {
            let from_human = human_field(&human, key);
            let from_json = as_human_text(json.pointer(ptr).unwrap_or(&Value::Null));
            assert_eq!(
                from_human,
                from_json,
                "{}: {key} (human) vs {ptr} (json) disagree",
                f.display()
            );
        }
    }
}

// --- C7/C8: the null-block asymmetry, both halves ---------------------------

#[test]
fn an_unencrypted_file_carries_both_parameter_blocks_as_null() {
    let v: Value =
        serde_json::from_str(&stdout(&classify_json(&fixture("plain.docx")))).expect("valid JSON");
    let o = v.as_object().expect("object");
    // `contains_key` and `is_null` are asserted SEPARATELY: `o["key_data"]` on a
    // `serde_json::Map` returns `Value::Null` for a key that is simply ABSENT, so
    // `is_null()` alone proves nothing about whether the key was ever inserted.
    assert!(o.contains_key("key_data"), "key_data key must be present");
    assert!(
        o.contains_key("password_key"),
        "password_key key must be present"
    );
    assert!(o["key_data"].is_null());
    assert!(o["password_key"].is_null());

    // A whole-object comparison against a literal, parsed rather than typed as a raw
    // string -- so no key order is asserted, only the parsed value.
    let expected: Value = serde_json::from_str(
        r#"{"container":"zip","data_integrity":"not-applicable","document":"ooxml-package",
            "encrypted":false,"family":"unencrypted","key_data":null,"password_key":null,
            "supported":false,"version":null}"#,
    )
    .expect("literal parses");
    assert_eq!(v, expected);
}

#[test]
fn a_standard_encrypted_file_nulls_only_the_password_block() {
    // The negative control for the test above: one block null, one an object, in the
    // same file. A `classification_json` that nulled both blocks whenever either was
    // `None` would pass the plain-file test and fail here.
    let v: Value =
        serde_json::from_str(&stdout(&classify_json(&fixture("standard_encrypted.docx"))))
            .expect("valid JSON");
    let o = v.as_object().expect("object");
    assert!(
        o["key_data"].is_object(),
        "standard encryption declares key_data"
    );
    assert!(
        o["password_key"].is_null(),
        "standard encryption has one parameter set, not a separate password encryptor"
    );
}

// --- C9: round-trip, with per-field types --------------------------------

#[test]
fn the_json_round_trips_for_an_encrypted_an_unencrypted_and_a_97_2003_fixture() {
    // agile_encrypted.docx: every field populated, both blocks objects.
    let v: Value = serde_json::from_str(&stdout(&classify_json(&fixture("agile_encrypted.docx"))))
        .expect("valid JSON");
    assert!(v["container"].is_string());
    assert!(v["document"].is_string());
    assert!(
        v["version"].is_string(),
        "version must be a JSON string, not an array or object"
    );
    assert!(v["family"].is_string());
    assert!(v["encrypted"].is_boolean());
    assert!(v["supported"].is_boolean());
    assert!(v["data_integrity"].is_string());
    let key_data = v["key_data"]
        .as_object()
        .expect("agile key_data is an object");
    assert!(
        key_data["key_bits"].is_number(),
        "key_bits must be a JSON number, not a quoted string"
    );
    assert_eq!(key_data["key_bits"], 256);
    assert_eq!(v["version"], "4.4");

    // plain.docx: an unencrypted package, both blocks null.
    let v: Value =
        serde_json::from_str(&stdout(&classify_json(&fixture("plain.docx")))).expect("valid JSON");
    assert_eq!(v["version"], Value::Null);
    assert!(v["key_data"].is_null());

    // word97_password.doc: a 97-2003 binary document, key_data carries only key_bits.
    let v: Value = serde_json::from_str(&stdout(&classify_json(&fixture("word97_password.doc"))))
        .expect("valid JSON");
    // Pinned to the value, not to "one of two JSON kinds": `serde_json::Value`'s `Index`
    // returns a static `Value::Null` for a **missing** map key, so an `is_null()` arm
    // here could not tell a rendered null from a `version` key that was never written at
    // all. `"4.2"` is this fixture's RC4 CryptoAPI EncryptionHeader version pair, and it
    // is the same in the `cli` and `cli,legacy-binary` builds -- classify does not read
    // the legacy feature.
    assert_eq!(v["version"], "4.2");
    let key_data = v["key_data"].as_object().unwrap_or_else(|| {
        panic!(
            "word97_password.doc: key_data must be an object, got {}",
            v["key_data"]
        )
    });
    if !key_data["key_bits"].is_number() {
        panic!(
            "word97_password.doc: key_data.key_bits has the wrong JSON type: {}",
            key_data["key_bits"]
        );
    }
    assert_eq!(key_data["key_bits"], 128);
    assert!(
        key_data["cipher"].is_null(),
        "97-2003 CryptoAPI header exposes only key_bits"
    );
}

// --- C10: exactly one line -----------------------------------------------

#[test]
fn json_is_one_line_with_no_pretty_printing() {
    let out = classify_json(&fixture("plain.docx"));
    let s = stdout(&out);
    // Platform-proof: trims a trailing CR-LF or LF rather than counting newlines, which
    // would differ between a Unix and a Windows build for a reason unrelated to the
    // thing under test.
    let trimmed = s.trim_end_matches(['\r', '\n']);
    assert!(!trimmed.contains('\n'), "expected one line, got:\n{s}");
}

// --- C11: unknown input --------------------------------------------------

#[test]
fn junk_bytes_classify_as_unknown_and_exit_zero_in_both_forms() {
    let s = Scratch::new("junk");
    let f = s.join("junk.bin");
    std::fs::write(&f, b"this is not an office file").expect("write junk");

    let human = classify_human(&f);
    assert_eq!(code(&human), EX_OK);
    assert_eq!(
        human_field(&stdout(&human), "container:").as_deref(),
        Some("unknown")
    );

    let json = classify_json(&f);
    assert_eq!(code(&json), EX_OK);
    let v: Value = serde_json::from_str(&stdout(&json)).expect("valid JSON");
    assert_eq!(v["container"], "unknown");
}

// --- C12: an unreadable file writes no stdout -----------------------------

#[test]
fn an_unreadable_file_exits_io_and_writes_no_stdout() {
    let s = Scratch::new("missing");
    let out = run(&[
        "classify",
        "--json",
        s.join("nope.docx").to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_IO);
    assert!(
        stdout(&out).is_empty(),
        "nothing on stdout: {}",
        stdout(&out)
    );
    assert!(stderr(&out).contains("cannot read"), "{}", stderr(&out));
}

// --- C13: --json is a classify-only flag ----------------------------------

#[test]
fn json_is_a_classify_only_flag() {
    // `--json` is not registered on `decrypt`/`encrypt` at all, so passing it is a clap
    // usage error (1), not a dispatch to the S1 stub (9, `not_implemented_yet`). If
    // `--json` were attached to `crypt_command` instead of `classify` by mistake, this
    // would parse and reach the stub, failing here as `left: 9, right: 1` -- localising
    // the mistake, since `json_is_exactly_one_object_for_every_fixture` (C4) would fail
    // at the same time for the opposite reason.
    for sub in ["decrypt", "encrypt"] {
        let out = run(&[
            sub,
            "--json",
            fixture("plain.docx").to_str().expect("utf-8 path"),
        ]);
        assert_eq!(
            code(&out),
            EX_USAGE,
            "{sub} must not accept --json as a real flag"
        );
    }
}
