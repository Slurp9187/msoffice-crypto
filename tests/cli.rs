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
//! S3 wires password sourcing into `decrypt` over a deliberately minimal `decrypt_ooxml`
//! call: this file proves the password ARRIVED (exit 0, wrong password exit 4) and
//! nothing about output handling, the classification dispatch, the legacy-binary arm or
//! `--integrity`, which are S4's. `encrypt` still reports itself unimplemented after
//! reading its password, which is what `encrypt_reads_the_password_before_it_reports_not_implemented`
//! pins.
#![cfg(feature = "cli")]

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

// Plan §3, mirrored from the binary's own constants (`src/bin/msoffice-crypto.rs`) --
// this file drives the binary as a subprocess, so it cannot `use` them directly.
const EX_OK: i32 = 0;
const EX_USAGE: i32 = 1;
const EX_IO: i32 = 2;
const EX_WRONG_PASSWORD: i32 = 4;
const EX_UNSUPPORTED: i32 = 9;

/// Every fixture in `tests/fixtures/` is sealed with this (CLAUDE.md § Testing Rules).
const PASSWORD: &str = "testpass";
/// A value no correct run may ever echo. Used as a wrong password, as the `--password`
/// trap's argument and inside the non-unicode variable, so one grep covers three paths.
const NEVER_PRINT: &str = "NEVERPRINTME-9f3c";
/// Named in the help and never read implicitly -- the two tests that turn on that.
const ENV_NAME: &str = "MSOFFICE_CRYPTO_PASSWORD";
/// Chosen to be absent; every test that depends on its absence also `env_remove`s it.
const UNSET_ENV_NAME: &str = "MSOFFICE_CRYPTO_DEFINITELY_UNSET_VARIABLE";

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

/// `run`, plus one environment variable, and with `ENV_NAME`/`UNSET_ENV_NAME` explicitly
/// removed first so no ambient value (a developer's shell, `tools/acceptance_gate.py`'s
/// own use of the same name) can make a test pass or fail for a reason outside it.
fn run_with_env(args: &[&str], name: &str, value: impl AsRef<std::ffi::OsStr>) -> Output {
    Command::new(bin())
        .args(args)
        .env_remove(ENV_NAME)
        .env_remove(UNSET_ENV_NAME)
        .env(name, value)
        .stdin(Stdio::null())
        .output()
        .expect("binary runs")
}

/// `run`, with `input` piped to stdin and the pipe closed, so `--password-stdin` sees EOF.
fn run_with_stdin(args: &[&str], input: &str) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write password");
    child.wait_with_output().expect("wait")
}

/// `run`, but a process that has not exited within `secs` is KILLED and the test FAILS.
///
/// This is what turns "does not hang" from an observation into an assertion. `cargo test`
/// has no per-test timeout: a binary that blocks on a prompt nobody can see blocks the
/// whole suite until CI's job timeout, with no failing test name to read. Polling
/// `try_wait` against a deadline converts that into a named failure in half a minute.
///
/// **Only for commands whose output is small.** The loop below polls `try_wait` without
/// draining the piped stdout/stderr, so a child that writes more than the OS pipe buffer
/// (tens of KB) before exiting blocks on its own write, never exits, and is reported as
/// the hang this helper exists to name -- the wrong diagnosis. The one caller today is
/// the no-TTY guard, whose entire output is a two-line usage message, so the condition
/// is unreachable; a second caller that prints a decrypted package or a `--json` dump is
/// what makes it real, and that caller must drain the pipes on threads first rather than
/// reuse this as it stands.
fn run_bounded(args: &[&str], secs: u64) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .env_remove(ENV_NAME)
        .env_remove(UNSET_ENV_NAME)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_) => break,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "{args:?} did not exit within {secs}s: it is waiting on a prompt with \
                     no terminal to type into, which is the hang the no-TTY guard exists \
                     to prevent"
                );
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
    child.wait_with_output().expect("wait")
}

/// Writes a password file with EXACTLY `contents` -- no trailing newline is added, so a
/// test that wants one writes it, and a test that wants a trailing space keeps it.
fn pw_file(s: &Scratch, name: &str, contents: &str) -> PathBuf {
    let p = s.join(name);
    std::fs::write(&p, contents).expect("write password file");
    p
}

/// An `OsString` that is NOT valid Unicode, carrying `NEVER_PRINT` so a leak is greppable.
/// Two definitions rather than one `cfg!` body: a platform that is neither fails to
/// COMPILE, which is louder than a test that quietly disappears.
#[cfg(windows)]
fn invalid_unicode_value() -> OsString {
    use std::os::windows::ffi::OsStringExt;
    let mut w: Vec<u16> = NEVER_PRINT.encode_utf16().collect();
    w.push(0xD800); // an unpaired high surrogate survives Command::env's UTF-16 block
    OsString::from_wide(&w)
}
#[cfg(unix)]
fn invalid_unicode_value() -> OsString {
    use std::os::unix::ffi::OsStringExt;
    let mut b = NEVER_PRINT.as_bytes().to_vec();
    b.push(0xFF); // not valid UTF-8; environ is bytes on unix, so it survives
    OsString::from_vec(b)
}

/// Asserts a run leaked nothing: neither stream may contain `needle`.
fn assert_never_echoed(out: &Output, needle: &str, what: &str) {
    assert!(
        !stdout(out).contains(needle),
        "{what}: the password reached stdout"
    );
    assert!(
        !stderr(out).contains(needle),
        "{what}: the password reached stderr:\n{}",
        stderr(out)
    );
}

/// The fixture every password test decrypts, as a `String` argv needs.
fn agile() -> String {
    fixture("agile_encrypted.docx")
        .to_str()
        .expect("utf-8 path")
        .to_string()
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

// --- S3: password sourcing ---------------------------------------------------

#[test]
fn password_env_decrypts_the_agile_fixture() {
    let path = agile();
    let out = run_with_env(
        &["decrypt", &path, "--password-env", ENV_NAME],
        ENV_NAME,
        PASSWORD,
    );
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("nothing was written"),
        "{}",
        stderr(&out)
    );
    assert!(
        stdout(&out).is_empty(),
        "S3 writes no output yet: {}",
        stdout(&out)
    );
    assert_never_echoed(&out, PASSWORD, "password_env_decrypts_the_agile_fixture");
}

#[test]
fn password_file_decrypts_the_agile_fixture() {
    let s = Scratch::new("pwfile-ok");
    let path = pw_file(&s, "pw.txt", "testpass\n");
    let agile_path = agile();
    let out = run(&[
        "decrypt",
        &agile_path,
        "--password-file",
        path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert_never_echoed(&out, PASSWORD, "password_file_decrypts_the_agile_fixture");
}

#[test]
fn password_stdin_decrypts_the_agile_fixture() {
    let agile_path = agile();
    // The newline is stripped AND only the first line is used.
    let out = run_with_stdin(
        &["decrypt", &agile_path, "--password-stdin"],
        "testpass\nignored-second-line\n",
    );
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert_never_echoed(&out, PASSWORD, "password_stdin_decrypts_the_agile_fixture");

    // Sanity variant: no trailing newline at all is still a legal password.
    let out = run_with_stdin(&["decrypt", &agile_path, "--password-stdin"], "testpass");
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
}

#[test]
fn the_env_value_is_raw_but_the_file_is_first_line() {
    // THE ASYMMETRY, proved with one string. Neither half can pass both ways, and
    // together they are the negative control CLAUDE.md demands: a test where only one
    // direction ever fails cannot distinguish "rule wired" from "always fails".
    let agile_path = agile();

    // Part A: an env value is used RAW, so the trailing newline is part of the password
    // and the real one does not match.
    let out = run_with_env(
        &["decrypt", &agile_path, "--password-env", ENV_NAME],
        ENV_NAME,
        "testpass\n",
    );
    assert_eq!(
        code(&out),
        EX_WRONG_PASSWORD,
        "an env value must be used raw: {}",
        stderr(&out)
    );

    // Part B: the SAME "testpass\n" written to a password file must decrypt, because the
    // file path strips exactly one trailing newline.
    let s = Scratch::new("asymmetry");
    let path = pw_file(&s, "pw.txt", "testpass\n");
    let out = run(&[
        "decrypt",
        &agile_path,
        "--password-file",
        path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(
        code(&out),
        EX_OK,
        "a password file must strip its trailing newline: {}",
        stderr(&out)
    );
}

#[test]
fn a_trailing_space_in_a_password_file_survives_but_a_newline_does_not() {
    let agile_path = agile();

    // Part A: a trailing SPACE is part of the password, and the fixture's is not.
    let s = Scratch::new("trailing-space");
    let path = pw_file(&s, "pw.txt", "testpass \n");
    let out = run(&[
        "decrypt",
        &agile_path,
        "--password-file",
        path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(
        code(&out),
        EX_WRONG_PASSWORD,
        "a trailing space must survive: {}",
        stderr(&out)
    );

    // Part B: exactly one CR-LF is stripped.
    let path = pw_file(&s, "pw2.txt", "testpass\r\n");
    let out = run(&[
        "decrypt",
        &agile_path,
        "--password-file",
        path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(
        code(&out),
        EX_OK,
        "one trailing CR-LF must be stripped: {}",
        stderr(&out)
    );
}

#[test]
fn two_password_sources_is_a_usage_error_naming_both() {
    let agile_path = agile();
    let env_args: &[&str] = &["--password-env", "PW"];
    let file_args: &[&str] = &["--password-file", "p"];
    let stdin_args: &[&str] = &["--password-stdin"];

    let pairs: [(&[&str], &[&str], &str, &str); 3] = [
        (env_args, file_args, "--password-env", "--password-file"),
        (env_args, stdin_args, "--password-env", "--password-stdin"),
        (file_args, stdin_args, "--password-file", "--password-stdin"),
    ];

    for (a, b, name_a, name_b) in pairs {
        let mut args: Vec<&str> = vec!["decrypt", &agile_path];
        args.extend_from_slice(a);
        args.extend_from_slice(b);
        let out = run(&args);
        assert_eq!(
            code(&out),
            EX_USAGE,
            "{name_a} + {name_b} must be rejected: {}",
            stderr(&out)
        );
        assert!(
            stderr(&out).contains(name_a) && stderr(&out).contains(name_b),
            "usage error must name both {name_a} and {name_b}: {}",
            stderr(&out)
        );
    }
}

#[test]
fn no_password_source_without_a_tty_fails_rather_than_hanging() {
    let agile_path = agile();
    // THE NO-HANG PROPERTY IS ENFORCED, NOT OBSERVED: run_bounded kills the child and
    // fails the test by name if it has not exited within 30s.
    let out = run_bounded(&["decrypt", &agile_path], 30);
    assert_eq!(code(&out), EX_USAGE, "stderr: {}", stderr(&out));
    for flag in ["--password-env", "--password-file", "--password-stdin"] {
        assert!(
            stderr(&out).contains(flag),
            "no-source usage error must name {flag}: {}",
            stderr(&out)
        );
    }
}

#[test]
fn there_is_no_password_value_flag_and_the_reason_is_the_message() {
    let agile_path = agile();
    for sub in ["decrypt", "encrypt"] {
        let out = run(&[sub, &agile_path, "--password", NEVER_PRINT]);
        assert_eq!(code(&out), EX_USAGE, "{sub}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("world-readable"),
            "{sub}: {}",
            stderr(&out)
        );
        assert!(
            !stderr(&out).contains("unexpected argument"),
            "{sub}: the trap must be answered with a reason, not clap's generic message: {}",
            stderr(&out)
        );
        assert_never_echoed(
            &out,
            NEVER_PRINT,
            "there_is_no_password_value_flag_and_the_reason_is_the_message",
        );
    }
}

#[test]
fn the_named_environment_variable_is_never_read_unless_it_is_named() {
    let agile_path = agile();

    // No source flag at all: the variable being SET must not make it apply implicitly.
    // stdin is null, so a Prompt fallback would fail the no-TTY guard rather than hang;
    // either way this must not be EX_OK.
    let out = run_with_env(&["decrypt", &agile_path], ENV_NAME, PASSWORD);
    assert_eq!(
        code(&out),
        EX_USAGE,
        "an unnamed variable must not be read implicitly: {}",
        stderr(&out)
    );
    for flag in ["--password-env", "--password-file", "--password-stdin"] {
        assert!(stderr(&out).contains(flag), "{}", stderr(&out));
    }
    assert_never_echoed(
        &out,
        PASSWORD,
        "the_named_environment_variable_is_never_read_unless_it_is_named (implicit)",
    );

    // Positive control: the SAME variable, WITH --password-env naming it, must decrypt.
    // This is what proves the first half measures "not implicit" rather than "broken".
    let out = run_with_env(
        &["decrypt", &agile_path, "--password-env", ENV_NAME],
        ENV_NAME,
        PASSWORD,
    );
    assert_eq!(code(&out), EX_OK, "named: {}", stderr(&out));
}

#[test]
fn a_missing_password_file_is_an_io_error() {
    let s = Scratch::new("missing-pwfile");
    let agile_path = agile();
    let out = run(&[
        "decrypt",
        &agile_path,
        "--password-file",
        s.join("nope.txt").to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_IO, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("cannot read"), "{}", stderr(&out));
}

#[test]
fn an_unset_password_env_var_is_a_usage_error() {
    let agile_path = agile();
    let out = Command::new(bin())
        .args(["decrypt", &agile_path, "--password-env", UNSET_ENV_NAME])
        .env_remove(UNSET_ENV_NAME)
        .stdin(Stdio::null())
        .output()
        .expect("binary runs");
    assert_eq!(code(&out), EX_USAGE, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains(UNSET_ENV_NAME), "{}", stderr(&out));
    assert!(stderr(&out).contains("is not set"), "{}", stderr(&out));
}

#[test]
fn a_non_unicode_password_variable_never_reaches_stderr() {
    // THE CLAUDE.md CRYPTOGRAPHIC-RULES TEST: `VarError::NotUnicode`'s `Display` embeds
    // the OsString. A `map_err(|e| ...)` with `{e}` in `read_password`'s Env arm would put
    // the password on stderr; this is the one test in the repository that would catch it.
    let agile_path = agile();
    let out = run_with_env(
        &["decrypt", &agile_path, "--password-env", ENV_NAME],
        ENV_NAME,
        invalid_unicode_value(),
    );
    assert_eq!(code(&out), EX_USAGE, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains(ENV_NAME), "{}", stderr(&out));
    assert_never_echoed(
        &out,
        NEVER_PRINT,
        "a_non_unicode_password_variable_never_reaches_stderr",
    );
}

#[test]
fn no_failure_path_echoes_the_password() {
    let agile_path = agile();

    // env, wrong password.
    let out = run_with_env(
        &["decrypt", &agile_path, "--password-env", ENV_NAME],
        ENV_NAME,
        NEVER_PRINT,
    );
    assert_eq!(code(&out), EX_WRONG_PASSWORD, "env: {}", stderr(&out));
    assert_never_echoed(
        &out,
        NEVER_PRINT,
        "no_failure_path_echoes_the_password (env)",
    );

    // file, wrong password.
    let s = Scratch::new("no-echo");
    let path = pw_file(&s, "pw.txt", &format!("{NEVER_PRINT}\n"));
    let out = run(&[
        "decrypt",
        &agile_path,
        "--password-file",
        path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_WRONG_PASSWORD, "file: {}", stderr(&out));
    assert_never_echoed(
        &out,
        NEVER_PRINT,
        "no_failure_path_echoes_the_password (file)",
    );

    // stdin, wrong password.
    let out = run_with_stdin(&["decrypt", &agile_path, "--password-stdin"], NEVER_PRINT);
    assert_eq!(code(&out), EX_WRONG_PASSWORD, "stdin: {}", stderr(&out));
    assert_never_echoed(
        &out,
        NEVER_PRINT,
        "no_failure_path_echoes_the_password (stdin)",
    );

    // Success control: even the real password never appears on stderr.
    let out = run_with_env(
        &["decrypt", &agile_path, "--password-env", ENV_NAME],
        ENV_NAME,
        PASSWORD,
    );
    assert_eq!(code(&out), EX_OK, "control: {}", stderr(&out));
    assert!(
        !stderr(&out).contains(PASSWORD),
        "the real password must not appear on stderr either: {}",
        stderr(&out)
    );
}

#[test]
fn help_never_defines_a_password_value_option_but_the_prose_denies_it() {
    for args in [
        vec!["--help"],
        vec!["classify", "--help"],
        vec!["decrypt", "--help"],
        vec!["encrypt", "--help"],
    ] {
        let out = run(&args);
        let text = stdout(&out);
        for line in text.lines() {
            let t = line.trim_start();
            assert!(
                !(t.starts_with("--password ") || t.starts_with("--password=")),
                "{args:?}: a `--password <VALUE>` option must never be defined: {line:?}"
            );
        }
    }
    for sub in ["decrypt", "encrypt"] {
        let out = run(&[sub, "--help"]);
        let text = stdout(&out);
        assert!(
            text.contains("`--password"),
            "{sub} --help must deny `--password` by name"
        );
        assert!(text.contains("world-readable"), "{sub} --help: {text}");
    }
}

/// An empty password source is a usage error, not a wrong password.
///
/// Found by a CodeQL alert on `first_line`'s `unwrap_or("")`, which was a false positive as
/// filed — the empty string is a parser fallback, not a hard-coded credential — but it pointed
/// at a real conflation. Before this, an empty `--password-file` reached the library as `""`
/// and returned `Error::WrongPassword`, exit 4, telling the user to re-check the one thing
/// that was not broken while a secret manager had quietly handed them nothing.
///
/// The negative control is the second half: the same file with content still decrypts, so the
/// test cannot pass by refusing everything.
#[test]
fn an_empty_password_source_is_a_usage_error_not_a_wrong_password() {
    let s = Scratch::new("empty-pw");
    let agile_path = agile();

    let empty = pw_file(&s, "empty.txt", "");
    let out = run(&[
        "decrypt",
        &agile_path,
        "--password-file",
        empty.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_USAGE, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("empty password"),
        "the message must name the fault, not blame the password: {}",
        stderr(&out)
    );
    assert_ne!(
        code(&out),
        EX_WRONG_PASSWORD,
        "an empty source must not be reported as a wrong password"
    );

    // Negative control: the same flag with a real password still works.
    let good = pw_file(&s, "good.txt", "testpass\n");
    let out = run(&[
        "decrypt",
        &agile_path,
        "--password-file",
        good.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
}

/// Deliberately overlapping with `password_file_decrypts_the_agile_fixture`, which covers
/// the same chain in the space-separated form. What this adds is the `--flag=value` argv
/// shape through the real binary; `the_equals_form_parses` in the binary's own test module
/// pins that shape at the clap level, but not end to end.
///
/// Review called it decoration and that is wrong, so the reasoning is recorded here rather
/// than rediscovered: this asserts a successful decrypt, so deleting `first_line` leaves the
/// password as `"testpass\n"` and the exit becomes 4, and deleting the `PasswordSource::File`
/// arm or the flag itself fails it outright. It is redundant, not vacuous — the redundancy is
/// the point, because the hand-rolled parser this crate rejected shipped exactly this bug
/// (plan § 1.2), and a regression would reappear in the argv shape rather than in the logic.
#[test]
fn the_equals_form_carries_a_password_file_end_to_end() {
    let s = Scratch::new("equals-form");
    let path = pw_file(&s, "pw.txt", "testpass\n");
    let agile_path = agile();
    let out = run(&[
        "decrypt",
        &agile_path,
        &format!("--password-file={}", path.display()),
    ]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
}

#[test]
fn a_near_miss_password_flag_is_given_a_suggestion() {
    let agile_path = agile();
    let out = run(&["decrypt", "--password-en", "X", &agile_path]);
    assert_eq!(code(&out), EX_USAGE, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("--password-env"), "{}", stderr(&out));
}

#[test]
fn encrypt_reads_the_password_before_it_reports_not_implemented() {
    let plain = fixture("plain.docx");
    let plain = plain.to_str().expect("utf-8 path");
    let s = Scratch::new("encrypt-password");

    // A password source that fails to read must surface as EX_IO, not the S1 stub's
    // EX_UNSUPPORTED -- which is the only way to tell "encrypt shares the password
    // wiring" from "encrypt is still the untouched stub".
    let out = run(&[
        "encrypt",
        plain,
        "--password-file",
        s.join("nope.txt").to_str().expect("utf-8 path"),
    ]);
    assert_eq!(
        code(&out),
        EX_IO,
        "encrypt must read its password before dispatching: {}",
        stderr(&out)
    );

    // Control: a VALID password file reaches the not-implemented notice, naming S5.
    let path = pw_file(&s, "pw.txt", "anything\n");
    let out = run(&[
        "encrypt",
        plain,
        "--password-file",
        path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_UNSUPPORTED, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("S5"), "{}", stderr(&out));
}

/// The other half of the test above: it proves the ordering, this proves the notice
/// printed at the end of that ordering is still true.
///
/// This slice is what made the question live. Before it, `encrypt` reached
/// `not_implemented_yet` having done nothing, and "nothing was read and nothing was
/// written" was accurate. Wiring the password read ahead of the stub made the first half
/// of that sentence false without touching the string, and no assertion anywhere would
/// have caught it: the test above asserts only the exit code and `S5`.
///
/// The password file below is opened and read by this process before the notice prints,
/// so a notice claiming nothing was read is a lie to a user deciding whether their
/// secret ever left the disk.
#[test]
fn the_not_implemented_notice_does_not_claim_nothing_was_read() {
    let plain = fixture("plain.docx");
    let plain = plain.to_str().expect("utf-8 path");
    let s = Scratch::new("encrypt-notice");
    let path = pw_file(&s, "pw.txt", "anything\n");

    let out = run(&[
        "encrypt",
        plain,
        "--password-file",
        path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_UNSUPPORTED, "stderr: {}", stderr(&out));
    let err = stderr(&out);
    assert!(
        !err.contains("nothing was read"),
        "the password file and the input file were both read before this printed, so the \
         notice must not claim otherwise: {err}"
    );
    // The half that is still true stays asserted, so the fix cannot be "delete the
    // sentence": the user must still be told no file was produced.
    assert!(
        err.contains("nothing was written"),
        "the notice must still say no output was produced: {err}"
    );
}
