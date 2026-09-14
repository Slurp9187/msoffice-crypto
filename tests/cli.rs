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
//! S4 makes `decrypt` real: dispatch on the classification, the `legacy-binary` arm
//! (present in the `cli,legacy-binary` build, exit 9 naming the feature in the plain
//! `cli` build -- both are tested, each behind its own `cfg`), `--integrity`, and the
//! output tail. **No test here ever runs `decrypt` on a path under tests/fixtures/
//! without `-o`**: the derived output name lands beside the input, which would be the
//! corpus, and `every_office_fixture_is_present_by_name` enumerates that directory and
//! fails on the leak. The derived-name tests copy their fixture into a `Scratch` first.
//! S5 makes `encrypt` real: `--format agile|standard` over the two writers, the
//! `Container::Cfb` refusal at exit 5, and the same output tail S4 built. **The rule
//! above applies to `encrypt` too**: no test here runs `encrypt` on a path under
//! `tests/fixtures/` without `-o`, because the derived name would land
//! `plain.encrypted.docx` in the corpus and `every_office_fixture_is_present_by_name`
//! fails on the leak. The derived-name test copies its fixture into a `Scratch` first.
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
const EX_NOT_OFFICE: i32 = 3;
const EX_WRONG_PASSWORD: i32 = 4;
const EX_REFUSED: i32 = 5;
/// Gated because its one use is: the build with a legacy walker reaches the library's
/// own verdict on an undecided `.xls`, and the build without one stops at exit 9 first.
#[cfg(feature = "legacy-binary")]
const EX_MALFORMED: i32 = 6;
const EX_INTEGRITY: i32 = 8;
/// Gated because after S5 every use is in the build WITHOUT a legacy walker: 9 is what
/// a `.doc` gets when this build cannot open it at all, and `encrypt`'s own refusals
/// are 5 and 3, never 9. The `cli,legacy-binary` column reaches the library's verdict
/// instead, so the constant is genuinely unused there.
#[cfg(not(feature = "legacy-binary"))]
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

/// The ten encrypted OOXML fixtures and the `integrity:` word each must print under
/// the default policy. Named, not globbed, so a missing one fails by name.
const ENCRYPTED_OOXML: [(&str, &str); 10] = [
    ("agile_aes128_sha1.docx", "verified"),
    ("agile_aes128_sha384.docx", "verified"),
    ("agile_aes192_sha384.docx", "verified"),
    ("agile_aes256_sha256.docx", "verified"),
    ("agile_aes256_sha384.docx", "verified"),
    ("agile_encrypted.docx", "verified"),
    ("excel16_agile.xlsx", "verified"),
    ("powerpoint16_agile.pptx", "verified"),
    ("standard_encrypted.docx", "not-applicable"),
    ("word16_agile.docx", "verified"),
];

/// `(fixture, SHA-256 of the decrypted container, its length)`, copied from the
/// `GOLDENS` table in tests/legacy_binary_fixtures.rs and pinned to it by
/// `the_legacy_digests_here_are_the_ones_legacy_binary_fixtures_pins`.
///
/// PROVENANCE, and it is not uniform: the `.doc`, the two `.xls` are **msoffcrypto-tool
/// 6.0.0's** digests (`py -3 -m msoffcrypto -p testpass <fixture> out; sha256sum out`)
/// -- the CLI checked against the independent oracle. The `.ppt` digest is **this
/// crate's own** (`PPT_THIS_CRATE_SHA` there): msoffcrypto's rewrite leaves a
/// `cPersist = 0` PowerPoint 16 refuses, so the two outputs differ by one word, and
/// `powerpoint_output_is_msoffcryptos_but_for_the_persist_count` in that file is what
/// ties this crate's digest to the oracle's. Do not describe the .ppt as byte-identical
/// to msoffcrypto-tool anywhere; it is not.
#[cfg(feature = "legacy-binary")]
const LEGACY_GOLDENS: [(&str, &str, usize); 4] = [
    (
        "word97_password.doc",
        "ec66234a7d716b0d0d048f0e736910d884e8dab768f9d1a771b27b14da9d1499",
        29_696,
    ),
    (
        "excel97_password.xls",
        "922ed3e95fd29a3613b42b84861a37b2b2790f2c7386c5abd7ab10ea192e1e99",
        31_744,
    ),
    (
        "powerpoint97_password.ppt",
        "b6cb44712585f0a537afee42bbca050d72bc80058786ba808cc55214a6b1d32d",
        39_936,
    ),
    (
        "excel97_xor.xls",
        "2c97ecdbd8759eb75efd76513ae72498cc5a638b2c9a954537993a5ca8ac7c75",
        25_600,
    ),
];
// Ungated by S5: `encrypt` writes a CFB container (either format) in every `cli`
// column, so this is no longer legacy-binary-only.
const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

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

/// `decrypt INPUT -o <scratch>/OUT --password-file <scratch>/pw.txt EXTRA...`.
fn decrypt_to(s: &Scratch, input: &Path, out_name: &str, extra: &[&str]) -> Output {
    let pw = pw_file(s, "pw.txt", "testpass\n");
    let out_path = s.join(out_name);
    let mut args = vec![
        "decrypt",
        input.to_str().expect("utf-8"),
        "-o",
        out_path.to_str().expect("utf-8"),
        "--password-file",
        pw.to_str().expect("utf-8"),
    ];
    args.extend_from_slice(extra);
    run(&args)
}

/// `encrypt INPUT -o <scratch>/OUT --password-file <scratch>/pw.txt EXTRA...`. A mirror
/// of `decrypt_to`, and it always passes `-o`: without one the derived name lands beside
/// the input, which for a fixture path is the corpus.
fn encrypt_to(s: &Scratch, input: &Path, out_name: &str, extra: &[&str]) -> Output {
    let pw = pw_file(s, "pw.txt", "testpass\n");
    let out_path = s.join(out_name);
    let mut args = vec![
        "encrypt",
        input.to_str().expect("utf-8"),
        "-o",
        out_path.to_str().expect("utf-8"),
        "--password-file",
        pw.to_str().expect("utf-8"),
    ];
    args.extend_from_slice(extra);
    run(&args)
}

/// The one `integrity: ...` line on stderr, or None. Asserts there is never more than one.
fn integrity_line(out: &Output) -> Option<String> {
    let text = stderr(out);
    let lines: Vec<String> = text
        .lines()
        .filter(|l| l.starts_with("integrity: "))
        .map(str::to_string)
        .collect();
    assert!(lines.len() <= 1, "more than one integrity line: {lines:?}");
    lines.first().map(|l| l["integrity: ".len()..].to_string())
}

/// Files in the scratch directory, sorted, so a temp file or an unexpected output is named.
fn entries(s: &Scratch) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(&s.0)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// A fixture, copied into the scratch dir under a new name -- so a decrypt with no
/// `-o` derives its output beside the copy, never beside tests/fixtures/.
fn fixture_copy(s: &Scratch, name: &str, as_name: &str) -> PathBuf {
    let dest = s.join(as_name);
    std::fs::copy(fixture(name), &dest).expect("copy fixture into scratch");
    dest
}

#[cfg(feature = "legacy-binary")]
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// `agile_encrypted.docx` with its `<dataIntegrity .../>` element deleted from the
/// EncryptionInfo XML, written to `s.join("no-tag.docx")`. Port of
/// `agile_fixture_without_data_integrity` in src/lib.rs, over the `cfb` dev-dependency.
///
/// WHERE THE TAMPER IS, AND WHY IT IS NOT THE HEADER OR THE CONTAINER. The two blobs
/// live only on that element, so blanking them is necessarily an edit inside the
/// EncryptionInfo stream. What stays untouched: the 8-byte version/reserved header at
/// the front of that stream (so the file still parses as agile 4.4), the CFB directory
/// and sector chain (the `cfb` crate rewrites the stream in place), and every byte of
/// EncryptedPackage. The negative control is the proof that this is not a parse
/// failure wearing a hat: the same bytes under `--integrity verify-if-present` exit 0
/// with `integrity: not-declared` and a PK package -- a damaged header or container
/// would exit 6 under both policies.
fn agile_without_data_integrity(s: &Scratch) -> PathBuf {
    use std::io::{Read, Seek, SeekFrom, Write};

    let target = s.join("no-tag.docx");
    std::fs::copy(fixture("agile_encrypted.docx"), &target).expect("copy fixture");
    {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&target)
            .expect("open scratch copy");
        let mut container = cfb::CompoundFile::open(&mut f).expect("fixture is a CFB container");

        let mut info = Vec::new();
        container
            .open_stream("/EncryptionInfo")
            .expect("EncryptionInfo stream")
            .read_to_end(&mut info)
            .expect("read EncryptionInfo");

        let start = info
            .windows(14)
            .position(|w| w == b"<dataIntegrity")
            .expect("the fixture declares a dataIntegrity tag");
        let end = start
            + info[start..]
                .windows(2)
                .position(|w| w == b"/>")
                .expect("the element is self-closing")
            + 2;
        info.drain(start..end);

        let mut stream = container
            .open_stream("/EncryptionInfo")
            .expect("EncryptionInfo stream");
        stream.set_len(0).expect("truncate");
        stream.seek(SeekFrom::Start(0)).expect("seek");
        stream.write_all(&info).expect("write shortened XML");
        stream.flush().expect("flush");
    }
    target
}

/// `agile_encrypted.docx` with one byte of `/EncryptedPackage` XORed with `0x01` at
/// `offset`, written to `s.join("flipped.docx")`. Port of `tamper_agile_fixture` in
/// src/lib.rs. The offset used by callers is `8 + 20_000`: past the 8-byte StreamSize
/// prefix and ~20 KB into the ciphertext body, so the zip local-file header at the
/// front of the plaintext still decrypts cleanly -- which is exactly why a structural
/// sniff is not an integrity check.
fn agile_with_a_flipped_package_byte(s: &Scratch, offset: u64) -> PathBuf {
    use std::io::{Read, Seek, SeekFrom, Write};

    let target = s.join("flipped.docx");
    std::fs::copy(fixture("agile_encrypted.docx"), &target).expect("copy fixture");
    {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&target)
            .expect("open scratch copy");
        let mut container = cfb::CompoundFile::open(&mut f).expect("fixture is a CFB container");
        let mut stream = container
            .open_stream("/EncryptedPackage")
            .expect("fixture has an EncryptedPackage stream");

        stream.seek(SeekFrom::Start(offset)).expect("seek");
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).expect("read one byte");
        byte[0] ^= 0x01;
        stream.seek(SeekFrom::Start(offset)).expect("seek back");
        stream.write_all(&byte).expect("write flipped byte");
        stream.flush().expect("flush");
    }
    target
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
    let s = Scratch::new("env-ok");
    let path = agile();
    let out_path = s.join("out.docx");
    let out = run_with_env(
        &[
            "decrypt",
            &path,
            "--password-env",
            ENV_NAME,
            "-o",
            out_path.to_str().expect("utf-8 path"),
        ],
        ENV_NAME,
        PASSWORD,
    );
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert_eq!(integrity_line(&out).as_deref(), Some("verified"));
    assert!(stderr(&out).contains("wrote "), "{}", stderr(&out));
    assert!(
        stdout(&out).is_empty(),
        "the package goes to the file, not stdout: {}",
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
        "-o",
        s.join("out.docx").to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert_never_echoed(&out, PASSWORD, "password_file_decrypts_the_agile_fixture");
}

#[test]
fn password_stdin_decrypts_the_agile_fixture() {
    let s = Scratch::new("stdin-ok");
    let agile_path = agile();
    // The newline is stripped AND only the first line is used.
    let out = run_with_stdin(
        &[
            "decrypt",
            &agile_path,
            "--password-stdin",
            "-o",
            s.join("out1.docx").to_str().expect("utf-8 path"),
        ],
        "testpass\nignored-second-line\n",
    );
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert_never_echoed(&out, PASSWORD, "password_stdin_decrypts_the_agile_fixture");

    // Sanity variant: no trailing newline at all is still a legal password.
    let out = run_with_stdin(
        &[
            "decrypt",
            &agile_path,
            "--password-stdin",
            "-o",
            s.join("out2.docx").to_str().expect("utf-8 path"),
        ],
        "testpass",
    );
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
        "-o",
        s.join("out.docx").to_str().expect("utf-8 path"),
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
        "-o",
        s.join("out.docx").to_str().expect("utf-8 path"),
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
    let s = Scratch::new("named-control");
    let out = run_with_env(
        &[
            "decrypt",
            &agile_path,
            "--password-env",
            ENV_NAME,
            "-o",
            s.join("out.docx").to_str().expect("utf-8 path"),
        ],
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
        &[
            "decrypt",
            &agile_path,
            "--password-env",
            ENV_NAME,
            "-o",
            s.join("out.docx").to_str().expect("utf-8 path"),
        ],
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
        "-o",
        s.join("out.docx").to_str().expect("utf-8 path"),
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
        "-o",
        s.join("out.docx").to_str().expect("utf-8 path"),
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

// --- S5: encrypt -----------------------------------------------------------

#[test]
fn encrypt_then_decrypt_is_byte_identical_in_both_formats() {
    let s = Scratch::new("enc-roundtrip");
    let plain = fixture("plain.docx");
    let want = std::fs::read(&plain).expect("read plain fixture");
    let mut sealed_bytes = Vec::new();

    for f in ["agile", "standard"] {
        let sealed_name = format!("sealed-{f}.docx");
        let out = encrypt_to(&s, &plain, &sealed_name, &["--format", f]);
        assert_eq!(code(&out), EX_OK, "{f}: stderr: {}", stderr(&out));
        let bytes = std::fs::read(s.join(&sealed_name)).expect("read sealed");
        assert!(bytes.starts_with(&CFB_MAGIC), "{f}: not a CFB container");

        let back_name = format!("back-{f}.docx");
        let out = decrypt_to(&s, &s.join(&sealed_name), &back_name, &[]);
        assert_eq!(code(&out), EX_OK, "{f}: decrypt stderr: {}", stderr(&out));
        assert_eq!(
            std::fs::read(s.join(&back_name)).expect("read decrypted"),
            want,
            "{f}: round trip changed bytes"
        );
        sealed_bytes.push(bytes);
    }
    // Proof the format flag reached a writer at all: two different writers over the
    // same plaintext produce different containers.
    assert_ne!(
        sealed_bytes[0], sealed_bytes[1],
        "the two --format values produced the same container"
    );
}

#[test]
fn each_format_produces_the_family_it_names() {
    let s = Scratch::new("enc-family");
    let plain = fixture("plain.docx");
    for (f, want_family) in [("agile", "agile"), ("standard", "standard")] {
        let out_name = format!("sealed-{f}.docx");
        let out = encrypt_to(&s, &plain, &out_name, &["--format", f]);
        assert_eq!(code(&out), EX_OK, "{f}: stderr: {}", stderr(&out));
        let human = classify_human(&s.join(&out_name));
        assert_eq!(
            code(&human),
            EX_OK,
            "{f}: classify stderr: {}",
            stderr(&human)
        );
        let text = stdout(&human);
        assert_eq!(human_field(&text, "family:").as_deref(), Some(want_family));
        assert_eq!(human_field(&text, "container:").as_deref(), Some("cfb"));
        assert_eq!(
            human_field(&text, "document:").as_deref(),
            Some("ooxml-package")
        );
        assert_eq!(human_field(&text, "encrypted:").as_deref(), Some("yes"));
        assert_eq!(human_field(&text, "supported:").as_deref(), Some("yes"));
    }
}

#[test]
fn each_format_reports_the_integrity_it_actually_carries() {
    let s = Scratch::new("enc-integrity-word");
    let plain = fixture("plain.docx");
    for (f, want) in [("agile", "declared"), ("standard", "not-applicable")] {
        let out_name = format!("sealed-{f}.docx");
        let out = encrypt_to(&s, &plain, &out_name, &["--format", f]);
        assert_eq!(code(&out), EX_OK, "{f}: stderr: {}", stderr(&out));
        assert_eq!(
            integrity_line(&out).as_deref(),
            Some(want),
            "{f}: encrypt's own integrity line"
        );
        let human = classify_human(&s.join(&out_name));
        let text = stdout(&human);
        assert_eq!(
            human_field(&text, "integrity:").as_deref(),
            Some(want),
            "{f}: encrypt's notice and classify must agree -- that equality is the \
             exact lie the absent --integrity flag would otherwise have told"
        );
    }
}

#[test]
fn the_standard_format_says_out_loud_that_it_has_no_integrity_element() {
    let s = Scratch::new("enc-standard-warn");
    let plain = fixture("plain.docx");

    let out = encrypt_to(&s, &plain, "standard.docx", &["--format", "standard"]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("defines no dataIntegrity element"),
        "--format standard must say what it costs: {err}"
    );
    assert!(err.contains("`--format agile` writes one"), "{err}");

    let out = encrypt_to(&s, &plain, "agile.docx", &["--format", "agile"]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert!(
        !stderr(&out).contains("defines no dataIntegrity element"),
        "the agile run warned about an element it wrote: {}",
        stderr(&out)
    );
}

#[test]
fn encrypting_an_already_encrypted_file_exits_five_and_writes_nothing() {
    let s = Scratch::new("enc-already");

    let out = encrypt_to(&s, &fixture("agile_encrypted.docx"), "nope.docx", &[]);
    assert_eq!(code(&out), EX_REFUSED, "stderr: {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("already encrypted"), "{err}");
    assert!(err.contains("agile"), "{err}");
    // The positive half of the pair whose negative half is
    // `an_encrypted_97_2003_document_is_not_offered_a_remedy_this_tool_cannot_carry_out`:
    // here the remedy is real, because `decrypt` of this file works in every cli build
    // and yields a package `encrypt` accepts. Without this the other test could not
    // tell "the clause is chosen per document kind" from "the clause was deleted".
    assert!(err.contains("decrypt it first"), "{err}");
    assert!(!s.join("nope.docx").exists());
    assert_eq!(entries(&s), vec!["pw.txt".to_string()], "no output leaked");

    let out = encrypt_to(&s, &fixture("standard_encrypted.docx"), "nope2.docx", &[]);
    assert_eq!(code(&out), EX_REFUSED, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("standard"), "{}", stderr(&out));
    assert!(!s.join("nope2.docx").exists());
}

#[test]
fn an_encrypted_97_2003_document_is_not_offered_a_remedy_this_tool_cannot_carry_out() {
    // Ungated, and the gap this closes ran along the feature boundary: "decrypt it
    // first" was the remedy for every encrypted CFB, and for a 97-2003 binary document
    // it is carriable in neither cli column. Without `legacy-binary`, `decrypt` of this
    // same file exits 9 ("rebuild with --features cli,legacy-binary"); with it, the
    // decrypt succeeds and yields a rewritten CFB that the very next `encrypt` refuses,
    // because there is no writer for these formats. Either way the advice was a second
    // refusal, so the refusal now says the durable thing instead.
    let s = Scratch::new("enc-already-legacy");
    let out = encrypt_to(&s, &fixture("word97_password.doc"), "nope.doc", &[]);
    assert_eq!(code(&out), EX_REFUSED, "stderr: {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("already encrypted"), "{err}");
    assert!(err.contains("rc4-cryptoapi"), "{err}");
    assert!(
        err.contains("no writer for the 97-2003 binary formats"),
        "{err}"
    );
    assert!(
        !err.contains("decrypt it first"),
        "a remedy no cli build can carry out: {err}"
    );
    assert!(!s.join("nope.doc").exists());
}

#[test]
fn encrypting_a_97_2003_document_exits_five_and_says_there_is_no_writer() {
    // Ungated on purpose: the guard fires before any walker, so the answer is
    // identical in both cli columns and a #[cfg] here would hide a regression in one.
    let s = Scratch::new("enc-cfb-plain");
    let out = encrypt_to(&s, &fixture("word97_plain.doc"), "nope.doc", &[]);
    assert_eq!(code(&out), EX_REFUSED, "stderr: {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("CFB container"), "{err}");
    assert!(err.contains("97-2003"), "{err}");
    assert!(!err.contains("already encrypted"), "{err}");
    assert!(!s.join("nope.doc").exists());
}

#[test]
fn encrypt_refuses_junk_as_not_an_office_file() {
    let s = Scratch::new("enc-junk");
    let junk = s.join("junk.bin");
    std::fs::write(&junk, b"sixteen bytes!!!").expect("write junk");

    let out = encrypt_to(&s, &junk, "nope.docx", &[]);
    assert_eq!(code(&out), EX_NOT_OFFICE, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("container: unknown"),
        "{}",
        stderr(&out)
    );
    assert!(!s.join("nope.docx").exists());

    // The control that makes 3 mean something: decrypt of the same bytes is also 3,
    // and encrypt of a real plain.docx succeeds.
    let out = decrypt_to(&s, &junk, "nope2.docx", &[]);
    assert_eq!(code(&out), EX_NOT_OFFICE, "stderr: {}", stderr(&out));
    let out = encrypt_to(&s, &fixture("plain.docx"), "ok.docx", &[]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
}

#[test]
fn encrypt_classifies_before_it_reads_a_password() {
    let s = Scratch::new("enc-order");
    let missing_pw = s.join("missing.txt");

    // (a) A refused file (a bare CFB) must be refused before its password source is
    // touched -- exit 5, not the EX_IO a missing password file would give.
    let out = run(&[
        "encrypt",
        fixture("word97_plain.doc").to_str().expect("utf-8 path"),
        "--password-file",
        missing_pw.to_str().expect("utf-8 path"),
        "-o",
        s.join("a.doc").to_str().expect("utf-8 path"),
    ]);
    assert_eq!(
        code(&out),
        EX_REFUSED,
        "a refused file must be refused before its password source is touched: {}",
        stderr(&out)
    );

    // (b) A plain package with the SAME missing password file reaches the read: EX_IO.
    let out = run(&[
        "encrypt",
        fixture("plain.docx").to_str().expect("utf-8 path"),
        "--password-file",
        missing_pw.to_str().expect("utf-8 path"),
        "-o",
        s.join("b.docx").to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_IO, "stderr: {}", stderr(&out));

    // (c) Control: a plain package with a VALID password file succeeds.
    let out = encrypt_to(&s, &fixture("plain.docx"), "c.docx", &[]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
}

#[test]
fn the_derived_output_name_for_encrypt_is_beside_the_input() {
    let s = Scratch::new("enc-derived");
    // Never a path under tests/fixtures/: the derived name would land in the corpus.
    let report = fixture_copy(&s, "plain.docx", "report.docx");
    let pw = pw_file(&s, "pw.txt", "testpass\n");
    let out = run(&[
        "encrypt",
        report.to_str().expect("utf-8 path"),
        "--password-file",
        pw.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    let derived = s.join("report.encrypted.docx");
    assert!(derived.exists(), "expected {} to exist", derived.display());
    assert!(std::fs::read(&derived)
        .expect("read")
        .starts_with(&CFB_MAGIC));
    let err = stderr(&out);
    assert!(err.contains("wrote "), "{err}");
    assert!(err.contains("report.encrypted.docx"), "{err}");
    assert_eq!(
        entries(&s),
        vec![
            "pw.txt".to_string(),
            "report.docx".to_string(),
            "report.encrypted.docx".to_string(),
        ],
        "no temp file survived"
    );
}

#[test]
fn encrypt_to_stdout_carries_only_the_container() {
    let s = Scratch::new("enc-dash");
    let pw = pw_file(&s, "pw.txt", "testpass\n");
    let out = run(&[
        "encrypt",
        fixture("plain.docx").to_str().expect("utf-8 path"),
        "--password-file",
        pw.to_str().expect("utf-8 path"),
        "-o",
        "-",
    ]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert!(
        out.stdout.starts_with(&CFB_MAGIC),
        "stdout must carry the container and nothing else"
    );
    let err = stderr(&out);
    assert!(err.contains("integrity: declared"), "{err}");
    assert!(!err.contains("wrote "), "{err}");

    // Two encrypt runs are not byte-identical (fresh salts each time), so the proof
    // that the piped bytes are a real container is a round trip, not a byte compare.
    let piped = s.join("piped.docx");
    std::fs::write(&piped, &out.stdout).expect("write piped bytes");
    let back = decrypt_to(&s, &piped, "back.docx", &[]);
    assert_eq!(code(&back), EX_OK, "stderr: {}", stderr(&back));
    assert_eq!(
        std::fs::read(s.join("back.docx")).expect("read"),
        std::fs::read(fixture("plain.docx")).expect("read fixture")
    );
}

#[test]
fn an_existing_encrypt_output_is_never_overwritten_without_force() {
    let s = Scratch::new("enc-force");
    let taken = s.join("taken.docx");
    std::fs::write(&taken, b"PRECIOUS").expect("seed");

    let out = encrypt_to(&s, &fixture("plain.docx"), "taken.docx", &[]);
    assert_eq!(code(&out), EX_USAGE, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("already exists"), "{}", stderr(&out));
    assert!(stderr(&out).contains("--force"), "{}", stderr(&out));
    assert_eq!(
        std::fs::read(&taken).expect("read"),
        b"PRECIOUS",
        "the existing file was overwritten"
    );

    // The negative control: without it, "refuses correctly" cannot be told apart from
    // "always refuses".
    let out = encrypt_to(&s, &fixture("plain.docx"), "taken.docx", &["--force"]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert!(std::fs::read(&taken).expect("read").starts_with(&CFB_MAGIC));
}

#[test]
fn a_successful_encrypt_prints_exactly_one_integrity_line() {
    let s = Scratch::new("enc-integrity-line");
    for f in ["agile", "standard"] {
        let out = encrypt_to(
            &s,
            &fixture("plain.docx"),
            &format!("{f}.docx"),
            &["--format", f],
        );
        assert_eq!(code(&out), EX_OK, "{f}: stderr: {}", stderr(&out));
        // `integrity_line` already asserts internally that there is never more than
        // one such line; this half checks there is not zero either.
        assert!(
            integrity_line(&out).is_some(),
            "{f}: must print an integrity line"
        );
    }
}

#[test]
fn encrypt_accepts_every_password_source_the_way_decrypt_does() {
    let s = Scratch::new("enc-pwsources");
    let plain = fixture("plain.docx");

    let sealed_env = s.join("env.docx");
    let out = run_with_env(
        &[
            "encrypt",
            plain.to_str().expect("utf-8 path"),
            "--password-env",
            ENV_NAME,
            "-o",
            sealed_env.to_str().expect("utf-8 path"),
        ],
        ENV_NAME,
        PASSWORD,
    );
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert_never_echoed(&out, PASSWORD, "encrypt --password-env");

    let pw = pw_file(&s, "pw.txt", "testpass\n");
    let sealed_file = s.join("file.docx");
    let out = run(&[
        "encrypt",
        plain.to_str().expect("utf-8 path"),
        "--password-file",
        pw.to_str().expect("utf-8 path"),
        "-o",
        sealed_file.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert_never_echoed(&out, PASSWORD, "encrypt --password-file");

    let sealed_stdin = s.join("stdin.docx");
    let out = run_with_stdin(
        &[
            "encrypt",
            plain.to_str().expect("utf-8 path"),
            "--password-stdin",
            "-o",
            sealed_stdin.to_str().expect("utf-8 path"),
        ],
        "testpass\n",
    );
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert_never_echoed(&out, PASSWORD, "encrypt --password-stdin");

    // Every artifact round-trips back to plain.docx byte for byte -- the trailing-
    // newline rule (`first_line`) must have applied to the file and stdin sources the
    // same way it does for decrypt, or the password would be "testpass\n".
    let want = std::fs::read(&plain).expect("read plain fixture");
    for (name, sealed) in [
        ("env", &sealed_env),
        ("file", &sealed_file),
        ("stdin", &sealed_stdin),
    ] {
        let back_name = format!("{name}-back.docx");
        let out = decrypt_to(&s, sealed, &back_name, &[]);
        assert_eq!(code(&out), EX_OK, "{name}: stderr: {}", stderr(&out));
        assert_eq!(
            std::fs::read(s.join(&back_name)).expect("read"),
            want,
            "{name}: round trip changed bytes"
        );
    }
}

// --- S4: decrypt ---------------------------------------------------------

#[test]
fn every_encrypted_ooxml_fixture_decrypts_to_a_plain_package() {
    let s = Scratch::new("ooxml-all");
    let mut ran = 0;
    for (name, want) in ENCRYPTED_OOXML {
        let out_name = format!("{name}.out");
        let out = decrypt_to(&s, &fixture(name), &out_name, &[]);
        assert_eq!(code(&out), EX_OK, "{name}: {}", stderr(&out));
        let bytes = std::fs::read(s.join(&out_name)).expect("read output");
        assert!(bytes.starts_with(b"PK\x03\x04"), "{name}: not a PK package");
        let human = classify_human(&s.join(&out_name));
        assert_eq!(code(&human), EX_OK, "{name}");
        let text = stdout(&human);
        assert_eq!(
            human_field(&text, "encrypted:").as_deref(),
            Some("no"),
            "{name}"
        );
        assert_eq!(
            human_field(&text, "container:").as_deref(),
            Some("zip"),
            "{name}"
        );
        assert_eq!(integrity_line(&out).as_deref(), Some(want), "{name}");
        ran += 1;
    }
    assert_eq!(ran, 10);
}

#[cfg(feature = "legacy-binary")]
#[test]
fn legacy_documents_decrypt_to_the_pinned_digests() {
    let s = Scratch::new("legacy-all");
    for (name, sha, len) in LEGACY_GOLDENS {
        let out_name = format!("{name}.out");
        let out = decrypt_to(&s, &fixture(name), &out_name, &[]);
        assert_eq!(code(&out), EX_OK, "{name}: {}", stderr(&out));
        let bytes = std::fs::read(s.join(&out_name)).expect("read output");
        assert_eq!(bytes.len(), len, "{name}");
        assert_eq!(sha256_hex(&bytes), sha, "{name}");
        assert!(bytes.starts_with(&CFB_MAGIC), "{name}: not a CFB container");
        let human = classify_human(&s.join(&out_name));
        let text = stdout(&human);
        assert_eq!(
            human_field(&text, "encrypted:").as_deref(),
            Some("no"),
            "{name}"
        );
        assert_eq!(
            human_field(&text, "container:").as_deref(),
            Some("cfb"),
            "{name}"
        );
        assert_eq!(
            integrity_line(&out).as_deref(),
            Some("not-applicable"),
            "{name}"
        );
    }
}

/// Pins that this file's copy of the four legacy digests agrees with
/// tests/legacy_binary_fixtures.rs's `GOLDENS` table without a shared `tests/common`
/// module. Ungated: it must compile and pass in the plain `cli` build too, where
/// `LEGACY_GOLDENS` above does not exist.
#[test]
fn the_legacy_digests_here_are_the_ones_legacy_binary_fixtures_pins() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/legacy_binary_fixtures.rs"
    ))
    .expect("read tests/legacy_binary_fixtures.rs");
    const DIGESTS: [&str; 4] = [
        "ec66234a7d716b0d0d048f0e736910d884e8dab768f9d1a771b27b14da9d1499",
        "922ed3e95fd29a3613b42b84861a37b2b2790f2c7386c5abd7ab10ea192e1e99",
        "b6cb44712585f0a537afee42bbca050d72bc80058786ba808cc55214a6b1d32d",
        "2c97ecdbd8759eb75efd76513ae72498cc5a638b2c9a954537993a5ca8ac7c75",
    ];
    for d in DIGESTS {
        assert!(
            text.contains(d),
            "digest {d} is not in tests/legacy_binary_fixtures.rs"
        );
    }
    // `DIGESTS` exists only because this test is ungated and `LEGACY_GOLDENS` is not.
    // Without the tie below, the chain would be `DIGESTS` -> the other file, leaving
    // `LEGACY_GOLDENS` -- the array the CLI's output is actually asserted against --
    // free to drift from both while this test stayed green.
    #[cfg(feature = "legacy-binary")]
    {
        let pinned: Vec<&str> = LEGACY_GOLDENS.iter().map(|(_, sha, _)| *sha).collect();
        assert_eq!(
            pinned, DIGESTS,
            "LEGACY_GOLDENS has drifted from the digests this test checks"
        );
    }
}

#[cfg(not(feature = "legacy-binary"))]
#[test]
fn a_binary_document_in_a_build_without_the_feature_exits_unsupported_naming_it() {
    let s = Scratch::new("no-legacy-feature");
    let out = decrypt_to(&s, &fixture("word97_password.doc"), "out.doc", &[]);
    assert_eq!(code(&out), EX_UNSUPPORTED, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("legacy-binary"), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("--features cli,legacy-binary"),
        "{}",
        stderr(&out)
    );
    assert!(!s.join("out.doc").exists());
}

#[test]
fn plain_junk_and_wrong_password_are_three_different_codes() {
    let s = Scratch::new("three-codes");
    let pw = pw_file(&s, "pw.txt", "testpass\n");

    // (a) an unencrypted OOXML package: refused before any password is read.
    let plain_copy = fixture_copy(&s, "plain.docx", "plain.docx");
    let out_a = run(&[
        "decrypt",
        plain_copy.to_str().expect("utf-8 path"),
        "--password-file",
        pw.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out_a), EX_REFUSED, "stderr: {}", stderr(&out_a));
    assert!(
        stderr(&out_a).contains("not encrypted"),
        "{}",
        stderr(&out_a)
    );
    // No password file was opened and no output was derived: the classification
    // refused before either happened.
    assert_eq!(
        entries(&s),
        vec!["plain.docx".to_string(), "pw.txt".to_string()]
    );

    // (b) sixteen bytes of junk.
    let junk = s.join("junk.bin");
    std::fs::write(&junk, b"sixteen bytes!!!").expect("write junk");
    let out_b = run(&[
        "decrypt",
        junk.to_str().expect("utf-8 path"),
        "--password-file",
        pw.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out_b), EX_NOT_OFFICE, "stderr: {}", stderr(&out_b));
    assert!(
        stderr(&out_b).contains("not a Microsoft Office file"),
        "{}",
        stderr(&out_b)
    );

    // (c) the wrong password on a real encrypted file. `-o` into the scratch dir, like
    // every other run here: the input is a committed fixture, and a derived output name
    // would land beside it. The run is expected to fail before the write stage -- so
    // assert that too, rather than leaving "nothing was written" to the check ordering
    // inside `cmd_decrypt` staying as it is today.
    let bad_pw = pw_file(&s, "bad.txt", &format!("{NEVER_PRINT}\n"));
    let out_c_path = s.join("c.docx");
    let out_c = run(&[
        "decrypt",
        &agile(),
        "-o",
        out_c_path.to_str().expect("utf-8 path"),
        "--password-file",
        bad_pw.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(
        code(&out_c),
        EX_WRONG_PASSWORD,
        "stderr: {}",
        stderr(&out_c)
    );
    assert!(!out_c_path.exists());

    // (d) an unencrypted 97-2003 document: the Unencrypted check precedes the
    // feature-gate check, in BOTH builds. `-o` for the same reason as (c).
    let out_d_path = s.join("d.doc");
    let out_d = run(&[
        "decrypt",
        fixture("word97_plain.doc").to_str().expect("utf-8 path"),
        "-o",
        out_d_path.to_str().expect("utf-8 path"),
        "--password-file",
        pw.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out_d), EX_REFUSED, "stderr: {}", stderr(&out_d));
    assert!(!out_d_path.exists());

    assert_ne!(code(&out_a), code(&out_b));
    assert_ne!(code(&out_a), code(&out_c));
    assert_ne!(code(&out_b), code(&out_c));
}

#[test]
fn a_deleted_data_integrity_element_is_refused_by_default_and_reported_under_verify_if_present() {
    let s = Scratch::new("no-tag");
    let f = agile_without_data_integrity(&s);

    // (i) the default policy refuses: this file's tamper-evidence was deleted.
    let out = decrypt_to(&s, &f, "a.docx", &[]);
    assert_eq!(code(&out), EX_INTEGRITY, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("tamper-evidence"), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("--integrity verify-if-present"),
        "{}",
        stderr(&out)
    );
    assert!(!s.join("a.docx").exists());

    // (ii) the SAME bytes, under the opt-out, decrypt as unauthenticated plaintext.
    let out = decrypt_to(&s, &f, "a.docx", &["--integrity", "verify-if-present"]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert_eq!(integrity_line(&out).as_deref(), Some("not-declared"));
    let bytes = std::fs::read(s.join("a.docx")).expect("read");
    assert!(bytes.starts_with(b"PK\x03\x04"));

    // (iii) control: the unmodified fixture under the default policy still verifies --
    // proof that (i) is not a parse failure wearing a hat.
    let out = decrypt_to(&s, &fixture("agile_encrypted.docx"), "control.docx", &[]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert_eq!(integrity_line(&out).as_deref(), Some("verified"));
}

#[test]
fn a_byte_flipped_in_the_ciphertext_body_is_refused_by_default_and_decrypts_under_skip() {
    let s = Scratch::new("flipped");
    let f = agile_with_a_flipped_package_byte(&s, 8 + 20_000);

    let out = decrypt_to(&s, &f, "a.docx", &[]);
    assert_eq!(code(&out), EX_INTEGRITY, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("modified after it was encrypted"),
        "{}",
        stderr(&out)
    );
    assert!(
        !stderr(&out).contains("--integrity"),
        "there is no opt-out for a failed MAC: {}",
        stderr(&out)
    );
    assert!(!s.join("a.docx").exists());

    let out = decrypt_to(&s, &f, "a.docx", &["--integrity", "skip"]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert_eq!(integrity_line(&out).as_deref(), Some("skipped"));
    let bytes = std::fs::read(s.join("a.docx")).expect("read");
    assert!(bytes.starts_with(b"PK\x03\x04"));
}

#[test]
fn require_on_a_2007_standard_file_is_8_and_require_where_defined_opens_it() {
    let s = Scratch::new("standard-require");
    let out = decrypt_to(
        &s,
        &fixture("standard_encrypted.docx"),
        "a.docx",
        &["--integrity", "require"],
    );
    assert_eq!(code(&out), EX_INTEGRITY, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("--integrity require-where-defined"),
        "{}",
        stderr(&out)
    );

    let out = decrypt_to(
        &s,
        &fixture("standard_encrypted.docx"),
        "a.docx",
        &["--integrity", "require-where-defined"],
    );
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert_eq!(integrity_line(&out).as_deref(), Some("not-applicable"));
}

#[test]
fn require_on_a_97_2003_document_is_a_refusal_not_a_silent_not_applicable() {
    let s = Scratch::new("legacy-require");
    let out = decrypt_to(
        &s,
        &fixture("word97_password.doc"),
        "a.doc",
        &["--integrity", "require"],
    );
    assert_eq!(code(&out), EX_INTEGRITY, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("--integrity require-where-defined"),
        "{}",
        stderr(&out)
    );
    assert!(!s.join("a.doc").exists());

    // Control, so 8 is proved to be the policy and not "always fails": the default
    // policy on the SAME file opens it (where the feature exists at all).
    let out = decrypt_to(&s, &fixture("word97_password.doc"), "a.doc", &[]);
    #[cfg(feature = "legacy-binary")]
    {
        assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
        assert_eq!(integrity_line(&out).as_deref(), Some("not-applicable"));
    }
    #[cfg(not(feature = "legacy-binary"))]
    {
        assert_eq!(code(&out), EX_UNSUPPORTED, "stderr: {}", stderr(&out));
    }
}

/// A CFB whose `/Workbook` does not open with BOF: `classify` names the document
/// (`excel-binary`) and refuses to name the family (`Family::Unknown`) -- the case
/// `src/classify_tests.rs`'s `a_workbook_that_does_not_open_with_bof_is_unknown` pins,
/// built here as a file so the CLI can be driven over it.
///
/// Synthetic rather than a fixture: this shape is not in `tests/fixtures/`, and
/// CLAUDE.md's "generate fixtures, don't copy them" applies to hostile inputs first.
fn undecided_workbook(s: &Scratch, name: &str) -> PathBuf {
    let mut stream = Vec::new();
    // MMS then INTERFACEHDR -- neither is BOF, so the walk decides nothing.
    for (id, body) in [(0x00C1u16, &[0u8, 0][..]), (0x00E1u16, &[0xB0, 0x04][..])] {
        stream.extend_from_slice(&id.to_le_bytes());
        stream.extend_from_slice(&(body.len() as u16).to_le_bytes());
        stream.extend_from_slice(body);
    }
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut container = cfb::CompoundFile::create(&mut cursor).expect("create cfb");
        let mut w = container
            .create_stream("/Workbook")
            .expect("create /Workbook");
        w.write_all(&stream).expect("write /Workbook");
        w.flush().expect("flush stream");
        container.flush().expect("flush cfb");
    }
    let p = s.join(name);
    std::fs::write(&p, cursor.into_inner()).expect("write synthetic .xls");
    p
}

/// `--integrity require` refuses a 97-2003 document whose encryption status `classify`
/// could not determine, and says so about the *request* rather than about the file.
///
/// The refusal is deliberate and fail-closed: `Family::Unknown` means the walk was
/// undecided, not that the file is plain, and the library's own walk may still decrypt
/// it -- so waiting for `is_encrypted()` here would be a way to get unauthenticated
/// plaintext out of `--integrity require`. What the message must not do is assert what
/// `classify` refused to assert, or promise that the opt-out will open the file: under
/// `require-where-defined` these same bytes get the decrypter's own answer, which for
/// this input is 6, not 0.
#[test]
fn require_on_an_undecided_97_2003_document_refuses_without_calling_it_encrypted() {
    let s = Scratch::new("legacy-require-unknown");
    let f = undecided_workbook(&s, "undecided.xls");

    // `classify` itself: the document is named, the family is not.
    let c = run(&["classify", f.to_str().expect("utf-8 path")]);
    assert_eq!(code(&c), EX_OK, "stderr: {}", stderr(&c));
    let text = stdout(&c);
    assert_eq!(
        human_field(&text, "document:").as_deref(),
        Some("excel-binary")
    );
    assert_eq!(human_field(&text, "family:").as_deref(), Some("unknown"));
    assert_eq!(human_field(&text, "encrypted:").as_deref(), Some("no"));

    let out = decrypt_to(&s, &f, "a.xls", &["--integrity", "require"]);
    assert_eq!(code(&out), EX_INTEGRITY, "stderr: {}", stderr(&out));
    let err = stderr(&out);
    // The sentence is about the request. It must not claim the file is encrypted, and
    // it must not promise the opt-out opens it -- for these bytes, it does not.
    assert!(err.contains("--integrity require"), "{err}");
    assert!(err.contains("--integrity require-where-defined"), "{err}");
    assert!(!err.contains("encrypted document"), "{err}");
    assert!(!err.contains("opens it"), "{err}");
    assert!(!s.join("a.xls").exists());

    // The negative control, and the proof that 8 came from the policy rather than from
    // the file: the SAME bytes under the opt-out reach the decrypter, which answers for
    // itself -- 6 where it can walk the stream, 9 where this build has no walker at all.
    // Either way it is not 8, and nothing is written.
    let out = decrypt_to(&s, &f, "b.xls", &["--integrity", "require-where-defined"]);
    #[cfg(feature = "legacy-binary")]
    assert_eq!(code(&out), EX_MALFORMED, "stderr: {}", stderr(&out));
    #[cfg(not(feature = "legacy-binary"))]
    assert_eq!(code(&out), EX_UNSUPPORTED, "stderr: {}", stderr(&out));
    assert_ne!(code(&out), EX_INTEGRITY, "stderr: {}", stderr(&out));
    assert!(!s.join("b.xls").exists());
}

#[test]
fn skip_still_prints_the_integrity_line() {
    let s = Scratch::new("skip-prints");
    let out = decrypt_to(
        &s,
        &fixture("agile_encrypted.docx"),
        "a.docx",
        &["--integrity", "skip"],
    );
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert_eq!(integrity_line(&out).as_deref(), Some("skipped"));
}

#[test]
fn output_dash_carries_only_the_package_on_stdout() {
    let s = Scratch::new("dash-stdout");
    let pw = pw_file(&s, "pw.txt", "testpass\n");
    let agile_path = agile();
    let out = run(&[
        "decrypt",
        &agile_path,
        "-o",
        "-",
        "--password-file",
        pw.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert!(out.stdout.starts_with(b"PK\x03\x04"));

    // Byte for byte against the same fixture decrypted to a file.
    let file_out = decrypt_to(&s, Path::new(&agile_path), "same.docx", &[]);
    assert_eq!(code(&file_out), EX_OK, "stderr: {}", stderr(&file_out));
    let file_bytes = std::fs::read(s.join("same.docx")).expect("read");
    assert_eq!(out.stdout, file_bytes);

    assert!(
        stderr(&out).contains("integrity: verified"),
        "{}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains("wrote "), "{}", stderr(&out));
}

#[test]
fn an_existing_output_is_never_overwritten_without_force() {
    let s = Scratch::new("no-clobber");
    let target = s.join("taken.docx");
    std::fs::write(&target, b"PRECIOUS").expect("seed");
    let pw = pw_file(&s, "pw.txt", "testpass\n");
    let agile_path = agile();

    let out = run(&[
        "decrypt",
        &agile_path,
        "-o",
        target.to_str().expect("utf-8 path"),
        "--password-file",
        pw.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_USAGE, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("--force"), "{}", stderr(&out));
    assert_eq!(std::fs::read(&target).expect("read"), b"PRECIOUS");

    let out = run(&[
        "decrypt",
        &agile_path,
        "-o",
        target.to_str().expect("utf-8 path"),
        "--password-file",
        pw.to_str().expect("utf-8 path"),
        "--force",
    ]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    let bytes = std::fs::read(&target).expect("read");
    assert!(bytes.starts_with(b"PK"));
    assert!(
        !entries(&s)
            .iter()
            .any(|e| e.contains("msoffice-crypto.tmp")),
        "temp file left behind: {:?}",
        entries(&s)
    );
}

#[test]
fn the_default_output_name_is_beside_the_input_for_ooxml_and_for_97_2003() {
    let s = Scratch::new("derived-name");
    let pw = pw_file(&s, "pw.txt", "testpass\n");

    let report = fixture_copy(&s, "agile_encrypted.docx", "report.docx");
    let out = run(&[
        "decrypt",
        report.to_str().expect("utf-8 path"),
        "--password-file",
        pw.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    let derived = s.join("report.decrypted.docx");
    assert!(derived.exists(), "expected {} to exist", derived.display());
    assert!(std::fs::read(&derived)
        .expect("read")
        .starts_with(b"PK\x03\x04"));
    assert!(stderr(&out).contains("wrote "), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("report.decrypted.docx"),
        "{}",
        stderr(&out)
    );

    let memo = fixture_copy(&s, "word97_password.doc", "memo.doc");
    let out = run(&[
        "decrypt",
        memo.to_str().expect("utf-8 path"),
        "--password-file",
        pw.to_str().expect("utf-8 path"),
    ]);
    let memo_derived = s.join("memo.decrypted.doc");
    #[cfg(feature = "legacy-binary")]
    {
        assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
        assert!(memo_derived.exists());
        let bytes = std::fs::read(&memo_derived).expect("read");
        assert!(bytes.starts_with(&CFB_MAGIC));
        assert_eq!(
            bytes.len(),
            std::fs::metadata(&memo).expect("metadata").len() as usize
        );
    }
    #[cfg(not(feature = "legacy-binary"))]
    {
        assert_eq!(code(&out), EX_UNSUPPORTED, "stderr: {}", stderr(&out));
        assert!(!memo_derived.exists());
    }

    let mut expected = vec![
        "memo.doc".to_string(),
        "pw.txt".to_string(),
        "report.decrypted.docx".to_string(),
        "report.docx".to_string(),
    ];
    #[cfg(feature = "legacy-binary")]
    expected.push("memo.decrypted.doc".to_string());
    expected.sort();
    assert_eq!(entries(&s), expected, "no temp file, and no other surprise");
}

#[cfg(feature = "legacy-binary")]
#[test]
fn a_wrong_password_on_a_97_2003_document_is_4() {
    let s = Scratch::new("legacy-wrong-pw");
    let pw = pw_file(&s, "pw.txt", &format!("{NEVER_PRINT}\n"));
    let out = run(&[
        "decrypt",
        fixture("word97_password.doc").to_str().expect("utf-8 path"),
        "-o",
        s.join("out.doc").to_str().expect("utf-8 path"),
        "--password-file",
        pw.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code(&out), EX_WRONG_PASSWORD, "stderr: {}", stderr(&out));
    assert!(!s.join("out.doc").exists());
    assert_never_echoed(
        &out,
        NEVER_PRINT,
        "a_wrong_password_on_a_97_2003_document_is_4",
    );
}

#[test]
fn a_successful_decrypt_prints_exactly_one_integrity_line() {
    let s = Scratch::new("one-line");

    let out = decrypt_to(&s, &fixture("agile_encrypted.docx"), "a.docx", &[]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert_eq!(integrity_line(&out).as_deref(), Some("verified"));
    assert_eq!(stderr(&out).matches("integrity: ").count(), 1);

    let out = decrypt_to(&s, &fixture("standard_encrypted.docx"), "b.docx", &[]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert!(integrity_line(&out).is_some());
    assert_eq!(stderr(&out).matches("integrity: ").count(), 1);

    let out = decrypt_to(
        &s,
        &fixture("agile_encrypted.docx"),
        "c.docx",
        &["--integrity", "skip"],
    );
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert!(integrity_line(&out).is_some());
    assert_eq!(stderr(&out).matches("integrity: ").count(), 1);

    let f = agile_without_data_integrity(&s);
    let out = decrypt_to(&s, &f, "d.docx", &["--integrity", "verify-if-present"]);
    assert_eq!(code(&out), EX_OK, "stderr: {}", stderr(&out));
    assert!(integrity_line(&out).is_some());
    assert_eq!(stderr(&out).matches("integrity: ").count(), 1);
}
