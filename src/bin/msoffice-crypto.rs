//! `msoffice-crypto` — classify, decrypt and encrypt Microsoft Office documents from a
//! shell.
//!
//! Plan: `docs/plans/msoffice-crypto-cli-2026-09-11.md`.
//!
//! Passwords never come from `argv`. There is deliberately no `--password VALUE`
//! argument, because `argv` is world-readable in a process listing for the lifetime of
//! the run. `--password` is registered anyway, hidden, purely so that reaching for it
//! produces an explanation rather than "unexpected argument".

#![deny(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};
#[cfg(feature = "legacy-binary")]
use msoffice_crypto::decrypt_binary_office;
use msoffice_crypto::{
    check_encryptable_from, classify_from, decrypt_ooxml_to, encrypt_ooxml_standard_to,
    encrypt_ooxml_to, AlgorithmParams, CipherAlgorithm, Classification, Container, ContainerRead,
    Document, Error, Family, HashAlgorithm, IntegrityDeclaration, IntegrityOutcome,
    IntegrityPolicy,
};
use serde_json::{json, Map, Value};

// Plan §3. A CLI that returns 1 for everything cannot be scripted. 4 against 5 is "try
// again" against "wrong file"; 8 against 4 and 6 is the crate's own rule that "wrong
// password" and "file tampered" are different facts, carried across the process
// boundary where the number is all a script gets; 9 against 5 is "nothing to do"
// against "something this build cannot do", which is usually a flag away.
const EX_OK: u8 = 0;
const EX_USAGE: u8 = 1;
const EX_IO: u8 = 2;
const EX_NOT_OFFICE: u8 = 3;
const EX_WRONG_PASSWORD: u8 = 4;
// Ungated: the CLI's own classification layer produces 5 in every build (route_for),
// and Error::NotEncrypted maps to it only where that variant exists (legacy-binary).
const EX_REFUSED: u8 = 5;
const EX_MALFORMED: u8 = 6;
const EX_INTERNAL: u8 = 7;
const EX_INTEGRITY: u8 = 8;
const EX_UNSUPPORTED: u8 = 9;

const AFTER_HELP: &str = "\
EXIT CODES:
  0 ok        1 usage      2 io          3 not-office
  4 wrong-password         5 refused     6 malformed   7 internal
  8 integrity              9 unsupported

4 and 5 differ on purpose: 4 means try again, 5 means you had the wrong file.
8 is not 4 or 6: the password was right and the file was changed after it was
encrypted, or the policy would not accept it unauthenticated.
9 is not 5: the file needed something this build cannot do, and the message says
which feature to rebuild with.";

const PASSWORD_AFTER_HELP: &str = "\
PASSWORDS:
  argv is world-readable in a process listing, so there is no `--password
  VALUE` argument. Give exactly one source, or none to be prompted without echo.
  --password-env takes the variable's NAME, so MSOFFICE_CRYPTO_PASSWORD is the
  obvious one to name -- and naming it is the only way this tool reads it. A
  password that applies without being asked for is how the wrong file gets
  decrypted in a loop.

EXIT CODES:
  0 ok        1 usage      2 io          3 not-office
  4 wrong-password         5 refused     6 malformed   7 internal
  8 integrity              9 unsupported";

/// Registered but hidden, so `--password secret` is met with the reason it does not
/// exist rather than clap's generic "unexpected argument". Removing it would make the
/// tool *less* clear about a decision the plan calls load-bearing.
const PASSWORD_TRAP: &str = "password";

/// The four [`IntegrityPolicy`] spellings, in the order the enum declares them.
const POLICY_NAMES: [&str; 4] = [
    "require",
    "require-where-defined",
    "verify-if-present",
    "skip",
];

const FORMAT_NAMES: [&str; 2] = ["agile", "standard"];

/// The one sentence for "nothing to do". Printed whether the CLI's classification
/// (`route_for`, every build) or the library's `Error::NotEncrypted` (`describe`,
/// `legacy-binary`) established it: two identical situations, one wording (CONTRACT § 3).
const NOT_ENCRYPTED: &str = "not encrypted; there is nothing to decrypt";

/// The one sentence for "this crate does not recognise the container at all". Shared by
/// `route_for` (`decrypt`, the CLI's own classification) and `describe`'s
/// `Error::UnknownContainer` arm (`encrypt`, established by the library's guard): the same
/// eight — or sixteen — bytes of junk get the same answer from either subcommand, and a
/// hand-duplicated copy that drifted between the two would be a lie one of them told.
const NOT_OFFICE: &str = "not a Microsoft Office file (container: unknown)";

fn password_args() -> [Arg; 4] {
    [
        Arg::new("password-env")
            .long("password-env")
            .value_name("NAME")
            .help("Read the password from this environment variable"),
        Arg::new("password-file")
            .long("password-file")
            .value_name("PATH")
            .help("Read the password from the first line of this file"),
        Arg::new("password-stdin")
            .long("password-stdin")
            .action(ArgAction::SetTrue)
            .help("Read the password as one line from stdin"),
        Arg::new(PASSWORD_TRAP)
            .long("password")
            .value_name("VALUE")
            .hide(true),
    ]
}

fn crypt_command(name: &'static str, about: &'static str, default_suffix: &'static str) -> Command {
    // Leaked rather than formatted into a `String` because clap wants `&'static str`,
    // and the extension is not hard-coded: `derived_output` preserves whatever the input
    // had, which for this crate may be .docx, .xlsx, .pptx, .doc, .xls or .ppt.
    let output_help: &'static str = Box::leak(
        format!("Write here; `-` for stdout. Default: FILE.{default_suffix}.EXT").into_boxed_str(),
    );
    Command::new(name)
        .about(about)
        .arg(
            Arg::new("file")
                .value_name("FILE")
                .required(true)
                .help("The Office file to read"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("PATH")
                .help(output_help),
        )
        .arg(
            Arg::new("force")
                .long("force")
                .action(ArgAction::SetTrue)
                .help("Overwrite an existing output file"),
        )
        .args(password_args())
        // Exactly one password source, so two is an error rather than a silent
        // precedence win. Not `required`: none of them means "prompt".
        .group(
            ArgGroup::new("password-source")
                .args(["password-env", "password-file", "password-stdin"])
                .multiple(false),
        )
        .after_help(PASSWORD_AFTER_HELP)
}

fn cli() -> Command {
    Command::new("msoffice-crypto")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Microsoft Office document encryption per MS-OFFCRYPTO")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .after_help(AFTER_HELP)
        .subcommand(
            Command::new("classify")
                .about("Report what a file is, whether it is encrypted, and how")
                .arg(
                    Arg::new("file")
                        .value_name("FILE")
                        .required(true)
                        .help("The file to inspect"),
                )
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Print one JSON object instead of the human-readable form"),
                )
                .after_help(
                    "classify cannot fail. An unencrypted package prints `encrypted: no` \
                     and sixteen bytes of junk print `container: unknown`; both exit 0, \
                     because both are answers. Only a file that cannot be read exits 2. \
                     The `--json` key set is the same for every input -- an unencrypted \
                     file carries key_data and password_key as null rather than dropping \
                     them.",
                ),
        )
        .subcommand(
            crypt_command(
                "decrypt",
                "Decrypt an encrypted Office document",
                "decrypted",
            )
            .arg(
                Arg::new("integrity")
                    .long("integrity")
                    .value_name("POLICY")
                    .value_parser(POLICY_NAMES)
                    // Never a literal: the library's default has already moved once
                    // (GH #12), and a CLI with the old name typed into its help text
                    // would have survived that change looking correct.
                    .default_value(policy_name(IntegrityPolicy::default()))
                    .help(
                        "What to do about the dataIntegrity tag: require refuses any \
                         format without one (Office 2007 and 97-2003 included); \
                         require-where-defined verifies wherever the format defines one; \
                         verify-if-present accepts a deleted tag; skip never checks. The \
                         outcome is printed on stderr as `integrity: ...` after every \
                         successful decrypt",
                    ),
            ),
        )
        .subcommand(
            crypt_command("encrypt", "Encrypt a plaintext OOXML package", "encrypted").arg(
                Arg::new("format")
                    .long("format")
                    .value_name("FORMAT")
                    .value_parser(FORMAT_NAMES)
                    .default_value(format_name(Format::Agile))
                    .help(
                        "Which encryption to write. agile is what Office 2010 and later \
                         write and the only one of the two carrying a dataIntegrity HMAC, \
                         so a file modified after it was encrypted is refused rather than \
                         silently opened. standard is ECMA-376 standard encryption, Office \
                         2007's: choose it when the result must open in a reader that \
                         predates agile, and accept that it defines no integrity element \
                         at all. The format's answer is printed on stderr as `integrity: \
                         ...` after every successful encrypt",
                    ),
            ),
        )
}

fn main() -> ExitCode {
    // Parsed by hand rather than `get_matches()` so a clap usage error becomes exit 1
    // from the table above, not clap's own exit 2 -- which would collide with EX_IO.
    let m = match cli().try_get_matches() {
        Ok(m) => m,
        Err(e) => {
            let ok = matches!(
                e.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            );
            let _ = e.print();
            return ExitCode::from(if ok { EX_OK } else { EX_USAGE });
        }
    };
    ExitCode::from(dispatch(&m))
}

fn dispatch(m: &ArgMatches) -> u8 {
    match m.subcommand() {
        Some(("classify", sub)) => cmd_classify(sub),
        Some(("decrypt", sub)) => cmd_crypt(sub, Direction::Decrypt),
        Some(("encrypt", sub)) => cmd_crypt(sub, Direction::Encrypt),
        _ => EX_USAGE,
    }
}

// --- classify -------------------------------------------------------------

fn cmd_classify(m: &ArgMatches) -> u8 {
    let file = m.get_one::<String>("file").expect("required by clap");
    let mut input = match open_input(file) {
        Ok(f) => f,
        Err(code) => return code,
    };
    // No `?`, no Result, no arm mapping "unknown" to a failure: `classify` answers
    // every input by contract (CLAUDE.md Design Value 1), so this always exits 0. From the
    // file rather than from its bytes: only the headers are read.
    let class = classify_from(&mut input);
    if m.get_flag("json") {
        println!("{}", classification_json(&class));
    } else {
        print!("{}", classification_human(&class));
    }
    EX_OK
}

// Every renderer carries a `_` arm because each of these enums is `#[non_exhaustive]`
// and this binary is a separate crate from the library. `_` renders `unrecognised`,
// never `unknown`: `unknown` is a real variant of three of them and the two facts must
// not be indistinguishable.

fn container_name(c: Container) -> &'static str {
    match c {
        Container::Cfb => "cfb",
        Container::Zip => "zip",
        Container::Unknown => "unknown",
        _ => "unrecognised",
    }
}

fn document_name(d: Document) -> &'static str {
    match d {
        Document::OoxmlPackage => "ooxml-package",
        // Not "ooxml-package": four bytes of `PK` magic, nothing inside the archive read.
        // The two were one word until the classifier stopped claiming more than it checked.
        Document::ZipArchive => "zip-archive",
        Document::WordBinary => "word-binary",
        Document::ExcelBinary => "excel-binary",
        Document::PowerPointBinary => "powerpoint-binary",
        Document::Word95Binary => "word95-binary",
        Document::Excel95Binary => "excel95-binary",
        Document::Unknown => "unknown",
        _ => "unrecognised",
    }
}

/// `container-read:` — whether the container's directory was reachable in the bytes
/// supplied. The one line that tells a reader whether the `unknown`s above it mean
/// "looked, found nothing" or "could not look", which for a file handed over in pieces is
/// the difference between an answer and a missing one.
fn container_read_name(r: ContainerRead) -> &'static str {
    match r {
        ContainerRead::Opened => "opened",
        ContainerRead::Unreadable => "unreadable",
        ContainerRead::NotAttempted => "not-attempted",
        _ => "unrecognised",
    }
}

fn family_name(f: Family) -> &'static str {
    match f {
        Family::Unencrypted => "unencrypted",
        Family::Agile => "agile",
        Family::Standard => "standard",
        Family::Rc4CryptoApi => "rc4-cryptoapi",
        Family::Rc4 => "rc4",
        Family::XorObfuscation => "xor-obfuscation",
        Family::Unsupported => "unsupported",
        Family::Irm => "irm",
        Family::Unknown => "unknown",
        _ => "unrecognised",
    }
}

fn integrity_name(i: IntegrityDeclaration) -> &'static str {
    match i {
        IntegrityDeclaration::Declared => "declared",
        IntegrityDeclaration::Incomplete => "incomplete",
        IntegrityDeclaration::Absent => "absent",
        IntegrityDeclaration::NotApplicable => "not-applicable",
        IntegrityDeclaration::Unknown => "unknown",
        _ => "unrecognised",
    }
}

/// Not kebab: these are the names the spec and the file both use.
fn cipher_name(c: CipherAlgorithm) -> &'static str {
    match c {
        CipherAlgorithm::Aes => "AES",
        CipherAlgorithm::Rc4 => "RC4",
        _ => "unrecognised",
    }
}

fn hash_name(h: HashAlgorithm) -> &'static str {
    match h {
        HashAlgorithm::Sha1 => "SHA-1",
        HashAlgorithm::Sha256 => "SHA-256",
        HashAlgorithm::Sha384 => "SHA-384",
        HashAlgorithm::Sha512 => "SHA-512",
        _ => "unrecognised",
    }
}

fn policy_name(p: IntegrityPolicy) -> &'static str {
    match p {
        IntegrityPolicy::Require => POLICY_NAMES[0],
        IntegrityPolicy::RequireWhereDefined => POLICY_NAMES[1],
        IntegrityPolicy::VerifyIfPresent => POLICY_NAMES[2],
        IntegrityPolicy::Skip => POLICY_NAMES[3],
        _ => "unrecognised",
    }
}

/// The inverse of [`policy_name`], over the same table. `None` for a name the table
/// lacks: unreachable from `main`, where clap has already validated against
/// `POLICY_NAMES`, and pinned by `the_policy_table_round_trips_and_the_default_is_in_it`.
fn parse_policy(name: &str) -> Option<IntegrityPolicy> {
    match name {
        n if n == POLICY_NAMES[0] => Some(IntegrityPolicy::Require),
        n if n == POLICY_NAMES[1] => Some(IntegrityPolicy::RequireWhereDefined),
        n if n == POLICY_NAMES[2] => Some(IntegrityPolicy::VerifyIfPresent),
        n if n == POLICY_NAMES[3] => Some(IntegrityPolicy::Skip),
        _ => None,
    }
}

/// Which writer `encrypt` calls. A CLI-local enum, deliberately NOT `#[non_exhaustive]`
/// and deliberately matched without a `_` arm: T2's wildcard rule is about the
/// library's types crossing a crate boundary, and here exhaustiveness is the feature --
/// a third format must not compile until every arm below has been written.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Format {
    Agile,
    Standard,
}

fn format_name(f: Format) -> &'static str {
    match f {
        Format::Agile => FORMAT_NAMES[0],
        Format::Standard => FORMAT_NAMES[1],
    }
}

/// The inverse of [`format_name`], over the same table. `None` is unreachable from
/// `main` (clap validated against `FORMAT_NAMES`) and pinned by the round-trip test.
fn parse_format(name: &str) -> Option<Format> {
    match name {
        n if n == FORMAT_NAMES[0] => Some(Format::Agile),
        n if n == FORMAT_NAMES[1] => Some(Format::Standard),
        _ => None,
    }
}

/// What the artifact will carry, as the LIBRARY's own word -- the same word `classify`
/// prints for that artifact afterwards. Agile always writes `<dataIntegrity>`;
/// [MS-OFFCRYPTO] §2.3.4.5 defines none for Office 2007, which is the whole reason
/// `encrypt` has no `--integrity` flag: this is a property of the format, reported, not
/// a policy, chosen.
fn declared_integrity(f: Format) -> IntegrityDeclaration {
    match f {
        Format::Agile => IntegrityDeclaration::Declared,
        Format::Standard => IntegrityDeclaration::NotApplicable,
    }
}

/// The `integrity:` line's spelling of an [`IntegrityOutcome`], lower-kebab like every
/// other enum here. The `_` arm is resolved through `is_authenticated()` rather than a
/// bare `unrecognised`: the enum is `#[non_exhaustive]`, and the one property of a
/// future variant that matters to the person reading the line is which side of that
/// predicate it falls on -- which the library maintains and this binary cannot know.
fn outcome_name(o: IntegrityOutcome) -> &'static str {
    match o {
        IntegrityOutcome::Verified => "verified",
        IntegrityOutcome::NotDeclared => "not-declared",
        IntegrityOutcome::NotApplicable => "not-applicable",
        IntegrityOutcome::Skipped => "skipped",
        _ if o.is_authenticated() => "unrecognised (authenticated)",
        _ => "unrecognised (unauthenticated)",
    }
}

/// The six `AlgorithmParams` fields, in declaration order, under one prefix.
///
/// Run twice — `key` over `key_data`, `pw` over `password_key` — because a
/// `Classification` carries the package encryptor's parameters and the verifier's
/// separately and they differ in real files. A field that is `None` prints no line at
/// all: absence is reported by absence, not by a dash.
///
/// `spin` is **not** special-cased away on the `key` block. `classify`'s `read_params`
/// is element-agnostic, so a hostile file can put `spinCount` on `<keyData>` and this
/// crate goes out of its way to surface it.
fn params_lines(prefix: &str, p: &AlgorithmParams) -> String {
    let mut out = String::new();
    let mut line = |k: String, v: String| out.push_str(&format!("{k:<16}{v}\n"));
    if let Some(v) = p.cipher {
        line(format!("{prefix}-cipher:"), cipher_name(v).to_string());
    }
    if let Some(v) = p.hash {
        line(format!("{prefix}-hash:"), hash_name(v).to_string());
    }
    if let Some(v) = p.key_bits {
        line(format!("{prefix}-bits:"), v.to_string());
    }
    if let Some(v) = p.block_size {
        line(format!("{prefix}-block:"), v.to_string());
    }
    if let Some(v) = p.salt_size {
        line(format!("{prefix}-salt:"), v.to_string());
    }
    if let Some(v) = p.spin_count {
        line(format!("{prefix}-spin:"), v.to_string());
    }
    out
}

/// The same six `AlgorithmParams` fields as [`params_lines`], as one JSON object with
/// **all six keys always present** — `null` where the field is `None`.
///
/// This is the deliberate asymmetry with the human form: a line the human renderer
/// omits for an absent field still gets a key here, because a script reading `--json`
/// should not have to distinguish "this key is missing" from "this key is null" for a
/// schema that is otherwise fixed. Built as a `serde_json::Value` rather than by string
/// concatenation for the same reason as the sibling's `classification_json`: a field
/// added later without remembering to escape it can no longer emit broken JSON, because
/// escaping is no longer something this function does.
fn params_json(p: &AlgorithmParams) -> Value {
    json!({
        "cipher": p.cipher.map(cipher_name),
        "hash": p.hash.map(hash_name),
        "key_bits": p.key_bits,
        "block_size": p.block_size,
        "salt_size": p.salt_size,
        "spin_count": p.spin_count,
    })
}

/// One field per line, `{key:<14}{value}`, absent fields omitted.
///
/// `encrypted:` and `supported:` are methods on `Classification`, not fields: nothing
/// derives them, so they are added by hand here.
fn classification_human(c: &Classification) -> String {
    let mut out = String::new();
    {
        // Width 16, taken from the longest key rather than chosen by eye:
        // `container-read:` is fifteen characters, and at the 14 this used to be its
        // value ran straight into the colon with no gap. `params_lines` above shares the
        // width because its output is appended to this one.
        // (Was 14, the sibling's idiom, when `key-cipher:` at eleven was the longest.)
        let mut line = |k: &str, v: &str| out.push_str(&format!("{k:<16}{v}\n"));
        line("container:", container_name(c.container));
        // Immediately after `container:`, because it qualifies every line below it.
        line("container-read:", container_read_name(c.container_read));
        line("document:", document_name(c.document));
        // Omitted entirely when absent -- never printed as an empty value or a dash.
        if let Some((major, minor)) = c.version {
            line("version:", &format!("{major}.{minor}"));
        }
        line("family:", family_name(c.family));
        line("encrypted:", if c.is_encrypted() { "yes" } else { "no" });
        line("supported:", if c.is_supported() { "yes" } else { "no" });
        // Always: `Unknown` is a variant of IntegrityDeclaration, not an absence.
        line("integrity:", integrity_name(c.data_integrity));
    }
    if let Some(p) = c.key_data.as_ref() {
        out.push_str(&params_lines("key", p));
    }
    if let Some(p) = c.password_key.as_ref() {
        out.push_str(&params_lines("pw", p));
    }
    out
}

/// One JSON object, hand-built as a `serde_json::Value` rather than by string
/// concatenation — the same reasoning as [`params_json`]: nothing here escapes a string,
/// so nothing here can forget to.
///
/// Nested, never prefix-flattened: `key_data` and `password_key` are each either `null`
/// (the whole block, when the `Option` is `None`) or a complete six-key object from
/// [`params_json`] — never six individually-nulled top-level keys. `data_integrity`, not
/// `integrity`: JSON keys are `Classification`'s own field names, while the human form's
/// `integrity:` is a column heading and free to read shorter.
///
/// `version` is the string `"{major}.{minor}"`, matching the human form, not a two-
/// element array or an object — chosen because nothing here needs to do arithmetic on
/// the pair, only display it, and a string is unambiguous either way.
///
/// `serde_json::Map` is a `BTreeMap`, so keys serialise in alphabetical order; nothing
/// here or in `tests/cli.rs` may assume a particular order.
fn classification_json(c: &Classification) -> String {
    let mut o = Map::new();
    o.insert("container".into(), json!(container_name(c.container)));
    o.insert(
        "container_read".into(),
        json!(container_read_name(c.container_read)),
    );
    o.insert("document".into(), json!(document_name(c.document)));
    o.insert(
        "version".into(),
        json!(c.version.map(|(major, minor)| format!("{major}.{minor}"))),
    );
    o.insert("family".into(), json!(family_name(c.family)));
    o.insert("encrypted".into(), json!(c.is_encrypted()));
    o.insert("supported".into(), json!(c.is_supported()));
    o.insert(
        "data_integrity".into(),
        json!(integrity_name(c.data_integrity)),
    );
    o.insert(
        "key_data".into(),
        c.key_data.as_ref().map_or(Value::Null, params_json),
    );
    o.insert(
        "password_key".into(),
        c.password_key.as_ref().map_or(Value::Null, params_json),
    );
    Value::Object(o).to_string()
}

// --- decrypt / encrypt ------------------------------------------------------

/// Which subcommand [`cmd_crypt`] is serving.
///
/// `prompt_verb` names the password prompt; `suffix` names the derived output file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Decrypt,
    Encrypt,
}

impl Direction {
    /// "Password" when reading one, "New password" when choosing one, so an `encrypt`
    /// prompt does not read as though the file already had a password.
    fn prompt_verb(self) -> &'static str {
        match self {
            Direction::Decrypt => "Password",
            Direction::Encrypt => "New password",
        }
    }

    /// `report.docx` -> `report.decrypted.docx` / `report.encrypted.docx` (plan § 8).
    fn suffix(self) -> &'static str {
        match self {
            Direction::Decrypt => "decrypted",
            Direction::Encrypt => "encrypted",
        }
    }
}

/// The one password source this run may use.
///
/// The [`ArgGroup`] in [`crypt_command`] guarantees at most one flag was given, so this
/// is a selection and not a precedence order; `Prompt` is what *no* flag means, which is
/// why that group is `multiple(false)` and deliberately not `required`.
enum PasswordSource {
    Env(String),
    File(PathBuf),
    Stdin,
    Prompt,
}

impl PasswordSource {
    /// How to name this source to a user whose password turned out to be empty. Never
    /// includes the value — only where it came from.
    fn origin(&self) -> String {
        match self {
            PasswordSource::Env(name) => format!("environment variable `{name}`"),
            PasswordSource::File(path) => format!("password file {}", path.display()),
            PasswordSource::Stdin => "stdin".to_string(),
            PasswordSource::Prompt => "the prompt".to_string(),
        }
    }
}

fn cmd_crypt(m: &ArgMatches, dir: Direction) -> u8 {
    // The hidden trap arg, checked before anything reads a file, a variable or stdin, so
    // reaching for `--password` is answered with the reason it does not exist rather than
    // clap's generic "unexpected argument". The value is never echoed: it is a password.
    if m.get_one::<String>(PASSWORD_TRAP).is_some() {
        eprintln!(
            "msoffice-crypto: there is no `--password` argument: argv is world-readable in a \
             process listing.\nUse --password-env NAME, --password-file PATH or --password-stdin."
        );
        return EX_USAGE;
    }

    // At most one is present -- the ArgGroup rejected two before we got here, so this is
    // not a precedence chain and must never become one.
    let source = if let Some(name) = m.get_one::<String>("password-env") {
        PasswordSource::Env(name.clone())
    } else if let Some(path) = m.get_one::<String>("password-file") {
        PasswordSource::File(PathBuf::from(path))
    } else if m.get_flag("password-stdin") {
        PasswordSource::Stdin
    } else {
        PasswordSource::Prompt
    };

    let file = m.get_one::<String>("file").expect("required by clap");
    let input = match open_input(file) {
        Ok(f) => f,
        Err(code) => return code,
    };

    match dir {
        Direction::Decrypt => cmd_decrypt(m, file, input, source),
        Direction::Encrypt => cmd_encrypt(m, file, input, source),
    }
}

/// Open the input for reading, the one way every command does.
///
/// Since 0.1.0-rc.7 the file is streamed rather than read whole: only the headers for a
/// classification, and one 4096-byte segment at a time through a decrypt or an encrypt.
/// One byte is read here and the file rewound, so that an input that opens but cannot be
/// read -- a directory, on the platforms where a directory opens -- is refused with the
/// error `std::fs::read` used to give, before anything else happens.
fn open_input(file: &str) -> Result<File, u8> {
    let probe = File::open(file).and_then(|mut f| {
        // The count does not matter, only whether the read fails: an empty file is a
        // file, and `classify` has an answer for it.
        let _ = f.read(&mut [0u8; 1])?;
        f.seek(SeekFrom::Start(0))?;
        Ok(f)
    });
    probe.map_err(|e| {
        eprintln!("msoffice-crypto: cannot read {file}: {e}");
        // Through the one table rather than a literal EX_IO, so the CLI has exactly one
        // Error -> exit-code function.
        exit_code(&Error::Io(e))
    })
}

/// `decrypt`: classify, refuse what needs no password, read the password, decrypt, write.
///
/// The classification comes BEFORE the password on purpose. A plain `.docx`, sixteen
/// bytes of junk, a `.doc` in a build without `legacy-binary`, and `--integrity require`
/// on a 97-2003 document are all answered from the bytes alone; prompting for a password
/// to a file that has none, or opening a `--password-file` for a file this build cannot
/// act on, would be wrong and would make "nothing was read" untrue.
///
/// Dispatch is on the classification, never the extension (plan § 6): a `.doc` that is
/// really an OOXML package, or the reverse, is exactly the file this crate exists for.
fn cmd_decrypt(m: &ArgMatches, file: &str, mut input: File, source: PasswordSource) -> u8 {
    let name = m.get_one::<String>("integrity").expect("clap default");
    let Some(policy) = parse_policy(name) else {
        // clap validated `name` against POLICY_NAMES and `parse_policy` reads the same
        // table, so this is a broken table, not a user error.
        eprintln!(
            "msoffice-crypto: internal error: --integrity {name} is in the accepted list \
             but names no policy"
        );
        return EX_INTERNAL;
    };

    let route = match route_for(&classify_from(&mut input), policy) {
        Ok(r) => r,
        Err(r) => return refused(file, &r),
    };

    // Before the password, as the classification is: an output that is already there is
    // answered from the file system alone, so it is not worth a prompt.
    let target = match output_target(m, file, Direction::Decrypt) {
        Ok(t) => t,
        Err(code) => return code,
    };

    let password = match read_password(source, Direction::Decrypt) {
        Ok(p) => p,
        Err(code) => return code,
    };

    let outcome = match route {
        // Streamed: the package goes from the input to the output a segment at a time,
        // and a verified decrypt checks the tag before the first byte is written, so a
        // tampered file leaves neither a target nor a temporary behind.
        Route::Ooxml => match deliver(&target, file, |out| {
            decrypt_ooxml_to(&mut input, out, &password, policy).map(|o| o.integrity)
        }) {
            Ok(integrity) => outcome_name(integrity),
            Err(code) => return code,
        },
        // T5: this is the whole rewritten CFB container, the same length as the input,
        // magic D0 CF 11 E0 -- not a PK package. Nothing below sniffs its shape. Read
        // whole, because `decrypt_binary_office` rewrites a container in memory: the
        // 97-2003 formats are outside the streaming work (#27), and their own read cap
        // bounds what this holds.
        #[cfg(feature = "legacy-binary")]
        Route::Legacy => {
            // From the start: classifying it moved the file's position, and
            // `classify_from` leaves it unspecified.
            let mut bytes = Vec::new();
            if let Err(e) = input
                .seek(SeekFrom::Start(0))
                .and_then(|_| input.read_to_end(&mut bytes))
            {
                eprintln!("msoffice-crypto: cannot read {file}: {e}");
                return exit_code(&Error::Io(e));
            }
            match deliver(&target, file, |out| {
                let container = decrypt_binary_office(&bytes, &password)?;
                out.write_all(&container)?;
                // The library returns bytes and no outcome: none of the 97-2003 formats
                // defines an integrity tag, so `not-applicable` is the CLI's own word,
                // and it is the same word under every policy that reaches here -- `skip`
                // included, because nothing was skipped. `require` never reaches here.
                Ok(IntegrityOutcome::NotApplicable)
            }) {
                Ok(integrity) => outcome_name(integrity),
                Err(code) => return code,
            }
        }
    };
    // On EVERY success, `skip` included, so a user who opted out is told in the same run
    // that the bytes they now hold are unauthenticated. Stderr, so `-o -` is unaffected.
    eprintln!("integrity: {outcome}");
    EX_OK
}

/// `encrypt`: choose the writer, refuse what cannot be encrypted, read the password,
/// encrypt, write, and say what the artifact carries.
///
/// The guard comes BEFORE the password for the same reason the classification does in
/// `cmd_decrypt`: prompting for a NEW password for a file that is about to be refused
/// would be wrong, and on an interactive path it is the part that cannot be taken back.
///
/// The guard itself is the library's. [`check_encryptable`] is the same function
/// `encrypt_ooxml` calls at the door, so the CLI cannot drift from what the writer will
/// accept — it used to be a CLI-only `encrypt_guard`, which is exactly how a consumer
/// ended up reimplementing it.
fn cmd_encrypt(m: &ArgMatches, file: &str, mut input: File, source: PasswordSource) -> u8 {
    let name = m.get_one::<String>("format").expect("clap default");
    let Some(format) = parse_format(name) else {
        eprintln!(
            "msoffice-crypto: internal error: --format {name} is in the accepted list \
             but names no writer"
        );
        return EX_INTERNAL;
    };

    if let Err(e) = check_encryptable_from(&mut input) {
        return report(file, &e);
    }

    let target = match output_target(m, file, Direction::Encrypt) {
        Ok(t) => t,
        Err(code) => return code,
    };

    let password = match read_password(source, Direction::Encrypt) {
        Ok(p) => p,
        Err(code) => return code,
    };

    // Streamed into a file the container can be assembled in: `cfb` reads back what it
    // writes, and the agile `EncryptionInfo` is patched once the package is through.
    let written = deliver_seekable(&target, file, |out| match format {
        Format::Agile => encrypt_ooxml_to(&mut input, out, &password),
        Format::Standard => encrypt_ooxml_standard_to(&mut input, out, &password),
    });
    if let Err(code) = written {
        return code;
    }
    // On every success, so the artifact's one security-relevant property is stated in
    // the run that produced it. Stderr, so `-o -` is unaffected.
    eprintln!("integrity: {}", integrity_name(declared_integrity(format)));
    if format == Format::Standard {
        eprintln!(
            "msoffice-crypto: Office 2007 standard encryption defines no dataIntegrity \
             element: a file modified after it was encrypted decrypts without \
             complaint. `--format agile` writes one."
        );
    }
    EX_OK
}

// --- dispatch: what each direction will and will not touch ---------------

/// Where `decrypt` sends a file, decided from its classification and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// `decrypt_ooxml_with_policy`.
    Ooxml,
    /// `decrypt_binary_office`. Exists only where that function does; in the other
    /// build `route_for` answers exit 9 for these documents and never names this.
    #[cfg(feature = "legacy-binary")]
    Legacy,
}

/// A refusal `decrypt` makes before it has read a password: the exit code and the
/// noun phrase, minus the file name and the `nothing was written` tail `cmd_decrypt` adds.
#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    code: u8,
    why: String,
}

fn refuse(code: u8, why: impl Into<String>) -> Result<Route, Refusal> {
    Err(Refusal {
        code,
        why: why.into(),
    })
}

/// Plan § 6 / CONTRACT § 5. Every branch here is a fact the classification alone
/// establishes, which is why this runs before the password is read.
///
/// The library cannot make these distinctions: handed `plain.docx` it says
/// `NotACfbFile`, which is true and unhelpful, and handed sixteen bytes of junk it says
/// the same thing. Two answers for one library error, because the classification tells
/// them apart and the error cannot.
fn route_for(class: &Classification, policy: IntegrityPolicy) -> Result<Route, Refusal> {
    if class.container == Container::Unknown {
        return refuse(EX_NOT_OFFICE, NOT_OFFICE);
    }
    // Either container: a plain `.docx` (zip) and a plain `.doc` (a CFB whose encryption
    // bit is clear) are the same fact, and neither needs a password to establish.
    if class.family == Family::Unencrypted {
        return refuse(EX_REFUSED, NOT_ENCRYPTED);
    }
    if class.document == Document::Unknown {
        return refuse(
            EX_NOT_OFFICE,
            "a CFB container, but not a Microsoft Office document this tool recognises",
        );
    }
    // `Family::Unsupported` (extensible encryption; a BIFF5 FILEPASS with no version)
    // and the pairs the library refuses by design (XOR obfuscation in a `.doc`).
    // `Family::Unknown` on a binary document is NOT caught here: `is_encrypted()` is
    // false for it, and the library gets to say `NotEncrypted` or `MissingStream`.
    if class.is_encrypted() && !class.is_supported() {
        return refuse(
            EX_UNSUPPORTED,
            format!(
                "a {} document under {} encryption, which this crate does not implement",
                document_name(class.document),
                family_name(class.family)
            ),
        );
    }
    match class.document {
        Document::OoxmlPackage => Ok(Route::Ooxml),
        Document::WordBinary | Document::ExcelBinary | Document::PowerPointBinary => {
            // The request before the build: "you asked for a guarantee this format does
            // not define" is true of the file in every build, so the answer must not
            // change with the feature set. The same sentence the library gives for
            // Office 2007 standard encryption (`IntegrityUnavailable`), which is also 8.
            //
            // It is also true before the encryption status is known, and deliberately
            // fires there. `Family::Unknown` on a binary document means the walk was
            // undecided (`classify.rs`: a `/Workbook` that runs out, or does not open
            // with BOF), and the library's own walk may still decrypt it -- so gating
            // this on `is_encrypted()` would hand back unauthenticated plaintext under
            // `--integrity require`, which is the one thing the policy forbids. Refusing
            // an undecided file is the fail-closed answer, and the sentence below is
            // therefore written about the *request*, never about the file: it neither
            // calls the file encrypted nor promises that the opt-out will open it. Under
            // any other policy these bytes reach the decrypter and get its answer.
            if policy == IntegrityPolicy::Require {
                return refuse(
                    EX_INTEGRITY,
                    format!(
                        "you asked for --integrity require, and this is a {} 97-2003 \
                         document; those formats define no integrity tag, so nothing \
                         could verify -- encrypted or not, which is why this refusal \
                         does not wait to find out. `--integrity require-where-defined` \
                         accepts that, and lets the decrypter answer for the file",
                        document_name(class.document)
                    ),
                );
            }
            #[cfg(feature = "legacy-binary")]
            {
                Ok(Route::Legacy)
            }
            // Not an `Error`: in this build the library produced nothing at all, so the
            // sentence -- and the remedy -- are the CLI's alone (CONTRACT § 3).
            #[cfg(not(feature = "legacy-binary"))]
            {
                refuse(
                    EX_UNSUPPORTED,
                    format!(
                        "a {} 97-2003 document, and this build was compiled without the \
                         `legacy-binary` feature; rebuild with `cargo install \
                         msoffice-crypto --features cli,legacy-binary`",
                        document_name(class.document)
                    ),
                )
            }
        }
        // Word 6.0/95 and Excel 5.0/95: recognised, and read by no decrypt path in any
        // build, whatever their encryption says -- the library refuses both by name.
        Document::Word95Binary | Document::Excel95Binary => refuse(
            EX_UNSUPPORTED,
            format!(
                "a {} document, an edition before 97 that this crate does not read",
                document_name(class.document)
            ),
        ),
        // `Document::Unknown` was answered above, so this is a variant added later.
        _ => refuse(
            EX_UNSUPPORTED,
            format!(
                "a document kind this build does not know how to decrypt ({})",
                document_name(class.document)
            ),
        ),
    }
}

/// The clause the "already encrypted" refusal ends on. A remedy is only a remedy if the
/// same binary can carry it out, and "decrypt it first" cannot be carried out for a
/// 97-2003 binary document in **either** `cli` column: with `legacy-binary` the decrypt
/// succeeds and hands back a rewritten CFB (T5) that the next `encrypt` refuses, because
/// this tool writes encryption around an OOXML package and nothing else; without it
/// `route_for`'s `#[cfg(not(feature = "legacy-binary"))]` arm refuses the decrypt itself
/// at exit 9. Either way the advice sends the user to a second refusal, so it is not
/// given. One sentence, true in both builds.
fn reencrypt_remedy(document: Document) -> &'static str {
    match document {
        Document::WordBinary | Document::ExcelBinary | Document::PowerPointBinary => {
            "there is no writer for the 97-2003 binary formats, so this tool cannot \
             re-encrypt it in any build"
        }
        // `Document` is `#[non_exhaustive]` (T2), and an encrypted CFB this build cannot
        // name is far likelier to be a package kind added later than a binary one: the
        // three binary documents above are the closed set [MS-OFFCRYPTO] defines.
        _ => "decrypt it first if you meant to re-encrypt it",
    }
}

// --- output paths ---------------------------------------------------------

/// `report.docx` -> `report.decrypted.docx`. A file with no extension gets the suffix
/// appended, so `report` -> `report.decrypted`.
///
/// The extension is whatever the input had -- `.doc` stays `.doc`, because
/// `decrypt_binary_office` returns a rewritten CFB, not a package, and normalising it
/// would mislabel the output.
fn derived_output(input: &Path, suffix: &str) -> PathBuf {
    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
    let name = match input.extension() {
        Some(ext) => format!("{stem}.{suffix}.{}", ext.to_string_lossy()),
        None => format!("{stem}.{suffix}"),
    };
    input.with_file_name(name)
}

/// Where the output goes: stdout for `-o -`, otherwise a path.
#[derive(Debug)]
enum Target {
    Stdout,
    File(PathBuf),
}

/// The output both directions share (plan § 8), decided **before** the password is read.
///
/// `Err(code)` with the reason printed if the target exists and `--force` was not given:
/// never silently, because a decrypt that replaced the encrypted original, or an earlier
/// decrypt, is unrecoverable. `exists()`, not `is_file()`: a directory at the target is
/// also something this tool must not rename over.
fn output_target(m: &ArgMatches, input: &str, dir: Direction) -> Result<Target, u8> {
    let target = match m.get_one::<String>("output").map(String::as_str) {
        Some("-") => return Ok(Target::Stdout),
        Some(o) => PathBuf::from(o),
        None => derived_output(Path::new(input), dir.suffix()),
    };
    if target.exists() && !m.get_flag("force") {
        eprintln!(
            "msoffice-crypto: {} already exists; pass --force to overwrite. Nothing was \
             written.",
            target.display()
        );
        return Err(EX_USAGE);
    }
    Ok(Target::File(target))
}

/// A writer that remembers whether anything reached it, so a failure on stdout can say
/// whether there is output to discard.
struct Counted<W> {
    inner: W,
    written: u64,
}

impl<W: Write> Write for Counted<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Run `produce` into the target and report the outcome: `Ok` with what it returned once
/// the output is complete, or `Err(code)` with the reason already printed.
///
/// A file target is written atomically, through the temporary beside it, so a failure at
/// any point -- a refused tag, a cancelled read, a full disk -- leaves the target as it
/// was and no temporary behind. Stdout cannot be taken back: if a failure comes after
/// bytes were written, the run says so, and exits non-zero.
fn deliver<T>(
    target: &Target,
    file: &str,
    produce: impl FnOnce(&mut dyn Write) -> Result<T, Error>,
) -> Result<T, u8> {
    match target {
        Target::Stdout => {
            // Stdout carries the bytes and nothing else; every notice is on stderr.
            let mut out = Counted {
                inner: std::io::stdout().lock(),
                written: 0,
            };
            let result = produce(&mut out).and_then(|t| {
                out.flush()?;
                Ok(t)
            });
            result.map_err(|e| {
                if out.written > 0 {
                    eprintln!(
                        "msoffice-crypto: the {} bytes already written to stdout are \
                         incomplete; discard them",
                        out.written
                    );
                }
                report(file, &e)
            })
        }
        Target::File(path) => finish(path, file, write_atomically_with(path, |f| produce(f))),
    }
}

/// [`deliver`] for an encrypt, whose output must be readable and seekable as well.
///
/// A file target is the same atomic temporary. Stdout cannot seek, so the container is
/// assembled in a temporary file in the system temp directory and copied out once it is
/// complete -- ciphertext only, removed on every path.
fn deliver_seekable(
    target: &Target,
    file: &str,
    produce: impl FnOnce(&mut File) -> Result<(), Error>,
) -> Result<(), u8> {
    match target {
        Target::File(path) => finish(path, file, write_atomically_with(path, produce)),
        Target::Stdout => {
            let tmp = std::env::temp_dir().join(format!(
                ".msoffice-crypto-{}.stdout.tmp",
                std::process::id()
            ));
            let result = (|| {
                // Never kept: it vanishes when it drops, at the end of this closure, on
                // success and failure alike -- and with the process if it is killed.
                let mut pending =
                    Pending::create(&std::env::temp_dir(), &tmp).map_err(Error::Io)?;
                let f = pending.file();
                produce(f)?;
                f.seek(SeekFrom::Start(0)).map_err(Error::Io)?;
                let mut out = std::io::stdout().lock();
                std::io::copy(f, &mut out).map_err(Error::Io)?;
                out.flush().map_err(Error::Io)
            })();
            result.map_err(|e| report(file, &e))
        }
    }
}

/// Turn an atomic write's result into the CLI's: the notice on success, and on failure
/// the library's reason or the file system's.
fn finish<T>(path: &Path, file: &str, result: Result<T, Failed>) -> Result<T, u8> {
    match result {
        Ok(t) => {
            eprintln!("msoffice-crypto: wrote {}", path.display());
            Ok(t)
        }
        Err(Failed::Produce(e)) => Err(report(file, &e)),
        Err(Failed::Io(e)) => {
            eprintln!("msoffice-crypto: cannot write {}: {e}", path.display());
            Err(EX_IO)
        }
    }
}

/// `/a/b/report.docx` -> `/a/b/.report.docx.msoffice-crypto.tmp`: the SAME directory as
/// the target, never the system temp directory, because `rename` is atomic only within
/// one filesystem and degrades to a copy across two.
fn temp_path_for(target: &Path) -> PathBuf {
    let dir = target.parent().unwrap_or(Path::new("."));
    let file_name = target.file_name().unwrap_or_default().to_string_lossy();
    dir.join(format!(".{file_name}.msoffice-crypto.tmp"))
}

/// Why [`write_atomically_with`] failed: the producer refused, or the file system did.
#[derive(Debug)]
enum Failed {
    Produce(Error),
    Io(std::io::Error),
}

/// Write to a temporary file beside the target, then rename over it.
///
/// The target path is touched by exactly one call in this function, `rename`, which is
/// atomic on the same filesystem. So an interrupted run leaves either the untouched
/// target or the finished one, plus at worst a `.X.msoffice-crypto.tmp` that no reader
/// mistakes for a document -- never a half-written `.docx` that looks complete. Pinned
/// by `write_atomically_never_opens_the_target_itself` in the unit module.
#[cfg(test)]
fn write_atomically(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomically_with(target, |f| f.write_all(bytes).map_err(Error::Io)).map_err(|e| match e {
        Failed::Io(e) => e,
        Failed::Produce(e) => std::io::Error::other(e.to_string()),
    })
}

/// [`write_atomically`] with the bytes produced into the temporary as they come, rather
/// than handed over whole: what lets a streamed decrypt or encrypt be atomic too.
///
/// The temporary is a [`Pending`]: readable as well as writable, because an encrypt
/// assembles a container in it, and gone if anything fails before it is kept -- whether
/// `produce` refuses, the disk fills, or the process is killed. Kept, it is renamed over
/// the target through `temp_path_for(target)`, so the target is touched only by that
/// rename.
fn write_atomically_with<T>(
    target: &Path,
    produce: impl FnOnce(&mut File) -> Result<T, Error>,
) -> Result<T, Failed> {
    let tmp = temp_path_for(target);
    let dir = match target.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let mut pending = Pending::create(dir, &tmp).map_err(Failed::Io)?;
    // On `Err` the `pending` drops here, and with it the temporary.
    let t = produce(pending.file()).map_err(Failed::Produce)?;
    pending.keep_as(&tmp, target).map_err(Failed::Io)?;
    Ok(t)
}

// --- passwords --------------------------------------------------------------

/// The one place a password enters this process.
///
/// Never returns the value in an error: every failure path here names the flag, the
/// path or the variable, and nothing else. That is not stylistic -- see the `Env` arm.
fn read_password(source: PasswordSource, dir: Direction) -> Result<String, u8> {
    let origin = source.origin();
    let password = read_password_from(source, dir)?;

    // An empty password is a usage error, not a wrong password. Before this check, an empty
    // `--password-file` -- a secret manager that returned nothing, a truncated write -- reached
    // the library as `""` and came back `Error::WrongPassword`, exit 4. That is the failure-mode
    // conflation CLAUDE.md § *Cryptographic Rules* forbids: it sends the user to re-check the
    // one thing that is not broken. No Office format encrypts under an empty password, so there
    // is no legitimate case to preserve.
    //
    // The message names the SOURCE and never the value.
    if password.is_empty() {
        eprintln!("msoffice-crypto: {origin} supplied an empty password.");
        return Err(EX_USAGE);
    }
    Ok(password)
}

fn read_password_from(source: PasswordSource, dir: Direction) -> Result<String, u8> {
    match source {
        // The value is used RAW: no `first_line`. A trailing newline in a variable the
        // caller set is the caller's, and an environment variable is not a file an editor
        // appended to. The asymmetry with `File` and `Stdin` below is deliberate.
        //
        // `map_err(|_| ..)`, discarding the error, is load-bearing. `VarError`'s `Display`
        // is "environment variable was not valid unicode: {:?}" -- it embeds the OsString,
        // which is the password. A `{e}` here would print it, and CLAUDE.md's cryptographic
        // rules forbid exactly that. Guarded by
        // `a_non_unicode_password_variable_never_reaches_stderr` in tests/cli.rs.
        PasswordSource::Env(name) => std::env::var(&name).map_err(|_| {
            eprintln!(
                "msoffice-crypto: environment variable `{name}` is not set, or does not \
                 hold text this platform can read as a password."
            );
            EX_USAGE
        }),
        PasswordSource::File(path) => match std::fs::read_to_string(&path) {
            Ok(s) => Ok(first_line(&s)),
            Err(e) => {
                eprintln!("msoffice-crypto: cannot read {}: {e}", path.display());
                Err(EX_IO)
            }
        },
        PasswordSource::Stdin => {
            let mut s = String::new();
            match std::io::stdin().read_to_string(&mut s) {
                Ok(_) => Ok(first_line(&s)),
                Err(e) => {
                    eprintln!("msoffice-crypto: cannot read stdin: {e}");
                    Err(EX_IO)
                }
            }
        }
        PasswordSource::Prompt => {
            // Refuse rather than block on a prompt nobody can see: with stdin redirected
            // from NUL or /dev/null there is no one to type into it, and a hang is a
            // failure no exit code can report. `std::io::IsTerminal`, stable since 1.70
            // and well under this crate's 1.87 MSRV -- no `atty`, no `is-terminal`.
            if !std::io::stdin().is_terminal() {
                eprintln!(
                    "msoffice-crypto: no password source and stdin is not a terminal.\n\
                     Use --password-env NAME, --password-file PATH or --password-stdin."
                );
                return Err(EX_USAGE);
            }
            rpassword::prompt_password(format!("{}: ", dir.prompt_verb())).map_err(|e| {
                eprintln!("msoffice-crypto: cannot read password: {e}");
                EX_IO
            })
        }
    }
}

/// A password file written by an editor ends with a newline that is not part of the
/// password. Strips one trailing CR-LF or LF, and nothing else — trailing spaces are
/// kept, because they can be deliberate.
///
/// Applies to `--password-file` and `--password-stdin`. NOT to `--password-env`: see
/// [`read_password`].
fn first_line(s: &str) -> String {
    let line = s.split('\n').next().unwrap_or("");
    line.strip_suffix('\r').unwrap_or(line).to_string()
}

// --- error -> exit code ---------------------------------------------------

/// A refusal made from the classification alone: the same sentence shape [`report`]
/// gives an [`Error`], minus the error. `decrypt`'s guard only — `encrypt`'s refusals are
/// the library's `Error`s now, and go through [`report`].
fn refused(file: &str, r: &Refusal) -> u8 {
    eprintln!("msoffice-crypto: {file}: {}; nothing was written.", r.why);
    r.code
}

/// Print an [`Error`] in the CLI's words and return its exit code.
fn report(file: &str, e: &Error) -> u8 {
    eprintln!(
        "msoffice-crypto: {file}: {}; nothing was written.",
        describe(e)
    );
    exit_code(e)
}

/// The CLI's own copy for the variants whose `Display` is written for a programmer
/// choosing a policy (`src/error.rs`, "Who the messages are written for"), and a
/// forward -- with the remedy where one exists -- for the rest. Opt-outs are named in
/// the CLI's spelling (`--integrity verify-if-present`), never as a Rust path, and
/// always AFTER the cost. `IntegrityCheckFailed` gets no remedy: there is none.
fn describe(e: &Error) -> String {
    match e {
        Error::NotACfbFile => "not a Microsoft Office file".to_string(),
        #[cfg(feature = "legacy-binary")]
        Error::NotEncrypted => NOT_ENCRYPTED.to_string(),
        Error::IntegrityCheckFailed => "this file was modified after it was encrypted: \
             your password was correct, but the package does not match its dataIntegrity \
             tag"
        .to_string(),
        Error::IntegrityElementMissing => "this file's tamper-evidence was deleted: it \
             declares agile encryption but carries no <dataIntegrity> element, which every \
             known writer emits, and removing it needs no password. `--integrity \
             verify-if-present` decrypts it anyway, as unauthenticated plaintext"
            .to_string(),
        Error::IntegrityUnavailable(what) => format!(
            "you asked for `--integrity require`; this format defines no integrity tag \
             ({what}). `--integrity require-where-defined` accepts it as unauthenticated \
             plaintext"
        ),
        Error::UnsupportedEncryptionVersion(..) | Error::UnsupportedAlgorithm { .. } => {
            format!("{e}; re-saving the document with a current Office writes agile encryption, which this tool reads")
        }
        // The three encrypt-guard refusals. These sentences were `encrypt_guard`'s until
        // the library took the guard; they are kept word for word, because `tests/cli.rs`
        // asserts them and because the wording is the CLI's job either way. `family` and
        // `document` come off the error rather than a second `classify` call.
        Error::AlreadyEncrypted { family, document } => format!(
            "already encrypted ({} encryption in a CFB container); {}",
            family_name(*family),
            reencrypt_remedy(*document)
        ),
        // Deliberately does NOT name a document kind: eight bytes of CFB magic are
        // `Document::Unknown`, and the variant carries no field to build one from.
        Error::NotAPlainPackage => "a CFB container, not a plain OOXML package; this \
             tool writes encryption around a package (.docx/.xlsx/.pptx), and there is \
             no writer for the 97-2003 binary formats"
            .to_string(),
        // The same sentence `decrypt`'s `route_for` gives these bytes: one fact, one
        // wording, whether the CLI's classification or the library's guard found it.
        Error::UnknownContainer => NOT_OFFICE.to_string(),
        // `EncryptParams` is forwarded **deliberately**, and this comment is the record
        // of that decision rather than an omission waiting to be fixed. Its `Display`
        // already reads as CLI copy: it names the `EncryptionInfo` attribute in
        // [MS-OFFCRYPTO]'s own spelling, says whose rule the value broke (the format's,
        // AES's, or this crate's margin), and prints the requested value beside the
        // accepted range. There is no Rust path in it -- the failure mode the header
        // above warns about -- and no remedy the CLI could word better than "pass a
        // number in that range".
        //
        // It is also unreachable from today's binary: there is no `--spin-count` or
        // `--key-bits` flag, so every encryption parameter this build uses is a
        // constant chosen here and already inside the bounds. The arm exists in
        // `exit_code` because a number must be returned for a variant that can arrive
        // through the library; the sentence does not, because nothing here can produce
        // it. When those flags arrive, this variant gets its own arm re-wording the
        // attribute as the flag the caller actually typed (`--spin-count`, not
        // `spinCount`), which is the one thing the library's message cannot know.
        //
        // WrongPassword, MissingStream, BadParameters, InvariantViolated, XmlParse,
        // CipherError, RandomSource, Io and any future variant: forwarded. Since
        // 0.1.0-rc.9 neither BadParameters nor UnsupportedAlgorithm carries text the file
        // chose (closed enums and integers); XmlParse is this crate's own wording.
        _ => e.to_string(),
    }
}

/// The one place an [`Error`] becomes a number.
///
/// `_` is **7**, not the sibling's 6: 6 asserts a fact about the *file* that a gap in
/// this table gives no basis for, while 7 says "this tool could not classify the
/// failure", which is true. A twentieth variant therefore lands on 7 with no compile
/// error here — the enum is `#[non_exhaustive]` and this is a separate crate — so the
/// coverage half of the proof is the exhaustive canary in `src/error.rs`'s own
/// `#[cfg(test)]` module, and the value half is `exit_codes_map_every_error_class`.
fn exit_code(e: &Error) -> u8 {
    match e {
        Error::NotACfbFile => EX_NOT_OFFICE,
        Error::MissingStream(_) => EX_MALFORMED,
        Error::BadParameters { .. } => EX_MALFORMED,
        // A fault of this crate's, not the file's: "could not classify the failure" is
        // not quite it, but 7 is the number that blames neither the file nor the caller.
        Error::InvariantViolated(_) => EX_INTERNAL,
        // Not malformed: a stream over a read cap of ours, as `PackageTooLarge` below.
        Error::StreamTooLarge { .. } => EX_REFUSED,
        Error::Io(_) => EX_IO,
        // `legacy-binary`, NOT `crypto-ops`: this variant does not exist in the plain
        // `cli` column, and copying the gate off a neighbouring arm breaks that build.
        #[cfg(feature = "legacy-binary")]
        Error::NotEncrypted => EX_REFUSED,
        // Unsupported, not malformed: the file is consistent about content this build
        // does not decrypt, and refusing beats handing back that content still encrypted.
        #[cfg(feature = "legacy-binary")]
        Error::UnsupportedEncryptedContent(_) => EX_UNSUPPORTED,
        Error::UnsupportedEncryptionVersion(_, _) => EX_UNSUPPORTED,
        Error::XmlParse(_) => EX_MALFORMED,
        Error::WrongPassword => EX_WRONG_PASSWORD,
        Error::CipherError => EX_MALFORMED,
        Error::UnsupportedAlgorithm { .. } => EX_UNSUPPORTED,
        Error::IntegrityCheckFailed => EX_INTEGRITY,
        Error::IntegrityElementMissing => EX_INTEGRITY,
        Error::IntegrityUnavailable(_) => EX_INTEGRITY,
        Error::RandomSource(_) => EX_INTERNAL,
        // The encrypt guard. 5 and 5 and 3, not one number: `AlreadyEncrypted` and
        // `NotAPlainPackage` are both "I recognise this and will not write into it",
        // while `UnknownContainer` is "wrong file" and shares `decrypt`'s 3 for the
        // same bytes. Collapsing them loses the distinction the help text promises.
        Error::AlreadyEncrypted { .. } => EX_REFUSED,
        Error::NotAPlainPackage => EX_REFUSED,
        Error::UnknownContainer => EX_NOT_OFFICE,
        // Not malformed: the file may be fine, and this path will not hold it.
        Error::PackageTooLarge { .. } => EX_REFUSED,
        // The only **caller** error in the table, and so the only 1. Every other arm is
        // a verdict on a file; this one is raised before a file is opened at all, from
        // the caller's own numbers against this crate's bounds.
        //
        // Not 6: `EX_MALFORMED` asserts a fact about a file -- "the bytes you gave me
        // are not a well-formed document" -- and there is frequently no file in hand
        // when this is raised, so 6 would be a claim about something that does not
        // exist. Not 9 either: `EX_UNSUPPORTED` means "this tool does not do that
        // *yet*", a build or a flag away from working, and a script may reasonably
        // retry elsewhere on it. A `spinCount` outside `0..=10_000_000` is not a
        // feature anyone can turn on; it is an impossible request, which is a bad
        // invocation, which is 1.
        Error::EncryptParams { .. } => EX_USAGE,
        _ => EX_INTERNAL,
    }
}

#[cfg(test)]
#[path = "msoffice-crypto_tests.rs"]
mod tests;

// --- temporaries that vanish with the process (#41) --------------------------------

/// A file being written that must not outlive the process unless it is kept.
///
/// A decrypt writes plaintext into it. Every failure this process sees drops it, which
/// removes it; what is left is a failure the process does not see -- a Ctrl-C, a hard
/// kill, a crash, the power -- and for those the file has to vanish by itself. Each
/// platform has its own way, and where none applies a Ctrl-C handler is the fallback:
///
/// | | while it is written | if the process dies |
/// | --- | --- | --- |
/// | Linux | no name at all (`O_TMPFILE`) | the kernel frees it |
/// | Windows | named, held delete-pending | closing the handle deletes it |
/// | fallback | named | a Ctrl-C handler removes it; a hard kill does not |
///
/// The fallback is macOS, and a Linux file system without `O_TMPFILE`.
struct Pending {
    file: Option<File>,
    how: How,
}

enum How {
    /// Linux `O_TMPFILE`: no name until [`Pending::keep_as`] gives it one.
    #[cfg(target_os = "linux")]
    Unnamed,
    /// Windows: named, with a delete disposition set on the handle. The name needs no
    /// keeping here: closing the handle is the cleanup.
    #[cfg(windows)]
    DeletePending,
    /// The fallback: a plain name, registered with the Ctrl-C handler.
    #[cfg(not(windows))]
    Named(PathBuf),
}

impl Pending {
    /// A pending file in `dir`, which is known by `name` if it needs a name before it is
    /// kept. Readable as well as writable, because an encrypt assembles a container in it.
    fn create(dir: &Path, name: &Path) -> std::io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{Mode, OFlags};
            use rustix::io::Errno;
            // 0o666 before the umask: what `File::create` asks for, so the kept file has
            // the permissions the target always had.
            match rustix::fs::open(
                dir,
                OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o666),
            ) {
                Ok(fd) => {
                    return Ok(Pending {
                        file: Some(File::from(fd)),
                        how: How::Unnamed,
                    })
                }
                // The file system or kernel has no `O_TMPFILE`: fall back to a name.
                Err(Errno::OPNOTSUPP | Errno::ISDIR | Errno::INVAL) => {}
                Err(e) => return Err(e.into()),
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                DELETE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
            };
            let _ = dir;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)
                // No sharing: nothing else opens the plaintext while it is written.
                .share_mode(0)
                .open(name)?;
            if let Err(e) = set_delete_disposition(&file, true) {
                drop(file);
                let _ = std::fs::remove_file(name);
                return Err(e);
            }
            Ok(Pending {
                file: Some(file),
                how: How::DeletePending,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = dir;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(name)?;
            interrupt::register(name);
            Ok(Pending {
                file: Some(file),
                how: How::Named(name.to_path_buf()),
            })
        }
    }

    fn file(&mut self) -> &mut File {
        // `Some` from `create` until `keep_as` consumes `self`.
        self.file
            .as_mut()
            .expect("a pending file is open until it is kept")
    }

    /// Flush the file to disk and give it `target`'s name, atomically: it passes through
    /// `name` (the temporary beside the target) and is renamed over `target`, so a reader
    /// sees either the old target or the finished one.
    fn keep_as(mut self, name: &Path, target: &Path) -> std::io::Result<()> {
        let file = self.file.take().expect("kept once");
        file.sync_all()?;
        match &self.how {
            #[cfg(target_os = "linux")]
            How::Unnamed => {
                use std::os::fd::AsRawFd;
                // A stale temporary from a run that predates this file -- or a fallback
                // run that was killed -- would make the link fail. Not a directory: that
                // is a real refusal, and `remove_file` leaves it for `linkat` to report.
                let _ = std::fs::remove_file(name);
                // Through /proc, because `AT_EMPTY_PATH` needs `CAP_DAC_READ_SEARCH` and
                // this runs unprivileged; `linkat(2)` documents this form for `O_TMPFILE`.
                let proc_path = format!("/proc/self/fd/{}", file.as_raw_fd());
                rustix::fs::linkat(
                    rustix::fs::CWD,
                    proc_path.as_str(),
                    rustix::fs::CWD,
                    name,
                    rustix::fs::AtFlags::SYMLINK_FOLLOW,
                )?;
                drop(file);
            }
            #[cfg(windows)]
            How::DeletePending => {
                set_delete_disposition(&file, false)?;
                // Closed before the rename: Windows will not move an open file.
                drop(file);
            }
            #[cfg(not(windows))]
            How::Named(_) => drop(file),
        }
        let renamed = std::fs::rename(name, target);
        if renamed.is_err() {
            let _ = std::fs::remove_file(name);
        }
        #[cfg(not(windows))]
        if let Some(path) = self.how.named() {
            interrupt::unregister(path);
        }
        // Nothing left for `Drop` to do: the file is the target now, or it is gone.
        self.how = How::kept();
        renamed
    }
}

impl How {
    /// The fallback's name, where this is the fallback. A function rather than an
    /// `if let` at each use: on macOS the fallback is the only variant, and the pattern
    /// would be irrefutable there.
    #[cfg(not(windows))]
    #[allow(unreachable_patterns)]
    fn named(&self) -> Option<&Path> {
        match self {
            How::Named(path) => Some(path),
            _ => None,
        }
    }

    /// What a kept `Pending` holds, so its `Drop` removes nothing: `Unnamed` and
    /// `DeletePending` have nothing to remove once the handle is closed, and the fallback's
    /// `Named` carries an empty path, which `Drop` skips.
    fn kept() -> Self {
        #[cfg(target_os = "linux")]
        {
            How::Unnamed
        }
        #[cfg(windows)]
        {
            How::DeletePending
        }
        #[cfg(all(not(windows), not(target_os = "linux")))]
        {
            How::Named(PathBuf::new())
        }
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        // Closing the handle is the cleanup on Linux (an unnamed file is freed) and on
        // Windows (a delete-pending file is deleted); a fallback name is removed here.
        drop(self.file.take());
        #[cfg(not(windows))]
        if let Some(path) = self.how.named() {
            if !path.as_os_str().is_empty() {
                let _ = std::fs::remove_file(path);
                interrupt::unregister(path);
            }
        }
    }
}

/// Set or clear the delete disposition on an open file: while set, closing the last
/// handle deletes the file, which is what a hard kill does.
///
/// `FILE_FLAG_DELETE_ON_CLOSE` at open would do the same, but it cannot be cleared, and a
/// decrypt that finishes must keep its file. The disposition can.
#[cfg(windows)]
#[allow(unsafe_code)]
fn set_delete_disposition(file: &File, delete: bool) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };
    let info = FILE_DISPOSITION_INFO { DeleteFile: delete };
    let size = u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>())
        .expect("a one-byte struct fits a u32");
    // SAFETY: the handle is `file`'s, open for the duration of the call and opened with
    // DELETE access; `info` is a live, correctly sized FILE_DISPOSITION_INFO, which is the
    // structure FileDispositionInfo names, and the call only reads it.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            std::ptr::from_ref(&info).cast(),
            size,
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// The fallback's Ctrl-C handler: the named temporaries in flight, removed on interrupt.
///
/// Paths only -- no plaintext, no key -- so a `static` holds nothing secret.
#[cfg(not(windows))]
mod interrupt {
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, Once};

    static IN_FLIGHT: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
    static INSTALL: Once = Once::new();

    pub(super) fn register(path: &Path) {
        INSTALL.call_once(|| {
            // If a handler cannot be installed the fallback is only as good as the
            // `Drop` that every failure the process sees still runs. Nothing to report.
            let _ = ctrlc::set_handler(|| {
                remove_all();
                std::process::exit(130);
            });
        });
        if let Ok(mut v) = IN_FLIGHT.lock() {
            v.push(path.to_path_buf());
        }
    }

    pub(super) fn unregister(path: &Path) {
        if let Ok(mut v) = IN_FLIGHT.lock() {
            v.retain(|p| p != path);
        }
    }

    /// Remove every registered temporary. What the handler runs; a function of its own so
    /// that a test can run it without sending a signal.
    pub(super) fn remove_all() {
        if let Ok(mut v) = IN_FLIGHT.lock() {
            for p in v.drain(..) {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}
