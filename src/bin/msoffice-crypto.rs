//! `msoffice-crypto` — classify, decrypt and encrypt Microsoft Office documents from a
//! shell.
//!
//! Plan: `docs/plans/msoffice-crypto-cli-2026-09-11.md`.
//!
//! Passwords never come from `argv`. There is deliberately no `--password VALUE`
//! argument, because `argv` is world-readable in a process listing for the lifetime of
//! the run. `--password` is registered anyway, hidden, purely so that reaching for it
//! produces an explanation rather than "unexpected argument".

use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(test)]
use std::path::Path;

use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};
use msoffice_crypto::{
    classify, decrypt_ooxml, AlgorithmParams, CipherAlgorithm, Classification, Container, Document,
    Error, Family, HashAlgorithm, IntegrityDeclaration, IntegrityPolicy,
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
// Ungated by design: from S4 the CLI's own classification layer produces 5 in every
// build (decrypt of an unencrypted file, encrypt of an already-encrypted one). Until
// that lands the only arm naming it is the `legacy-binary` one below, so the
// `cli`-without-`legacy-binary` column would warn. `expect`, not `allow`, so the
// attribute itself fails once S4 gives it a caller; `cfg_attr`, because the lint does
// not fire in the column where `Error::NotEncrypted` exists.
#[cfg_attr(
    all(not(test), not(feature = "legacy-binary")),
    expect(
        dead_code,
        reason = "S4 adds the CLI's own exit-5 refusals; remove this then"
    )
)]
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
                    .help("How hard to insist on a dataIntegrity tag"),
            ),
        )
        .subcommand(
            crypt_command("encrypt", "Encrypt a plaintext OOXML package", "encrypted").arg(
                Arg::new("format")
                    .long("format")
                    .value_name("FORMAT")
                    .value_parser(FORMAT_NAMES)
                    .default_value(FORMAT_NAMES[0])
                    .help(
                        "agile (Office 2010+, has a dataIntegrity HMAC) or standard (Office 2007)",
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

/// The remaining scaffold: `encrypt`'s grammar and its password wiring are real, the
/// writer is not here yet.
///
/// Exit 9 rather than 0 or 1: nothing was encrypted and nothing was written, and 9 is
/// the table's "this build cannot do it". Deleted by the slice named in the message.
///
/// **The message may not claim nothing was read.** Until this slice the `encrypt` arm
/// really was a no-op, and the wording said so. It is now reached only after `cmd_crypt`
/// has read the whole input file (`std::fs::read`) and resolved the password through
/// `read_password` -- opening a `--password-file`, reading a `--password-env` variable,
/// draining stdin or prompting on the terminal. Telling the user their password source
/// was never touched would be false, and a script or a person reading it would conclude
/// a `--password-file` on disk had not been opened when it had. Guarded by
/// `the_not_implemented_notice_does_not_claim_nothing_was_read` in tests/cli.rs.
fn not_implemented_yet(name: &str, slice: &str) -> u8 {
    eprintln!(
        "msoffice-crypto: `{name}` is not implemented in this build yet (plan slice \
         {slice}); your input file and password were read, but nothing was encrypted \
         and nothing was written."
    );
    EX_UNSUPPORTED
}

// --- classify -------------------------------------------------------------

fn cmd_classify(m: &ArgMatches) -> u8 {
    let file = m.get_one::<String>("file").expect("required by clap");
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("msoffice-crypto: cannot read {file}: {e}");
            // Through the one table rather than a literal EX_IO, so the CLI has exactly
            // one Error -> exit-code function from this slice onward.
            return exit_code(&Error::Io(e));
        }
    };
    // No `?`, no Result, no arm mapping "unknown" to a failure: `classify` answers
    // every input by contract (CLAUDE.md Design Value 1), so this always exits 0.
    let class = classify(&bytes);
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
        Document::WordBinary => "word-binary",
        Document::ExcelBinary => "excel-binary",
        Document::PowerPointBinary => "powerpoint-binary",
        Document::Unknown => "unknown",
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
    let mut line = |k: String, v: String| out.push_str(&format!("{k:<14}{v}\n"));
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
        // The sibling's idiom at width 14: `key-cipher:` is eleven characters and the
        // plan's sample aligns every value at column 15.
        let mut line = |k: &str, v: &str| out.push_str(&format!("{k:<14}{v}\n"));
        line("container:", container_name(c.container));
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
/// Only the prompt verb differs at this slice. `suffix()` -- the derived output name --
/// is S4's, deliberately not added here: with `derived_output` still `#[cfg(test)]` it
/// would be dead code in the one column that ships.
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
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("msoffice-crypto: cannot read {file}: {e}");
            return exit_code(&Error::Io(e));
        }
    };

    // A plain `String`, not a secure-gate wrapper, and that is the documented boundary:
    // the secure-gate skill puts the password argument of the public decrypt API outside
    // what is wrapped, and nothing here may print it.
    let password = match read_password(source, dir) {
        Ok(p) => p,
        Err(code) => return code,
    };

    match dir {
        Direction::Decrypt => {
            // S3's seam, deliberately the narrowest decrypt that can prove the password
            // arrived: no `classify` dispatch, no `legacy-binary` arm, no `--integrity`
            // and no output handling -- all four are S4's (issue #5). `decrypt_ooxml` is
            // `decrypt_ooxml_with_policy` under the library's own fail-closed default,
            // which is exactly what `--integrity` will make selectable, so S4 substitutes
            // one call rather than rewriting this arm. Until it lands, a plain or non-CFB
            // input is reported in the library's words and exits 3; the CLI's own "not
            // encrypted, nothing to decrypt" (exit 5) arrives with the classification.
            match decrypt_ooxml(&bytes, &password) {
                Ok(package) => {
                    eprintln!(
                        "msoffice-crypto: decrypted {file} ({} bytes); this build does not \
                         write output yet (plan slice S4), so -o was ignored and nothing \
                         was written.",
                        package.len()
                    );
                    EX_OK
                }
                Err(e) => {
                    eprintln!("msoffice-crypto: {e}");
                    exit_code(&e)
                }
            }
        }
        Direction::Encrypt => not_implemented_yet("encrypt", "S5"),
    }
}

// --- output paths ---------------------------------------------------------

/// `report.docx` -> `report.decrypted.docx`. A file with no extension gets the suffix
/// appended, so `report` -> `report.decrypted`.
///
/// `#[cfg(test)]` until S4 wires the output tail that calls it — the gate is the
/// reminder that the flip is due, the same way `dataspaces` and `encryption_info` were
/// gated until `encrypt_ooxml` became their production caller.
#[cfg(test)]
fn derived_output(input: &Path, suffix: &str) -> PathBuf {
    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
    let name = match input.extension() {
        Some(ext) => format!("{stem}.{suffix}.{}", ext.to_string_lossy()),
        None => format!("{stem}.{suffix}"),
    };
    input.with_file_name(name)
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
            // and well under this crate's 1.85 MSRV -- no `atty`, no `is-terminal`.
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

/// The one place an [`Error`] becomes a number.
///
/// `_` is **7**, not the sibling's 6: 6 asserts a fact about the *file* that a gap in
/// this table gives no basis for, while 7 says "this tool could not classify the
/// failure", which is true. A fifteenth variant therefore lands on 7 with no compile
/// error here — the enum is `#[non_exhaustive]` and this is a separate crate — so the
/// coverage half of the proof is the exhaustive canary in `src/error.rs`'s own
/// `#[cfg(test)]` module, and the value half is `exit_codes_map_every_error_class`.
fn exit_code(e: &Error) -> u8 {
    match e {
        Error::NotACfbFile => EX_NOT_OFFICE,
        Error::MissingStream(_) => EX_MALFORMED,
        Error::BadParameters(_) => EX_MALFORMED,
        Error::Io(_) => EX_IO,
        // `legacy-binary`, NOT `crypto-ops`: this variant does not exist in the plain
        // `cli` column, and copying the gate off a neighbouring arm breaks that build.
        #[cfg(feature = "legacy-binary")]
        Error::NotEncrypted => EX_REFUSED,
        Error::UnsupportedEncryptionVersion(_, _) => EX_UNSUPPORTED,
        Error::XmlParse(_) => EX_MALFORMED,
        Error::WrongPassword => EX_WRONG_PASSWORD,
        Error::CipherError => EX_MALFORMED,
        Error::UnsupportedAlgorithm { .. } => EX_UNSUPPORTED,
        Error::IntegrityCheckFailed => EX_INTEGRITY,
        Error::IntegrityElementMissing => EX_INTEGRITY,
        Error::IntegrityUnavailable(_) => EX_INTEGRITY,
        Error::RandomSource(_) => EX_INTERNAL,
        _ => EX_INTERNAL,
    }
}

#[cfg(test)]
#[path = "msoffice-crypto_tests.rs"]
mod tests;
