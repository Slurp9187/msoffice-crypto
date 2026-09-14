//! `msoffice-crypto` — classify, decrypt and encrypt Microsoft Office documents from a
//! shell.
//!
//! Plan: `docs/plans/msoffice-crypto-cli-2026-09-11.md`.
//!
//! Passwords never come from `argv`. There is deliberately no `--password VALUE`
//! argument, because `argv` is world-readable in a process listing for the lifetime of
//! the run. `--password` is registered anyway, hidden, purely so that reaching for it
//! produces an explanation rather than "unexpected argument".

use std::process::ExitCode;

#[cfg(test)]
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};
use msoffice_crypto::{
    classify, AlgorithmParams, CipherAlgorithm, Classification, Container, Document, Error, Family,
    HashAlgorithm, IntegrityDeclaration, IntegrityPolicy,
};

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
                .after_help(
                    "classify cannot fail. An unencrypted package prints `encrypted: no` \
                     and sixteen bytes of junk print `container: unknown`; both exit 0, \
                     because both are answers. Only a file that cannot be read exits 2.",
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
        Some(("decrypt", _)) => not_implemented_yet("decrypt", "S4"),
        Some(("encrypt", _)) => not_implemented_yet("encrypt", "S5"),
        _ => EX_USAGE,
    }
}

/// The S1 scaffold: the grammar is real, the work is not here yet.
///
/// Exit 9 rather than 0 or 1: nothing was decrypted and nothing was written, and 9 is
/// the table's "this build cannot do it". Deleted by the slice named in the message.
fn not_implemented_yet(name: &str, slice: &str) -> u8 {
    eprintln!(
        "msoffice-crypto: `{name}` is not implemented in this build yet (plan slice \
         {slice}); nothing was read and nothing was written."
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
    print!("{}", classification_human(&classify(&bytes)));
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

/// A password file written by an editor ends with a newline that is not part of the
/// password. Strips one trailing CR-LF or LF, and nothing else — trailing spaces are
/// kept, because they can be deliberate.
///
/// `#[cfg(test)]` until S3 wires `--password-file` and `--password-stdin`.
#[cfg(test)]
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
