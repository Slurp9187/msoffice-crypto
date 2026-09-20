//! Detects, decrypts and encrypts Microsoft Office documents in the formats
//! [MS-OFFCRYPTO] defines.
//!
//! This crate's job is password-protected Word, Excel and PowerPoint files: the OOXML
//! packages (`.docx` / `.xlsx` / `.pptx`) Office wraps in a CFB container when a
//! password is set, and — behind the `legacy-binary` feature — the 97-2003 binaries
//! (`.doc` / `.xls` / `.ppt`). It is not a general CFB or ZIP library, not a reader of
//! certificate-based (`CertificateKeyEncryptor`) wrapping, and not affiliated with,
//! endorsed by, or sponsored by Microsoft; see [Trademarks](#trademarks).
//!
//! The public surface is re-exported at the crate root. Detection types
//! ([`Classification`], [`Family`], [`IntegrityDeclaration`]) compile into every build.
//! `decrypt_ooxml`, `encrypt_ooxml`, `check_encryptable`, `Error`, `IntegrityPolicy` and
//! `IntegrityOutcome` exist only under `crypto-ops`; `decrypt_binary_office` exists
//! only under `legacy-binary`. Those names are not linked from this page because this
//! crate-level document renders in the detection-only build, where they are absent.
//!
//! - **Agile encryption** (Office 2010+, `vMajor=4` `vMinor=4`): AES-CBC in the files this
//!   crate reads and writes ([MS-OFFCRYPTO] §2.3.4.10 also names CFB and other ciphers;
//!   those are refused as unimplemented). The key derivation runs whichever of SHA-1 /
//!   SHA-256 / SHA-384 / SHA-512 the file names — read separately from `<keyData>` and
//!   `<p:encryptedKey>`, so that a file whose two elements disagree still decrypts under
//!   the hash each half was written with. A writer MUST make them match (§2.3.4.10); a
//!   reader that assumes they do silently uses the wrong hash on whichever half it
//!   guessed. SHA-512 is what Office 16 writes; a file naming another is not a wrong
//!   password.
//! - **Standard encryption** (Office 2007, `vMajor` 2/3/4 with `vMinor=2` and `fAES` set):
//!   AES in ECB under a SHA-1 KDF of 50,000 iterations ([MS-OFFCRYPTO] §2.3.4.7). The
//!   header (§2.3.4.5) declares AES-128, AES-192 or AES-256; this crate reads and writes
//!   AES-128, which is Office's default. SHA-1, ECB and the iteration count are fixed by
//!   the KDF; the key length is not.
//!
//! Both OOXML formats use a CFB container (magic: `D0 CF 11 E0 A1 B1 1A E1`). The
//! decrypted output of the modern path is the original OOXML ZIP.
//!
//! # Getting started
//!
//! [`classify()`] is the first call on bytes that have not been vetted. It never panics
//! and never returns an error: every unreadable shape collapses to [`Family::Unknown`].
//! [`is_cfb_office`] is the cheaper CFB-magic check when that is all that is needed.
//!
//! Decrypting and encrypting need the `crypto-ops` feature. The 97-2003 binaries need
//! `legacy-binary`, a superset of `crypto-ops`.
//!
//! # Examples
//!
//! ```
//! use msoffice_crypto::{classify, Container, Family, IntegrityDeclaration};
//!
//! let class = classify(include_bytes!("../tests/fixtures/agile_encrypted.docx"));
//! assert_eq!(class.container, Container::Cfb);
//! assert_eq!(class.family, Family::Agile);
//! assert_eq!(class.data_integrity, IntegrityDeclaration::Declared);
//! assert!(class.is_encrypted());
//! assert!(class.is_supported());
//! ```
//!
//! Decrypting needs `crypto-ops`. The example compiles as an empty test without that
//! feature, and runs against the shipped agile fixture with it:
//!
//! ```
//! # #[cfg(feature = "crypto-ops")]
//! # fn doctest() -> Result<(), msoffice_crypto::Error> {
//! use msoffice_crypto::decrypt_ooxml;
//!
//! let package = decrypt_ooxml(
//!     include_bytes!("../tests/fixtures/agile_encrypted.docx"),
//!     "testpass",
//! )?;
//! assert!(package.starts_with(b"PK\x03\x04"));
//! # Ok(())
//! # }
//! # #[cfg(feature = "crypto-ops")]
//! # doctest().unwrap();
//! ```
//!
//! # Two builds
//!
//! **Detection is the default build.** [`classify()`] and [`is_cfb_office`] answer what a
//! file is — container shape, encryption family, the algorithm tuple it declares, and
//! whether it carries a `dataIntegrity` element — with no cryptographic dependency at
//! all. `cargo add msoffice-crypto` installs that and nothing more.
//!
//! **Decryption and encryption are the `crypto-ops` feature.** `decrypt_ooxml`,
//! `decrypt_ooxml_with_policy`, `encrypt_ooxml`, `encrypt_ooxml_standard`,
//! `check_encryptable`, the `Decrypted` struct and the `IntegrityPolicy` /
//! `IntegrityOutcome` enums live behind it, together with `aes`, `cbc`, `ecb`, `sha1`,
//! `sha2`, `hmac`, `base64` and `rand`:
//!
//! ```toml
//! msoffice-crypto = { version = "0.1.0-rc.4", features = ["crypto-ops"] }
//! ```
//!
//! <div class="warning">
//!
//! **If you see** `cannot find type Error in crate msoffice_crypto`, this is the
//! feature you are missing.
//!
//! To be exact about what is gated, because the imprecise version misleads: the error
//! *type* compiles in every configuration — every variant payload is a `&'static str`,
//! `String`, `u16`, `std::io::Error` or a fieldless `Copy` enum from the detection half
//! (`Family`, `Document`), so it costs the detection build nothing but `thiserror` — and
//! it is only the `pub use` that `crypto-ops` gates. The reason is not
//! that the type needs a cipher. It is that once the crypto-only variants are gated, an
//! ungated re-export would be a public type whose *shape* changes with a feature the
//! consumer cannot see from the name, in a build where `classify()` is infallible and
//! nothing produces it.
//!
//! The first crate to wire against this reported that the failure surfaces on a function
//! signature naming `Error`, which reads as a plumbing mistake rather than a missing
//! feature. The diagnostic cannot be improved from inside the crate: a `compile_error!`
//! on "no cryptography features" would break the detection-only build, which is a
//! supported configuration and the default one.
//!
//! </div>
//!
//! `secure-gate` — this crate's zeroizing primitive — rides on `crypto-ops` as well: the
//! detection build holds no key material. No secure-gate type crosses the public API,
//! by design; the password is `&str` and the plaintext is `Vec<u8>`. Key material derived
//! inside the crate is zeroized on drop; the password you pass and the plaintext you
//! receive are yours to wipe.
//!
//! **The 97-2003 binary formats are the `legacy-binary` feature**, a superset of
//! `crypto-ops`. `decrypt_binary_office` reads a `.doc`, `.xls` or `.ppt` protected
//! with RC4 CryptoAPI ([MS-OFFCRYPTO] §2.3.5), Office 97/2000 RC4 (§2.3.6) or, for a
//! workbook, XOR obfuscation (§2.3.7), and adds `rc4` and `md-5` — the two primitives
//! nothing modern needs — to that build alone:
//!
//! ```toml
//! msoffice-crypto = { version = "0.1.0-rc.4", features = ["legacy-binary"] }
//! ```
//!
//! # Bounds on untrusted input
//!
//! Every number below is read from a file an attacker may have written, so each one is
//! capped. A declared size is an allocation request and an iteration count is a promise
//! of work; neither is believed. The values are listed because a consumer sizing its own
//! limits, or deciding whether this crate can be handed a particular document, should not
//! have to ask. **They are internal constants (`src/limits.rs`, all `pub(crate)`), not
//! public API** — they are quoted here for discoverability and may tighten in any
//! release.
//!
//! Compiled into **every build**, because `classify` reads them before anything is
//! authenticated: the `EncryptionInfo` stream is read to at most 1 MiB, a 97-2003 binary
//! header to 512 bytes, the `.xls` BIFF scan to 1 MiB, `/Current User` to 256 bytes, and
//! the PowerPoint persist directory to 8 MiB across at most 2^20 objects — that last
//! figure being the spec's own, since `persistId` is 20 bits ([MS-PPT] § 2.3.5), not a
//! margin this crate chose.
//!
//! Under **`crypto-ops`**: a package is at most **1 GiB** in either direction — the same
//! ceiling refuses an oversized `EncryptedPackage` on read and an oversized `package` on
//! write, so a file this crate writes is a file it can read back. `spinCount` is capped
//! at **2^21**, deliberately far below the 10 000 000 the spec permits and about 21× the
//! 100 000 Office writes; uncapped it is roughly fifty minutes of one core, which no
//! `Result` can report. Agile key sizes are 128, 192 or 256 bits, salts 1..=65536 bytes,
//! and the standard path accepts AES-128 only.
//!
//! Under **`legacy-binary`**: RC4 key sizes 40..=128 bits (the spec's own range,
//! [MS-OFFCRYPTO] § 2.3.5.1) and an XOR-obfuscation password of at most 15 characters,
//! which is structural rather than a margin — the `InitialCode` table has exactly 15
//! entries.
//!
//! # Trademarks
//!
//! Microsoft, Microsoft Office, Word, Excel and PowerPoint are trademarks of Microsoft
//! Corporation. This crate is not affiliated with, endorsed by, or sponsored by
//! Microsoft; it is an independent implementation of the [MS-OFFCRYPTO] formats and uses
//! those names only to describe what it reads and writes.
//!
//! # A note on `GH #N` in the source
//!
//! Comments throughout this crate cite issues as `GH #4`, `GH #13` and so on. Those
//! numbers belong to the **private repository this crate was developed in**, which is
//! archived and is not this one — they are not issues in the published repository and
//! will not resolve there.
//!
//! They are kept because the surrounding sentence usually needs them to make sense: the
//! reason a guard is shaped the way it is, or the change that made a hardcoded value
//! configurable, is often the only record of why an obvious-looking simplification is
//! wrong. `docs/design/development-record.md` in the repository is the index that maps every one
//! of them to what it was, alongside the decisions that were reversed and the negative
//! results worth not repeating. Plan slice identifiers (`S1`–`S12`) appear beside many of
//! them and are defined in the same place.

// Feature badges on docs.rs. Two thirds of this crate's public surface is behind
// `crypto-ops` or `legacy-binary`, and without this rustdoc renders `decrypt_ooxml`
// beside `classify` with nothing to say one needs a feature and the other does not — a
// reader takes the default build and gets a compile error the docs did not predict.
// § *Two builds* above says it in prose; this says it per item, which is where a reader
// actually looks.
//
// `doc_cfg` in its auto mode rather than annotating each item with `doc(cfg(..))`: the badge is
// derived from the `#[cfg]` that is already there, so an item that changes features
// cannot keep a stale badge, and adding a gated item cannot forget one. Nightly-only and
// inert without `--cfg docsrs`, which only docs.rs and the `docsrs` CI job pass — stable
// builds, the MSRV job and `cargo test` never see it.
#![cfg_attr(docsrs, feature(doc_cfg))]
// The crate has never contained an `unsafe` block, and this is what turns that from a
// fact about today's source into a property a reviewer does not have to re-check. It is
// the one claim in § *Every input is hostile* that the compiler can enforce on its own:
// the parsers are handed bytes an attacker chose, so memory unsafety here is reachable by
// anyone who can hand a caller a file. `forbid` rather than `deny` on purpose -- `deny` is
// overridable by an inner `#[allow]`, which is exactly the edit that would need to be
// noticed, and `forbid` makes that edit a compile error instead of a diff to catch.
//
// It binds the whole crate, dependencies excluded: `cfb`, `quick-xml` and the RustCrypto
// stack each answer for their own, and `cargo deny` is what watches them.
#![forbid(unsafe_code)]

mod binary_office;
mod cfb_reader;
mod classify;
mod error;
mod limits;

// The 97-2003 binary formats, GH #4: the container they are decrypted inside, the
// three cipher families, and one module per application format. A `//` comment, not a
// `///` one: this describes the eight modules below, and as rustdoc it would become
// `excel97`'s alone and be prepended to that module's own header.
#[cfg(feature = "legacy-binary")]
mod excel97;
#[cfg(feature = "legacy-binary")]
mod legacy_container;
#[cfg(feature = "legacy-binary")]
mod powerpoint97;
#[cfg(feature = "legacy-binary")]
mod rc4;
#[cfg(feature = "legacy-binary")]
mod rc4_cryptoapi;
#[cfg(feature = "legacy-binary")]
mod rc4_office97;
#[cfg(feature = "legacy-binary")]
mod word97;
#[cfg(feature = "legacy-binary")]
mod xor_obfuscation;

#[cfg(feature = "crypto-ops")]
mod agile;
/// The agile write path: the password encryptor (the inverse of
/// `agile::verify_password`), the package encryptor, and the assembly behind
/// [`encrypt_ooxml`]. Where `secure-gate`'s `rand` turns on.
#[cfg(feature = "crypto-ops")]
mod agile_encrypt;
/// The `\x06DataSpaces` subtree and the CFB container that carries it — the write half
/// of the format, promoted out of `tests/` in GH #6 step 1 so the byte-identity proof
/// covers the code the encrypt path will call rather than a copy of it.
///
/// `cfg(test)` until GH #6 step 6 made [`encrypt_ooxml`] its production caller — the
/// gate was the reminder that the flip was due, and it fired on schedule.
#[cfg(feature = "crypto-ops")]
mod dataspaces;
/// Serialise the agile `EncryptionInfo` stream — the inverse of `agile`'s parser, and the
/// half GH #6 step 3 added. Shaped byte-for-byte on what Word 16 writes.
#[cfg(feature = "crypto-ops")]
mod encryption_info;
/// The four hash algorithms an agile file may name, as operations rather than as a
/// label. The enum itself lives in `classify`, which must report the hash in a build
/// with no cipher crate at all; this is the `crypto-ops` half.
#[cfg(feature = "crypto-ops")]
mod hash;
#[cfg(feature = "crypto-ops")]
mod integrity;
/// The 4096-byte segment layout the agile package is encrypted in, with each segment's
/// IV. One segmentation shared by decrypt and, from GH #6 step 4, encrypt — plan D4.
#[cfg(feature = "crypto-ops")]
mod segments;
#[cfg(feature = "crypto-ops")]
mod sensitive;
#[cfg(feature = "crypto-ops")]
mod standard;
/// The standard (Office 2007) write path: the salt, the derived key, the two verifier
/// blobs, the binary header, and the assembly behind [`encrypt_ooxml_standard`]. Runs on
/// `standard`'s own KDF and ECB helper, so the two directions share one derivation.
#[cfg(feature = "crypto-ops")]
mod standard_encrypt;

/// Malformed-parameter tests: every number a file declares about itself must produce an
/// error rather than a panic or a hang. Test-only, and separate from the fixture tests
/// below because it needs a synthetic container builder those have no use for.
#[cfg(all(test, feature = "crypto-ops"))]
mod malformed_input;

/// The same discipline for the binary formats: every offset and length a `.doc`, `.xls`
/// or `.ppt` declares, poisoned one at a time, with a control beside each.
#[cfg(all(test, feature = "legacy-binary"))]
mod legacy_malformed;

pub use classify::{
    classify, AlgorithmParams, CipherAlgorithm, Classification, Container, ContainerRead, Document,
    Family, HashAlgorithm, IntegrityDeclaration,
};
/// Gated with the functions that return it. In a detection-only build no public
/// function returns a `Result`, so an ungated re-export was a public type nothing
/// produced — and, once its crypto-only variants were gated, a type whose public shape
/// depended on a feature the consumer could not see from the name. See the enum's doc.
#[cfg(feature = "crypto-ops")]
pub use error::Error;
#[cfg(feature = "crypto-ops")]
pub use integrity::{IntegrityOutcome, IntegrityPolicy};

/// What [`decrypt_ooxml_with_policy`] returns: the package, and what was established
/// about it.
///
/// A struct rather than the `(Vec<u8>, IntegrityOutcome)` this returned until the first
/// consumer wired against it, for two reasons that only showed up at a real call site.
///
/// **Arity.** A tuple freezes the number of facts at publication. There are two here and
/// a plausible third — which cipher a file actually used, which spec branch it parsed as
/// — and adding one to a tuple is a breaking change for every caller, while adding a
/// field to a `#[non_exhaustive]` struct is not. `#[non_exhaustive]` is free before the
/// first publish and impossible to add afterwards without the same break, which is why
/// this is the shape that ships.
///
/// **Prominence.** [`Self::integrity`] is not a detail attached to the bytes; for a
/// caller that stores what it decrypts it is the predicate deciding whether the bytes may
/// be kept at all. `let (package, _) = ...` is eight characters and reads as idiom rather
/// than as a decision, and this crate's own [`decrypt_ooxml`] is the demonstration — it is
/// the one place that consumes this and it discards the outcome. That is correct *there*,
/// because that wrapper exists to be the "I do not need to ask" path, which is exactly
/// what made it the wrong default shape for everyone else. As a field the check reads as
/// `decrypted.integrity`, named at every call site and in every review diff.
///
/// There is deliberately no `require_verified()` helper. [`IntegrityPolicy::Require`]
/// already refuses unauthenticated plaintext *before* any work is done, and a second
/// gate after the fact would have to invent an error variant for "the policy allowed this
/// but I changed my mind", which is not a fact about the file.
#[cfg(feature = "crypto-ops")]
#[derive(Debug)]
#[non_exhaustive]
pub struct Decrypted {
    /// The decrypted package: the plain `.docx` / `.xlsx` / `.pptx` ZIP.
    ///
    /// **Not zeroized on drop**, deliberately and unlike this crate's key material. It is
    /// a document, its size is the file's, and a caller that needs it wiped knows that
    /// better than this crate does — wrap it at the boundary. No `secure-gate` type
    /// crosses this API by design; see the crate docs.
    pub package: Vec<u8>,

    /// What was established about [`Self::package`]'s integrity.
    ///
    /// Ask [`IntegrityOutcome::is_authenticated`] rather than matching: the enum is
    /// `#[non_exhaustive]`, so a wildcard arm in a caller's `match` cannot know which side
    /// a future variant belongs on, and that predicate can.
    pub integrity: IntegrityOutcome,
}

/// Returns `true` if `data` begins with the CFB magic `D0 CF 11 E0 A1 B1 1A E1`.
///
/// A Word / Excel / PowerPoint file encrypted via File → Protect → Encrypt with Password
/// becomes a CFB container; the ZIP magic (`PK\x03\x04`) is replaced by the CFB magic.
/// This is only a prefix check: a truncated or corrupt container that still starts with
/// those eight bytes returns `true`, and [`classify()`] is what reports whether the rest
/// can be read.
///
/// # Examples
///
/// ```
/// use msoffice_crypto::is_cfb_office;
///
/// assert!(is_cfb_office(include_bytes!("../tests/fixtures/agile_encrypted.docx")));
/// assert!(!is_cfb_office(include_bytes!("../tests/fixtures/plain.docx")));
/// assert!(!is_cfb_office(b"PK\x03\x04"));
/// ```
///
/// # See Also
///
/// [`classify()`] reports container, family and integrity declaration together.
pub fn is_cfb_office(data: &[u8]) -> bool {
    data.len() >= 8 && data[..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
}

/// Decrypt a password-protected OOXML file to the original ZIP package.
///
/// Supports agile encryption (Office 2010+) and standard encryption (Office 2007).
/// Returns the decrypted OOXML ZIP bytes (a valid `.docx` / `.xlsx` / `.pptx` package).
///
/// Integrity is checked under [`IntegrityPolicy::RequireWhereDefined`], the default, and
/// it **fails closed**: an agile file must carry a `dataIntegrity` tag and it must match,
/// or the file is refused. ECMA-376 standard encryption defines no such element and still
/// decrypts. Use [`decrypt_ooxml_with_policy`] to demand a tag of every format, to accept
/// an agile file that lacks one, to skip the check, or to learn which of those happened.
///
/// The password is `&str` and the returned plaintext is a plain `Vec<u8>`, by design: no
/// `secure-gate` type crosses this boundary. Key material derived inside the crate is
/// zeroized on drop; the password you pass and the package you receive are yours to wipe.
///
/// On error, `data` is left untouched and no plaintext is produced. The agile HMAC covers
/// ciphertext and is checked before decryption, so a failed integrity check never yields
/// unauthenticated bytes.
///
/// # Errors
///
/// - [`Error::NotACfbFile`] — `data` is not a CFB container
/// - [`Error::MissingStream`] — `EncryptionInfo` or `EncryptedPackage` is
///   absent, unreadable, or shorter than its header
/// - [`Error::XmlParse`] — the agile `EncryptionInfo` XML is malformed, a
///   required attribute is missing, or the file carries only `CertificateKeyEncryptor`
///   elements and no `PasswordKeyEncryptor` (this crate opens password-protected
///   documents only)
/// - [`Error::BadParameters`] — a declared length, spin count, reserved word
///   or sibling field is out of range or inconsistent
/// - [`Error::WrongPassword`] — password verification failed
/// - [`Error::IntegrityCheckFailed`] — the package does not match its HMAC
/// - [`Error::IntegrityElementMissing`] — the file declares agile encryption
///   but carries no `dataIntegrity` element to check it against
/// - [`Error::UnsupportedAlgorithm`] — the file names a cipher or hash this
///   crate does not implement. Never reported as a wrong password: the password may be
///   correct and simply unusable
/// - [`Error::UnsupportedEncryptionVersion`] — a version pair this crate does
///   not implement
/// - [`Error::CipherError`] — an AES operation rejected a block (a length that
///   is not a block multiple, typically a truncated stream)
/// - [`Error::Io`] — reading the in-memory container failed
///
/// [`Error::IntegrityUnavailable`] is not reachable here: that variant is
/// [`IntegrityPolicy::Require`] on a format that defines no tag, and this function uses
/// the default policy.
///
/// # Examples
///
/// ```
/// use msoffice_crypto::decrypt_ooxml;
///
/// let package = decrypt_ooxml(
///     include_bytes!("../tests/fixtures/agile_encrypted.docx"),
///     "testpass",
/// )?;
/// assert!(package.starts_with(b"PK\x03\x04"));
/// # Ok::<(), msoffice_crypto::Error>(())
/// ```
///
/// A wrong password is a distinct variant from a tampered package:
///
/// ```
/// use msoffice_crypto::{decrypt_ooxml, Error};
///
/// let err = decrypt_ooxml(
///     include_bytes!("../tests/fixtures/agile_encrypted.docx"),
///     "wrongpass",
/// )
/// .unwrap_err();
/// assert!(matches!(err, Error::WrongPassword));
/// ```
///
/// # See Also
///
/// [`decrypt_ooxml_with_policy`] chooses the HMAC policy and reports
/// [`IntegrityOutcome`]. [`encrypt_ooxml`] is the inverse for the agile tuple Office 16
/// writes. [`classify()`] is the pre-flight that does not decrypt.
#[cfg(feature = "crypto-ops")]
pub fn decrypt_ooxml(data: &[u8], password: &str) -> Result<Vec<u8>, Error> {
    decrypt_ooxml_with_policy(data, password, IntegrityPolicy::default()).map(|d| d.package)
}

/// Refuse, before a password is asked for, anything [`encrypt_ooxml`] and
/// [`encrypt_ooxml_standard`] will refuse.
///
/// **This is the same function those two call**, not a second copy that agrees with them:
/// each opens with `check_encryptable(package)?`. A caller that runs it and gets `Ok(())`
/// is not promised the encryption will succeed — the payload ceiling and the system RNG
/// are still ahead — but it is promised that the *shape* of the input will not be what
/// stops it.
///
/// It exists because the alternative is asking for a password first. Prompting for a new
/// password, or reading one from a keychain, for a file that is about to be refused is a
/// question the user answers for nothing, and on an interactive path it is the part of a
/// refusal that cannot be taken back. This crate's own CLI calls it in that position; so
/// did a consumer that had to write its own copy before this existed.
///
/// **Exactly one thing is encryptable: a plain OOXML package**, which [`classify()`]
/// reports as [`Container::Zip`] for every `PK` signature it knows. Four bytes of magic
/// are the whole test — no entry is read and no content type is examined, so a `.vsdx`, a
/// `.jar` and a backup archive all pass here (see [`Document::ZipArchive`]). That is the
/// honest limit of what was checked, and encrypting a ZIP that is not an Office package
/// harms nobody: the result is a container whose payload the caller chose. What is
/// refused is everything that would produce a *misleading* artifact — above all a second
/// wrap around a file that is already encrypted.
///
/// # Errors
///
/// - [`Error::AlreadyEncrypted`] — a CFB container that already carries a
///   password-to-open. The payload names the family and document kind, for a caller
///   choosing its own words
/// - [`Error::NotAPlainPackage`] — a CFB container that does not: a 97-2003 binary
///   document, or one this crate could not read
/// - [`Error::UnknownContainer`] — neither a ZIP package nor a CFB container
///
/// # Examples
///
/// ```
/// use msoffice_crypto::{check_encryptable, encrypt_ooxml, Error};
///
/// // Ask before the prompt, not after.
/// let package = include_bytes!("../tests/fixtures/plain.docx");
/// check_encryptable(package)?;
/// let password = "correct horse battery staple"; // …whatever asking cost you
/// let sealed = encrypt_ooxml(package, password)?;
///
/// // And the answer for bytes that were never worth asking about:
/// assert!(matches!(
///     check_encryptable(&sealed),
///     Err(Error::AlreadyEncrypted { .. })
/// ));
/// # Ok::<(), msoffice_crypto::Error>(())
/// ```
///
/// # See Also
///
/// [`classify()`] is the full pre-flight; this is the one question the encrypt path asks
/// of it. Every public encrypt entry point this crate gains must call this.
// No `#[must_use]`: `Result` already carries it, and adding a second fires
// `clippy::double_must_use`, which is `-D warnings` in all five feature columns.
#[cfg(feature = "crypto-ops")]
pub fn check_encryptable(package: &[u8]) -> Result<(), Error> {
    let class = classify(package);
    // Exhaustive without a `_` arm: `Container` is `#[non_exhaustive]` only to other
    // crates, so a variant added later is `E0004` right here and someone has to decide
    // what it is, rather than it defaulting into "encryptable" or into one refusal.
    match class.container {
        Container::Zip => Ok(()),
        Container::Cfb if class.is_encrypted() => Err(Error::AlreadyEncrypted {
            family: class.family,
            document: class.document,
        }),
        Container::Cfb => Err(Error::NotAPlainPackage),
        Container::Unknown => Err(Error::UnknownContainer),
    }
}

/// Encrypt an OOXML package with a password, producing the CFB container Office writes.
///
/// `package` is the plain `.docx` / `.xlsx` / `.pptx` ZIP. The result is ECMA-376 agile
/// encryption in the one tuple Office 16 itself writes — AES-256-CBC, SHA-512, a
/// 100 000-round spin count — with a `dataIntegrity` HMAC over the `EncryptedPackage`
/// ciphertext, including the 8-byte size prefix ([MS-OFFCRYPTO] §2.3.4.14), and it
/// is what [`decrypt_ooxml`] reads back under its fail-closed default. Every step of the
/// write path has been checked byte for byte against real Office output where Office's
/// own random inputs could be recovered: the `EncryptionInfo` document and the two
/// `dataIntegrity` blobs reproduce Word's, Excel's and PowerPoint's exactly.
///
/// **The profile is fixed, and both halves of that are load-bearing for a caller.** The
/// spin count is 100 000 with no parameter to change it — there is no overload, no
/// builder and no environment variable, because the one tuple Office writes is the whole
/// point of this function. And a `<dataIntegrity>` element is written **unconditionally**:
/// every artifact this function produces declares one, so a consumer checking
/// [`Classification::data_integrity`] on agile output from here may assert
/// [`IntegrityDeclaration::Declared`] and know the assertion cannot fail. Neither
/// guarantee extends to [`encrypt_ooxml_standard`], whose format defines no such element.
///
/// The session key, block keys and spin hash are held in `secure-gate` wrappers and
/// zeroized on drop; the password is `&str` and the input and output are plain bytes, by
/// design. Randomness comes from the operating system's CSPRNG through the same function
/// the seeded golden tests drive, so those tests are about this code path.
///
/// On error, nothing is written: the function returns without a container.
///
/// # Errors
///
/// - [`Error::AlreadyEncrypted`], [`Error::NotAPlainPackage`],
///   [`Error::UnknownContainer`] — `package` is not a plain OOXML package. Checked by
///   [`check_encryptable`] before anything else, so a caller can ask the same question
///   before it pays for a password
/// - [`Error::BadParameters`] — `package` is over the 1 GiB this crate would
///   read back
/// - [`Error::RandomSource`] — the system RNG would not produce bytes
/// - [`Error::CipherError`] — an AES-CBC step rejected a block (an internal
///   length invariant, not a property of a well-formed `package`)
/// - [`Error::Io`] — the in-memory container could not be written
///
/// # Examples
///
/// ```
/// use msoffice_crypto::{decrypt_ooxml, encrypt_ooxml, is_cfb_office};
///
/// let package = include_bytes!("../tests/fixtures/plain.docx");
/// let sealed = encrypt_ooxml(package, "testpass")?;
/// assert!(is_cfb_office(&sealed));
/// assert_eq!(decrypt_ooxml(&sealed, "testpass")?, package);
/// # Ok::<(), msoffice_crypto::Error>(())
/// ```
///
/// # See Also
///
/// [`encrypt_ooxml_standard`] writes the Office 2007 format for a reader that cannot
/// open agile files. Prefer this function unless that constraint applies.
#[cfg(feature = "crypto-ops")]
pub fn encrypt_ooxml(package: &[u8], password: &str) -> Result<Vec<u8>, Error> {
    check_encryptable(package)?;
    agile_encrypt::encrypt(
        package,
        password,
        encryption_info::OFFICE_SPIN_COUNT,
        &mut rand::rngs::SysRng,
    )
}

/// Encrypt an OOXML package in the Office 2007 format, ECMA-376 standard encryption.
///
/// AES-128-ECB under a SHA-1-derived key, for a reader that predates agile encryption.
///
/// **Prefer [`encrypt_ooxml`].** Standard encryption defines no integrity element: a
/// modified ciphertext decrypts, silently, to a modified document, and ECB leaks equal
/// plaintext blocks as equal ciphertext blocks. This entry point exists because Office
/// 2007 cannot open an agile file and some tooling still targets it; it is named for the
/// format so that choosing it is a decision rather than a default. [`decrypt_ooxml`]
/// reads the result back under its fail-closed default, [`decrypt_ooxml_with_policy`]
/// reports [`IntegrityOutcome::NotApplicable`] for it, and
/// [`IntegrityPolicy::Require`] refuses it by name.
///
/// The header is [MS-OFFCRYPTO] §2.3.4.5's, written with the conforming
/// `fCryptoAPI | fAES` / `AlgID 0x660E` pair and the CSP name Office 2007 wrote; the
/// verifier hash is zero-padded to its 32-byte blob, the pad real Word compares. The
/// derived key, the password digest it comes from and the verifier plaintexts are held
/// in `secure-gate` wrappers and zeroized on drop; the password is `&str` and the input
/// and output are plain bytes, by design. Randomness comes from the operating system's
/// CSPRNG through the same function the seeded golden test drives.
///
/// On error, nothing is written: the function returns without a container.
///
/// # Errors
///
/// - [`Error::AlreadyEncrypted`], [`Error::NotAPlainPackage`],
///   [`Error::UnknownContainer`] — `package` is not a plain OOXML package. Checked by
///   [`check_encryptable`] before anything else, so a caller can ask the same question
///   before it pays for a password
/// - [`Error::BadParameters`] — `package` is over the 1 GiB this crate would
///   read back
/// - [`Error::RandomSource`] — the system RNG would not produce bytes
/// - [`Error::CipherError`] — an AES-ECB step returned a blob of the wrong
///   length (unreachable for the fixed AES-128 tuple this function writes)
/// - [`Error::Io`] — the in-memory container could not be written
///
/// # Examples
///
/// ```
/// use msoffice_crypto::{
///     decrypt_ooxml_with_policy, encrypt_ooxml_standard, IntegrityOutcome,
///     IntegrityPolicy,
/// };
///
/// let package = include_bytes!("../tests/fixtures/plain.docx");
/// let sealed = encrypt_ooxml_standard(package, "testpass")?;
/// let decrypted = decrypt_ooxml_with_policy(
///     &sealed,
///     "testpass",
///     IntegrityPolicy::RequireWhereDefined,
/// )?;
/// assert_eq!(decrypted.package, package);
/// assert_eq!(decrypted.integrity, IntegrityOutcome::NotApplicable);
/// assert!(!decrypted.integrity.is_authenticated());
/// # Ok::<(), msoffice_crypto::Error>(())
/// ```
///
/// # See Also
///
/// [`encrypt_ooxml`] writes agile encryption with a `dataIntegrity` HMAC, which is what
/// Office 16 writes and what this crate recommends.
#[cfg(feature = "crypto-ops")]
pub fn encrypt_ooxml_standard(package: &[u8], password: &str) -> Result<Vec<u8>, Error> {
    check_encryptable(package)?;
    standard_encrypt::encrypt(package, password, &mut rand::rngs::SysRng)
}

/// Decrypt a Word 97-2003, Excel 97-2003 or PowerPoint 97-2003 document in place.
///
/// The three binary formats keep their encryption inside their own records rather than
/// in an `EncryptionInfo` stream, and their plaintext is not a package but the same CFB
/// container with its encrypted streams replaced: the `WordDocument`, table and `Data`
/// streams of a `.doc`; the `Workbook` stream of a `.xls`; the `PowerPoint Document`
/// stream of a `.ppt`. The result is what `msoffcrypto-tool -d` writes, byte for byte on
/// every fixture in `tests/fixtures/`, and what Word, Excel and PowerPoint open without a
/// password.
///
/// Which format is decided by the streams the container holds ([`classify()`] reports the
/// same answer in [`Document`]), and which scheme by the format's own marker: the FIB's
/// `fEncrypted` bit and the version at the top of the table stream, the `FILEPASS`
/// record, the `UserEditAtom`'s `encryptSessionPersistIdRef`. Three schemes are read:
/// RC4 CryptoAPI ([MS-OFFCRYPTO] §2.3.5, all three formats), Office 97/2000 RC4 (§2.3.6,
/// Word and Excel) and XOR obfuscation (§2.3.7, Excel only — Word's variant is refused
/// by name). None of them defines an integrity element, so there is no policy to
/// choose and nothing to report: RC4 is a stream cipher and XOR is a transformation,
/// and a modified file decrypts to modified bytes with no error. That is the format's
/// limit, not this crate's, and the reason the modern formats exist.
///
/// The password hash, every block key and the XOR array are held in `secure-gate`
/// wrappers and zeroized on drop, and the RC4 key schedule is wiped with them.
///
/// On error, `data` is left untouched and no decrypted container is produced.
///
/// # Errors
///
/// - [`Error::NotACfbFile`] — `data` is not a CFB container
/// - [`Error::MissingStream`] — the container carries none of the three
///   formats' streams, or a stream is shorter than its header
/// - [`Error::NotEncrypted`] — the document carries no password-to-open
/// - [`Error::WrongPassword`] — the verifier did not match. Every scheme has
///   one: the RC4 families' encrypted verifier, XOR's 16-bit `verificationBytes`
/// - [`Error::UnsupportedAlgorithm`] — XOR obfuscation of a `.doc`, a BIFF5
///   workbook, a header naming `fExternal` or `fAES`, or an `AlgID` / `AlgIDHash` naming
///   anything but RC4 and SHA-1
/// - [`Error::UnsupportedEncryptionVersion`] — a version pair the format's own
///   walk does not implement: none of `1.1`, `2.2`, `3.2`, `4.2` for a `.doc` or `.xls`,
///   and none of `2.2`, `3.2`, `4.2` for a `.ppt`, whose `CryptSession10Container`
///   defines RC4 CryptoAPI only ([MS-OFFCRYPTO] §2.3.5)
/// - [`Error::BadParameters`] — a length or offset the file declares is out of
///   range: an `lKey` past the table stream, a record length past the workbook, a persist
///   offset past the presentation, a `KeySize` outside 40..=128, a `FILEPASS` out of order
/// - [`Error::Io`] — rewriting a stream inside the in-memory container failed
///
/// # Examples
///
/// A non-CFB input is refused before any format walk:
///
/// ```
/// use msoffice_crypto::{decrypt_binary_office, Error};
///
/// let err = decrypt_binary_office(b"PK\x03\x04", "testpass").unwrap_err();
/// assert!(matches!(err, Error::NotACfbFile));
/// ```
///
/// A password-protected `.doc` / `.xls` / `.ppt` decrypts in place. The crate tarball
/// does not ship a binary fixture, so this example is not executed:
///
/// ```no_run
/// use msoffice_crypto::decrypt_binary_office;
///
/// let data = std::fs::read("protected.doc")?;
/// let plain = decrypt_binary_office(&data, "testpass")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # See Also
///
/// [`classify()`] reports [`Document::WordBinary`], [`Document::ExcelBinary`] or
/// [`Document::PowerPointBinary`] for these files. [`decrypt_ooxml`] is the modern-OOXML
/// path and does not read a `.doc`.
#[cfg(feature = "legacy-binary")]
pub fn decrypt_binary_office(data: &[u8], password: &str) -> Result<Vec<u8>, Error> {
    if !is_cfb_office(data) {
        return Err(Error::NotACfbFile);
    }
    let mut container = legacy_container::LegacyContainer::open(data)?;
    match container.format() {
        Some(binary_office::BinaryFormat::Word) => word97::decrypt(&mut container, password)?,
        Some(binary_office::BinaryFormat::Excel) => excel97::decrypt(&mut container, password)?,
        Some(binary_office::BinaryFormat::PowerPoint) => {
            powerpoint97::decrypt(&mut container, password)?
        }
        None => {
            return Err(Error::MissingStream(
                "WordDocument, Workbook or PowerPoint Document",
            ))
        }
    }
    container.into_bytes()
}

/// `EncryptionInfo.Reserved` for agile encryption — [MS-OFFCRYPTO] §2.3.4.10 requires
/// exactly this value in bytes 4..8 of the stream.
///
/// Deliberately **not** in [`limits`]: that module's own doc comment excludes "lengths
/// fixed by the on-disk format rather than by a field in it", and this is a fixed word
/// in a header rather than a bound on anything a file chooses. It lives beside the code
/// that reads the offsets it describes, next to the `vMajor` / `vMinor` pair it follows.
///
/// `classify` reads the same header and does not check this, which is correct rather
/// than an oversight: a classifier reports what a file claims to be and must never fail
/// loudly (see [`classify()`]'s contract), so a wrong Reserved word there belongs in the
/// verdict, not in a refusal. Acting on the file is where the refusal belongs.
#[cfg(feature = "crypto-ops")]
const AGILE_ENCRYPTION_RESERVED: u32 = 0x0000_0040;

/// Decrypt a password-protected OOXML file, choosing what happens about the package HMAC.
///
/// Returns the decrypted OOXML ZIP bytes together with the [`IntegrityOutcome`] that
/// actually applied — so a caller can tell "verified" from "this format has no tag to
/// verify" without inspecting the file itself.
///
/// The check runs **before** the package is decrypted (the HMAC covers ciphertext), so
/// a failure means no plaintext was produced, not that plaintext was produced and
/// withheld. On any error, `data` is left untouched.
///
/// # Errors
///
/// Every variant [`decrypt_ooxml`] documents, plus:
///
/// - [`Error::IntegrityUnavailable`] — [`IntegrityPolicy::Require`] on
///   ECMA-376 standard encryption, which defines no integrity element at all. An *agile*
///   file that omits `<dataIntegrity>` is [`Error::IntegrityElementMissing`]
///   instead, under `Require` and under the default alike.
///
/// [`Error::BadParameters`] also covers a declared tag whose parameters this
/// crate cannot use: a `hashSize` that contradicts the hash `<keyData>` names, a
/// `blockSize` that is not the AES block, or a blob that is not a block multiple or is
/// shorter than the digest. A `hashAlgorithm` this crate does not implement is
/// [`Error::UnsupportedAlgorithm`], never `BadParameters`: `agile::resolve_hash`
/// refuses the name before `integrity::verify` is reached, and the file is well formed —
/// the password may be exactly right.
///
/// # Examples
///
/// ```
/// use msoffice_crypto::{
///     decrypt_ooxml_with_policy, IntegrityOutcome, IntegrityPolicy,
/// };
///
/// let decrypted = decrypt_ooxml_with_policy(
///     include_bytes!("../tests/fixtures/agile_encrypted.docx"),
///     "testpass",
///     IntegrityPolicy::Require,
/// )?;
/// assert_eq!(decrypted.integrity, IntegrityOutcome::Verified);
/// assert!(decrypted.integrity.is_authenticated());
/// assert!(decrypted.package.starts_with(b"PK\x03\x04"));
/// # Ok::<(), msoffice_crypto::Error>(())
/// ```
///
/// # See Also
///
/// [`decrypt_ooxml`] is this function under [`IntegrityPolicy::RequireWhereDefined`],
/// discarding the outcome. [`IntegrityPolicy`] documents each choice; [`classify()`]
/// reports [`IntegrityDeclaration`] before any decrypt.
#[cfg(feature = "crypto-ops")]
pub fn decrypt_ooxml_with_policy(
    data: &[u8],
    password: &str,
    policy: IntegrityPolicy,
) -> Result<Decrypted, Error> {
    if !is_cfb_office(data) {
        return Err(Error::NotACfbFile);
    }

    let streams = cfb_reader::read_cfb_streams(data)?;

    // The version header is eight bytes. Copying it into an array is how a short stream
    // becomes [`Error::MissingStream`] rather than a panic on `try_into` or
    // on indexing past the end — both of which clippy::missing_panics_doc would then
    // demand a `# Panics` section for, on a path that is an error, not a panic.
    let header: [u8; 8] = streams
        .encryption_info
        .get(..8)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::MissingStream("EncryptionInfo too short"))?;

    // Bytes 0-1: vMajor (LE u16), bytes 2-3: vMinor (LE u16)
    let v_major = u16::from_le_bytes([header[0], header[1]]);
    let v_minor = u16::from_le_bytes([header[2], header[3]]);

    match (v_major, v_minor) {
        // Agile Encryption — XML starts after the 8-byte header (4-byte version + 4-byte reserved)
        (4, 4) => {
            // [MS-OFFCRYPTO] §2.3.4.10: the four bytes after `EncryptionVersionInfo` are
            // `Reserved` and MUST be `0x00000040` — 0x40, not zero, which is the one
            // thing about this field that is easy to get backwards. A structural check
            // on attacker-supplied bytes that runs *before* the XML parser is handed
            // anything, for the cost of one comparison.
            //
            // Gated to this arm on purpose: for `vMinor = 2` (standard encryption) the
            // same four bytes are `EncryptionHeader.Flags`, a different field entirely —
            // `standard_encrypted.docx` carries `00 00 00 00` there — so a check hoisted
            // above the `match` would reject every Office 2007 file in existence.
            //
            // herumi checks it in the same shape this crate does — read the four bytes as
            // a little-endian `u32` and compare: `include/crypto_util.hpp:322-323`
            // (`const uint32_t reserved = cybozu::Get32bitAsLE(p + 4);
            // MS_ASSERT_EQUAL(reserved, 0x40u);`), immediately before its XML parse, with
            // the encode side writing `0x40` at `:350-353`. That is BSD-3, so the fact is
            // available from a permissive source, exactly as `limits::AGILE_SALT_SIZE`
            // records for its own range. LibreOffice checks it too
            // (`AgileEngine.cxx:522-530`, against `msfilter::AGILE_ENCRYPTION_RESERVED`
            // at `mscodec.hxx:441`; behaviour and constant only, nothing copied), and its
            // comparison *shape* is the one deliberately not followed: `readBytes`
            // resizes to what it actually read and `std::equal` then walks that range, so
            // a stream truncated inside the field compares fewer elements and passes.
            // `header` is `[u8; 8]`, so these four bytes exist.
            let reserved = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
            if reserved != AGILE_ENCRYPTION_RESERVED {
                return Err(Error::BadParameters(format!(
                    "agile EncryptionInfo Reserved is {reserved:#010x}; [MS-OFFCRYPTO] \
                     2.3.4.10 requires {AGILE_ENCRYPTION_RESERVED:#010x}"
                )));
            }
            agile::decrypt(
                &streams.encryption_info[8..],
                &streams.encrypted_package,
                password,
                policy,
            )
            .map(|(package, integrity)| Decrypted { package, integrity })
        }
        // Standard Encryption — binary EncryptionHeader starts after the 8-byte header
        // vMajor 2/3/4 all indicate Standard Encryption per MS-OFFCRYPTO spec.
        //
        // [MS-OFFCRYPTO] §2.3.4.5 defines no integrity element for this format: there is
        // no dataIntegrity, no HMAC, nothing to check. That is reported as
        // `IntegrityOutcome::NotApplicable` rather than as a failure — absence here is
        // the spec, not a defect in the file. `Require` is the one exception, and only
        // because the caller asked for a guarantee the format cannot give; it is
        // refused before any work is done rather than after.
        //
        // The standard half of `IntegrityPolicy`'s contract; the agile half is
        // `agile::check_integrity`. Matched exhaustively rather than written as
        // `if policy == Require`, so that this arm's tolerance of a new policy variant
        // is a decision someone makes rather than a fall-through they inherit — the
        // fail-closed default of GH #12 deliberately stops short of here.
        (2, 2) | (3, 2) | (4, 2) => {
            match policy {
                IntegrityPolicy::Require => {
                    return Err(Error::IntegrityUnavailable(
                        "ECMA-376 standard encryption (Office 2007) defines no integrity \
                         element. Re-saving the file with Office 2013 or later writes agile \
                         encryption, which does; IntegrityPolicy::RequireWhereDefined opens \
                         this one as it is, unauthenticated",
                    ))
                }
                IntegrityPolicy::RequireWhereDefined
                | IntegrityPolicy::VerifyIfPresent
                | IntegrityPolicy::Skip => {}
            }
            let package = standard::decrypt(
                &streams.encryption_info[8..],
                &streams.encrypted_package,
                password,
            )?;
            Ok(Decrypted {
                package,
                integrity: IntegrityOutcome::NotApplicable,
            })
        }
        _ => Err(Error::UnsupportedEncryptionVersion(v_major, v_minor)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_cfb_office_magic() {
        let cfb = [0xD0u8, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00];
        assert!(is_cfb_office(&cfb));
    }

    #[test]
    fn test_is_cfb_office_not_zip() {
        assert!(!is_cfb_office(b"PK\x03\x04something"));
    }

    #[test]
    fn test_is_cfb_office_not_pdf() {
        assert!(!is_cfb_office(b"%PDF-1.4"));
    }

    #[test]
    fn test_is_cfb_office_too_short() {
        assert!(!is_cfb_office(&[0xD0, 0xCF, 0x11]));
    }

    /// Everything past detection. Gated as a child module rather than by tagging each
    /// test, so `cargo test --no-default-features` still runs the four `is_cfb_office`
    /// cases above instead of finding an empty suite.
    #[cfg(feature = "crypto-ops")]
    mod crypto_ops {
        use crate::*;

        #[test]
        fn test_decrypt_non_cfb_returns_error() {
            let result = decrypt_ooxml(b"PK\x03\x04not a cfb", "password");
            assert!(matches!(result, Err(Error::NotACfbFile)));
        }

        /// End-to-end fixture tests. The fixtures are committed in tests/fixtures/
        /// and are NOT optional: a missing one fails the test rather than skipping,
        /// so the suite cannot go green while exercising nothing.
        #[test]
        fn test_agile_fixture_decrypts_to_zip() {
            let fixture_path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/agile_encrypted.docx"
            );
            let data = std::fs::read(fixture_path)
                .expect("fixture must be present -- agile tests are not optional");
            assert!(is_cfb_office(&data));
            let plain = decrypt_ooxml(&data, "testpass").expect("Agile decrypt must succeed");
            assert!(
                plain.starts_with(b"PK\x03\x04"),
                "Decrypted output must be ZIP"
            );
        }

        #[test]
        fn test_agile_fixture_wrong_password() {
            let fixture_path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/agile_encrypted.docx"
            );
            let data = std::fs::read(fixture_path)
                .expect("fixture must be present -- agile tests are not optional");
            let result = decrypt_ooxml(&data, "wrongpass");
            assert!(
                matches!(result, Err(Error::WrongPassword)),
                "Wrong password must return WrongPassword"
            );
        }

        // ---- non-SHA-512 agile fixtures (issue #11) ---------------------------------

        /// Every agile fixture that is not AES-256/SHA-512: the two GH #11 added and the
        /// three GH #13 added, all from `tools/gen_agile_fixtures.py`.
        const NON_SHA512_AGILE_FIXTURES: [&str; 5] = [
            "agile_aes256_sha384.docx",
            "agile_aes256_sha256.docx",
            "agile_aes128_sha1.docx",
            "agile_aes128_sha384.docx",
            "agile_aes192_sha384.docx",
        ];

        fn fixture(name: &str) -> Vec<u8> {
            let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
            std::fs::read(&path)
                .unwrap_or_else(|e| panic!("fixture {name} must be present, not optional: {e}"))
        }

        /// An agile file may name any of four hashes on `<p:encryptedKey>`, and until
        /// issue #11 this crate ran SHA-512 for all of them: wrong `H_final`, wrong block
        /// keys, failed verifier, and the user told their password was wrong when it was
        /// right.
        ///
        /// **What these two fixtures are.** Written by msoffcrypto-tool 6.x — an
        /// independent MIT implementation with its own reading of [MS-OFFCRYPTO] — with
        /// its hardcoded parameter tuple replaced and nothing else changed, by
        /// `tools/gen_agile_fixtures.py`. Each was read back to a byte-identical
        /// `plain.docx` by msoffcrypto's own CLI before being committed, and is asserted
        /// here against that same known plaintext rather than against a round trip.
        ///
        /// **What they are not.** Evidence of agreement with Microsoft's writer. No real
        /// Office file with these tuples exists in any local corpus and none can be
        /// produced here; the container is the same shape as the SHA-512 fixture beside
        /// them, and that is as far as the claim goes. That fixture is **not** an Office
        /// artefact either: `agile_encrypted.docx` was written by msoffcrypto-tool over a
        /// python-docx `plain.docx`, like the other two — its `/EncryptionInfo` stream is
        /// byte-identical to msoffcrypto's `toEncryptionDescriptor()` template
        /// (`msoffcrypto/method/ecma376_agile.py:138-152`) rendered with the fixture's own
        /// attribute values, four-space indentation and `xmlns:c` included, where Office
        /// writes that stream unindented. **No Office-written agile fixture exists in this
        /// corpus, for any tuple** — the whole agile suite is one third-party writer read
        /// back by two readers.
        ///
        /// **Since GH #13, the four tuples that exist in the wild are all here** — the
        /// three LibreOffice writes besides Office 16's own, `(128, SHA1)`, `(128, SHA384)`
        /// and `(192, SHA384)`, produced by the same independent writer with its `keyBits`
        /// replaced. The AES-128/SHA-1 one is Word 2010's default. **Real Word 16 opens
        /// all five** (`tools/office_com_check.ps1`, recorded in CHANGELOG.md for
        /// 2026-09-05), which is evidence that each is a file Office recognises,
        /// separate from the evidence that this crate reads it — and it was not free:
        /// the SHA-1 file only opened once its `dataIntegrity` blobs were zero-padded,
        /// and the AES-192 file is the one whose 24-byte session key travels in a 32-byte
        /// blob. The SHA-1 fixture is also the only one whose blobs carry a `hashSize`
        /// pad at all, so it is the one that exercises `integrity::unwrap_blob`'s
        /// truncation on a real container.
        #[test]
        #[cfg_attr(
            not(fixture_corpus),
            ignore = "needs the fixture corpus, which the published crate does not ship"
        )]
        fn test_non_sha512_agile_fixtures_decrypt_to_the_known_plaintext() {
            let plain = fixture("plain.docx");
            for name in NON_SHA512_AGILE_FIXTURES {
                let data = fixture(name);
                assert!(is_cfb_office(&data));
                let crate::Decrypted {
                    package: out,
                    integrity: outcome,
                } = decrypt_ooxml_with_policy(&data, "testpass", IntegrityPolicy::Require)
                    .unwrap_or_else(|e| panic!("{name} must decrypt: {e}"));
                assert_eq!(out, plain, "{name} must decrypt to the known plaintext");
                // Its dataIntegrity HMAC runs on the same non-SHA-512 algorithm, so
                // `Require` also proves `<keyData>`'s half is honoured end to end.
                assert_eq!(outcome, IntegrityOutcome::Verified, "{name}");
            }
        }

        /// The negative control the hash work needs: a wrong password on a non-SHA-512
        /// file must still be `WrongPassword`. Without it the test above cannot
        /// distinguish "the dispatch is wired" from "this tuple always errors" — which
        /// is exactly what the pre-#11 crate did, for every password.
        #[test]
        #[cfg_attr(
            not(fixture_corpus),
            ignore = "needs the fixture corpus, which the published crate does not ship"
        )]
        fn test_non_sha512_agile_fixtures_still_report_a_wrong_password() {
            for name in NON_SHA512_AGILE_FIXTURES {
                let result = decrypt_ooxml(&fixture(name), "wrongpass");
                assert!(
                    matches!(result, Err(Error::WrongPassword)),
                    "{name} with the wrong password got {:?}",
                    result.map(|p| p.len())
                );
            }
        }

        /// The SHA-512 fixtures decrypt byte-identically to the same known plaintext.
        /// The hash work touched every derivation on the password path, so "still starts
        /// with PK" is not a strong enough regression assertion for it.
        #[test]
        fn test_sha512_agile_fixture_still_decrypts_byte_identically() {
            assert_eq!(
                decrypt_ooxml(&fixture("agile_encrypted.docx"), "testpass").unwrap(),
                fixture("plain.docx")
            );
        }

        /// The standard fixture decrypts to `plain.docx`, byte for byte.
        ///
        /// This asserted only `starts_with(b"PK\x03\x04")` until 2026-09-05, which a
        /// wrong-but-ZIP-shaped decrypt passes: a mis-derived key that happened to leave
        /// the first block intact, a segment boundary off by one, a truncation a few bytes
        /// early. The plaintext to compare against was already committed, and the
        /// expectation is external to this crate: `msoffcrypto-tool -p testpass` decrypts
        /// `standard_encrypted.docx` to a file whose SHA-256 is
        /// `285ce3ad5021f04436e3…`, identical to `tests/fixtures/plain.docx` (36 678
        /// bytes), measured before this assertion was written. The ZIP-shape check stays
        /// first so a failure is diagnosable rather than reducing to "36 678 bytes differ".
        #[test]
        #[cfg_attr(
            not(fixture_corpus),
            ignore = "needs the fixture corpus, which the published crate does not ship"
        )]
        fn test_standard_fixture_decrypts_to_zip() {
            let fixture_path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/standard_encrypted.docx"
            );
            let data = std::fs::read(fixture_path)
                .expect("fixture must be present -- standard tests are not optional");
            assert!(is_cfb_office(&data));
            let plain = decrypt_ooxml(&data, "testpass").expect("Standard decrypt must succeed");
            assert!(
                plain.starts_with(b"PK\x03\x04"),
                "Decrypted output must be ZIP"
            );
            assert_eq!(
                plain,
                fixture("plain.docx"),
                "the standard fixture must decrypt to plain.docx byte for byte"
            );
        }

        #[test]
        #[cfg_attr(
            not(fixture_corpus),
            ignore = "needs the fixture corpus, which the published crate does not ship"
        )]
        fn test_standard_fixture_wrong_password() {
            let fixture_path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/standard_encrypted.docx"
            );
            let data = std::fs::read(fixture_path)
                .expect("fixture must be present -- standard tests are not optional");
            let result = decrypt_ooxml(&data, "wrongpass");
            assert!(
                matches!(result, Err(Error::WrongPassword)),
                "Wrong password must return WrongPassword"
            );
        }

        // ---- dataIntegrity (S2 / F18) ------------------------------------------------

        fn agile_fixture() -> Vec<u8> {
            std::fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/agile_encrypted.docx"
            ))
            .expect("fixture must be present -- agile tests are not optional")
        }

        /// Flip one bit of ciphertext inside the CFB container's `EncryptedPackage`
        /// stream, well past the first segment so the decrypted ZIP header survives.
        ///
        /// Built at runtime rather than committed as a second binary fixture: a tampered
        /// `.docx` in the tree is indistinguishable from a corrupt one, and nothing in the
        /// file would record *which* byte was flipped or why.
        fn tamper_agile_fixture(offset: u64) -> Vec<u8> {
            use std::io::{Read, Seek, SeekFrom, Write};

            let mut cursor = std::io::Cursor::new(agile_fixture());
            {
                let mut container =
                    cfb::CompoundFile::open(&mut cursor).expect("fixture is a CFB container");
                let mut stream = container
                    .open_stream("/EncryptedPackage")
                    .expect("fixture has an EncryptedPackage stream");

                stream.seek(SeekFrom::Start(offset)).unwrap();
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).unwrap();
                byte[0] ^= 0x01;
                stream.seek(SeekFrom::Start(offset)).unwrap();
                stream.write_all(&byte).unwrap();
                stream.flush().unwrap();
            }
            cursor.into_inner()
        }

        /// Delete the whole `<dataIntegrity .../>` element from the fixture's
        /// `EncryptionInfo` XML.
        ///
        /// That XML is stored in the clear, so this touches no cryptographic parameter and
        /// needs no foreign writer: what comes back is a valid agile document that simply
        /// declares no tag. The base64 alphabet contains `/` but not `>`, so the first
        /// `/>` after the element name is its own terminator.
        ///
        /// This is not "an old file" — GH #12 found no writer that omits the element and
        /// no corpus file lacking it. It is the downgrade attack: the ~200 bytes an
        /// attacker deletes to turn off the integrity check, and nothing else changes.
        fn agile_fixture_without_data_integrity() -> Vec<u8> {
            use std::io::{Read, Seek, SeekFrom, Write};

            let mut cursor = std::io::Cursor::new(agile_fixture());
            {
                let mut container =
                    cfb::CompoundFile::open(&mut cursor).expect("fixture is a CFB container");

                let mut info = Vec::new();
                container
                    .open_stream("/EncryptionInfo")
                    .unwrap()
                    .read_to_end(&mut info)
                    .unwrap();

                let start = info
                    .windows(14)
                    .position(|w| w == b"<dataIntegrity")
                    .expect("the fixture declares a dataIntegrity tag");
                let end = start + info[start..].windows(2).position(|w| w == b"/>").unwrap() + 2;
                info.drain(start..end);

                let mut stream = container.open_stream("/EncryptionInfo").unwrap();
                stream.set_len(0).unwrap();
                stream.seek(SeekFrom::Start(0)).unwrap();
                stream.write_all(&info).unwrap();
                stream.flush().unwrap();
            }
            cursor.into_inner()
        }

        /// GH #12, the downgrade attack: an attacker who can modify the file deletes the
        /// `<dataIntegrity>` element and the tamper detection goes with it — no password,
        /// no error. The bytes here are exactly that attack, and the default policy must
        /// refuse them.
        ///
        /// This test asserted the opposite until #12 (`..._reports_not_declared`, where
        /// the loop below ran `VerifyIfPresent` as *the default* and expected `Ok`).
        #[test]
        fn test_agile_without_data_integrity_is_refused_by_default() {
            let data = agile_fixture_without_data_integrity();

            // The fix. `decrypt_ooxml` is the signature the consumer calls, so the fail-closed
            // behaviour must arrive without anyone passing a policy — asserted on the
            // specific variant, since `is_err()` would also pass if the rewrite had
            // simply broken the container.
            assert!(
                matches!(
                    decrypt_ooxml(&data, "testpass"),
                    Err(Error::IntegrityElementMissing)
                ),
                "the default policy must refuse an agile file whose tag was deleted"
            );
            assert!(matches!(
                decrypt_ooxml_with_policy(&data, "testpass", IntegrityPolicy::default()),
                Err(Error::IntegrityElementMissing)
            ));
            // `Require` is stricter still and refuses for the same reason, with the same
            // variant: the file is the problem, not the request.
            assert!(matches!(
                decrypt_ooxml_with_policy(&data, "testpass", IntegrityPolicy::Require),
                Err(Error::IntegrityElementMissing)
            ));

            // The negative control that makes the refusals mean something: the SAME bytes
            // decrypt under either explicit opt-out. Without this the test cannot tell
            // "the policy is wired" from "these bytes always fail", and the opt-out #12
            // promises could be unreachable while every assertion above still passed.
            for policy in [IntegrityPolicy::VerifyIfPresent, IntegrityPolicy::Skip] {
                let crate::Decrypted {
                    package: plain,
                    integrity: outcome,
                } = decrypt_ooxml_with_policy(&data, "testpass", policy).unwrap_or_else(|e| {
                    panic!("{policy:?} must still decrypt a tag-less agile file: {e}")
                });
                // `Skip` reports `NotDeclared`, not `Skipped`: nothing was skipped.
                assert_eq!(outcome, IntegrityOutcome::NotDeclared, "{policy:?}");
                assert!(plain.starts_with(b"PK\x03\x04"), "{policy:?}");
            }

            // The second control: the same bytes with the tag still in place verify, so
            // the refusals come from the deleted element and not from the rewrite.
            let crate::Decrypted {
                integrity: outcome, ..
            } = decrypt_ooxml_with_policy(&agile_fixture(), "testpass", IntegrityPolicy::Require)
                .unwrap();
            assert_eq!(outcome, IntegrityOutcome::Verified);
        }

        /// The unmodified fixture verifies. This is the positive half of the guard: if the
        /// HMAC were computed over the wrong bytes, this fails rather than the tamper test.
        #[test]
        fn test_agile_fixture_integrity_verifies() {
            let crate::Decrypted {
                package: plain,
                integrity: outcome,
            } = decrypt_ooxml_with_policy(&agile_fixture(), "testpass", IntegrityPolicy::Require)
                .expect("the unmodified fixture must verify under Require");
            assert_eq!(outcome, IntegrityOutcome::Verified);
            assert!(plain.starts_with(b"PK\x03\x04"));
        }

        /// F18 itself: before this check existed, this input decrypted to garbage and
        /// returned `Ok`. The flipped byte sits ~20 KB in, so the ZIP magic still appears
        /// at the front of the plaintext — "it looks like a ZIP" is not a integrity check.
        #[test]
        fn test_agile_tampered_ciphertext_is_refused() {
            let tampered = tamper_agile_fixture(8 + 20_000);

            for policy in [
                IntegrityPolicy::default(),
                IntegrityPolicy::VerifyIfPresent,
                IntegrityPolicy::Require,
            ] {
                let result = decrypt_ooxml_with_policy(&tampered, "testpass", policy);
                assert!(
                    matches!(result, Err(Error::IntegrityCheckFailed)),
                    "{policy:?} must refuse a tampered package, got {:?}",
                    result.map(|d| (d.package.len(), d.integrity))
                );
            }

            // The policy-free entry point the consumer calls refuses too. Note the variant: the
            // element is present and the HMAC is wrong, which is `IntegrityCheckFailed`,
            // not the `IntegrityElementMissing` of the deleted-element case.
            assert!(matches!(
                decrypt_ooxml(&tampered, "testpass"),
                Err(Error::IntegrityCheckFailed)
            ));
        }

        /// `Skip` still decrypts the same tampered file. This is what proves the policy is
        /// wired rather than the tamper being rejected by some unrelated check: the bytes
        /// are identical, only the policy differs.
        #[test]
        fn test_agile_tampered_ciphertext_decrypts_under_skip() {
            let tampered = tamper_agile_fixture(8 + 20_000);
            let crate::Decrypted {
                package: plain,
                integrity: outcome,
            } = decrypt_ooxml_with_policy(&tampered, "testpass", IntegrityPolicy::Skip)
                .expect("Skip must not check the HMAC");
            assert_eq!(outcome, IntegrityOutcome::Skipped);
            assert!(
                plain.starts_with(b"PK\x03\x04"),
                "the corruption is mid-package; the ZIP header still decrypts cleanly, \
                 which is exactly why a structural sniff is not an integrity check"
            );

            // ... and it really is corrupt: the same offset in the clean fixture differs.
            let clean = decrypt_ooxml(&agile_fixture(), "testpass").unwrap();
            assert_ne!(clean, plain, "the flipped byte must change the plaintext");
        }

        /// A wrong password must still be reported as a wrong password, not as corruption.
        /// The password check runs first for exactly this reason.
        #[test]
        fn test_agile_wrong_password_is_not_reported_as_corruption() {
            let result =
                decrypt_ooxml_with_policy(&agile_fixture(), "wrongpass", IntegrityPolicy::Require);
            assert!(matches!(result, Err(Error::WrongPassword)));
        }

        /// ECMA-376 standard encryption has no integrity element by spec. Absence is
        /// reported, not treated as a failure.
        ///
        /// GH #12 item 3, and the single most likely way to break something while fixing
        /// the agile downgrade: the fail-closed default stops at formats that *define* an
        /// element, so `IntegrityPolicy::default()` and the bare `decrypt_ooxml` are in
        /// the loop below explicitly rather than left to be assumed equivalent to
        /// `VerifyIfPresent`.
        #[test]
        #[cfg_attr(
            not(fixture_corpus),
            ignore = "needs the fixture corpus, which the published crate does not ship"
        )]
        fn test_standard_reports_integrity_absent_not_failure() {
            let data = std::fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/standard_encrypted.docx"
            ))
            .expect("fixture must be present -- standard tests are not optional");

            // Byte-identity against the committed plaintext, not a ZIP-shape check: see
            // `test_standard_fixture_decrypts_to_zip` for the provenance of that claim.
            let known = fixture("plain.docx");
            assert_eq!(
                decrypt_ooxml(&data, "testpass")
                    .expect("the default must never refuse a standard file"),
                known,
                "the policy-free signature the consumer calls must still decrypt Office 2007 files"
            );

            for policy in [
                IntegrityPolicy::default(),
                IntegrityPolicy::VerifyIfPresent,
                IntegrityPolicy::Skip,
            ] {
                let crate::Decrypted {
                    package: plain,
                    integrity: outcome,
                } = decrypt_ooxml_with_policy(&data, "testpass", policy)
                    .unwrap_or_else(|e| panic!("{policy:?} must decrypt a standard file: {e}"));
                assert_eq!(outcome, IntegrityOutcome::NotApplicable);
                assert_eq!(plain, known, "{policy:?}");
            }

            // `Require` is the caller demanding a guarantee the format cannot give, so it
            // is refused -- with a distinct error, never `IntegrityCheckFailed`.
            assert!(matches!(
                decrypt_ooxml_with_policy(&data, "testpass", IntegrityPolicy::Require),
                Err(Error::IntegrityUnavailable(_))
            ));
        }

        /// The no-regression half of GH #12: the policy-free signature still behaves
        /// exactly as it did for well-formed files, so an existing caller inherits the
        /// fail-closed default without a line changing on its side. A security fix that
        /// also broke every good file would not be one.
        #[test]
        #[cfg_attr(
            not(fixture_corpus),
            ignore = "needs the fixture corpus, which the published crate does not ship"
        )]
        fn test_default_policy_requires_a_tag_and_still_decrypts_good_files() {
            assert_eq!(
                IntegrityPolicy::default(),
                IntegrityPolicy::RequireWhereDefined
            );

            // Every committed agile fixture — all three carry the element — decrypts
            // unchanged through the bare signature, and reports `Verified` rather than
            // merely succeeding.
            for name in [
                "agile_encrypted.docx",
                "agile_aes256_sha384.docx",
                "agile_aes256_sha256.docx",
            ] {
                let data = fixture(name);
                let plain = decrypt_ooxml(&data, "testpass")
                    .unwrap_or_else(|e| panic!("{name} must decrypt under the default: {e}"));
                let crate::Decrypted {
                    package: with_policy,
                    integrity: outcome,
                } = decrypt_ooxml_with_policy(&data, "testpass", IntegrityPolicy::Require).unwrap();
                assert_eq!(plain, with_policy, "{name}");
                assert_eq!(plain, fixture("plain.docx"), "{name}");
                assert_eq!(outcome, IntegrityOutcome::Verified, "{name}");
            }
        }

        // ---- the encrypt shape guard -----------------------------------------------

        /// The bug this guard exists for: encrypting a file that is already encrypted
        /// used to return `Ok` and produce a CFB wrapped in a CFB, indistinguishable
        /// from a single wrap without decrypting it. Found by a downstream consumer,
        /// which had to reimplement the CLI's guard to avoid it.
        ///
        /// The first `encrypt_ooxml` succeeding is the negative control: this test
        /// cannot pass by refusing everything.
        #[test]
        fn encrypt_ooxml_refuses_a_file_it_just_encrypted() {
            let plain = fixture("plain.docx");
            let sealed = encrypt_ooxml(&plain, "testpass").expect("a plain package encrypts");

            let again = encrypt_ooxml(&sealed, "testpass");
            assert!(
                matches!(
                    again,
                    Err(Error::AlreadyEncrypted {
                        family: Family::Agile,
                        document: Document::OoxmlPackage,
                    })
                ),
                "a second wrap must be refused, naming what it found; got: {:?}",
                again.map(|c| c.len())
            );
        }

        /// The standard writer's half of the same bug.
        #[test]
        fn encrypt_ooxml_standard_refuses_a_file_it_just_encrypted() {
            let plain = fixture("plain.docx");
            let sealed =
                encrypt_ooxml_standard(&plain, "testpass").expect("a plain package encrypts");

            let again = encrypt_ooxml_standard(&sealed, "testpass");
            assert!(
                matches!(
                    again,
                    Err(Error::AlreadyEncrypted {
                        family: Family::Standard,
                        document: Document::OoxmlPackage,
                    })
                ),
                "a second wrap must be refused, naming what it found; got: {:?}",
                again.map(|c| c.len())
            );
        }

        /// Cross-format double-wrapping is the same defect wearing a different hat, and
        /// nothing else here would catch it: each writer must refuse the other's output.
        #[test]
        fn the_two_writers_refuse_each_others_output() {
            let plain = fixture("plain.docx");
            let agile = encrypt_ooxml(&plain, "testpass").unwrap();
            let standard = encrypt_ooxml_standard(&plain, "testpass").unwrap();

            assert!(
                matches!(
                    encrypt_ooxml_standard(&agile, "testpass"),
                    Err(Error::AlreadyEncrypted {
                        family: Family::Agile,
                        ..
                    })
                ),
                "the standard writer must refuse an agile container"
            );
            assert!(
                matches!(
                    encrypt_ooxml(&standard, "testpass"),
                    Err(Error::AlreadyEncrypted {
                        family: Family::Standard,
                        ..
                    })
                ),
                "the agile writer must refuse a standard container"
            );
        }

        /// Eight bytes of CFB magic: a container this crate recognises and will not write
        /// into. Fixture-free on purpose — the fact is about the shape, not any document.
        #[test]
        fn a_bare_cfb_is_refused_as_not_a_plain_package() {
            let magic = [0xD0u8, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
            assert!(matches!(
                check_encryptable(&magic),
                Err(Error::NotAPlainPackage)
            ));
            assert!(matches!(
                encrypt_ooxml(&magic, "testpass"),
                Err(Error::NotAPlainPackage)
            ));
            assert!(matches!(
                encrypt_ooxml_standard(&magic, "testpass"),
                Err(Error::NotAPlainPackage)
            ));
        }

        /// Bytes that are no container at all, including the empty input. `&[]` is
        /// `Container::Unknown`, so it is refused like any other non-package — the
        /// writer's handling of a degenerate *payload* is a separate fact, checked
        /// through the seeded cores in `agile_encrypt_tests` and `standard_encrypt_tests`.
        #[test]
        fn bytes_that_are_no_container_are_refused() {
            for input in [&b"sixteen bytes!!!"[..], &[][..]] {
                assert!(
                    matches!(check_encryptable(input), Err(Error::UnknownContainer)),
                    "{input:?} is not a container"
                );
                assert!(matches!(
                    encrypt_ooxml(input, "testpass"),
                    Err(Error::UnknownContainer)
                ));
                assert!(matches!(
                    encrypt_ooxml_standard(input, "testpass"),
                    Err(Error::UnknownContainer)
                ));
            }
        }

        /// A plain ZIP is the one thing the guard accepts, and four bytes of magic are
        /// the whole test — which is why a bare signature passes alongside a real
        /// package. Moved here from the CLI when the guard stopped being the CLI's.
        #[test]
        fn a_plain_zip_is_the_one_thing_the_guard_accepts() {
            check_encryptable(b"PK\x03\x04").expect("four bytes of zip magic are encryptable");
            check_encryptable(&fixture("plain.docx")).expect("a real package is encryptable");
        }

        /// The guard a caller runs before paying for a password is the guard the writer
        /// runs at the door. Not two functions that agree — one function, called twice —
        /// and this is what would fail if a future entry point grew its own copy.
        ///
        /// [`Error`] has no `PartialEq` by design, so the comparison is over a name.
        #[test]
        fn the_guard_a_caller_runs_is_the_guard_the_writer_runs() {
            fn kind(e: &Error) -> &'static str {
                match e {
                    Error::AlreadyEncrypted { .. } => "already-encrypted",
                    Error::NotAPlainPackage => "not-a-plain-package",
                    Error::UnknownContainer => "unknown-container",
                    _ => "other",
                }
            }
            fn verdict(r: Result<Vec<u8>, Error>) -> String {
                r.map_or_else(|e| kind(&e).to_string(), |_| "ok".to_string())
            }

            let plain = fixture("plain.docx");
            let sealed = encrypt_ooxml(&plain, "testpass").unwrap();
            let magic = [0xD0u8, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

            for input in [
                &plain[..],
                &sealed[..],
                &magic[..],
                &b"sixteen bytes!!!"[..],
                &[][..],
            ] {
                let asked = check_encryptable(input)
                    .map_or_else(|e| kind(&e).to_string(), |()| "ok".to_string());
                assert_eq!(
                    asked,
                    verdict(encrypt_ooxml(input, "testpass")),
                    "the agile writer disagreed with the guard a caller would have run"
                );
                assert_eq!(
                    asked,
                    verdict(encrypt_ooxml_standard(input, "testpass")),
                    "the standard writer disagreed with the guard a caller would have run"
                );
            }
        }
    }
}
