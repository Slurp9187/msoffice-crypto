#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Answer what encryption a byte stream declares, without decrypting anything.
//!
//! [`classify()`] is the first thing a caller runs on a file it has not vetted, so it is
//! built to the one property that matters in that position: **it cannot panic and it
//! cannot fail**. Every unreadable shape — a truncated container, a corrupt directory
//! tree, XML that does not parse, an attribute that is not a number — collapses into
//! `Unknown` rather than an error or an unwind. A caller gets a verdict for every input.
//!
//! It also needs **no cryptographic dependency**: reading `EncryptionInfo` is a CFB open
//! plus an XML or binary-header parse. That is why the crate's `crypto-ops` feature is
//! off by default — `cargo add msoffice-crypto` installs detection, and only a consumer
//! that actually decrypts pays for `aes`, `cbc`, `ecb`, `sha1`, `sha2` and `hmac`.
//!
//! # Design commitment D1 — classify carries the integrity claim
//!
//! The sibling crate `odf-crypto`'s `classify` answers "encrypted? which algorithm
//! tuple?". This one answers a third question: **does the file declare a
//! `<dataIntegrity>` element?** ([`IntegrityDeclaration`]). That is what lets a caller
//! choose `IntegrityPolicy::Require` knowingly instead of discovering after the
//! fact that there was nothing to verify. See the foundation plan's D1.
//!
//! # The two agile parameter sets are reported separately
//!
//! `<keyData>` and `<p:encryptedKey>` each carry their own `cipherAlgorithm`,
//! `hashAlgorithm`, `keyBits`, `blockSize` and `saltSize`. [MS-OFFCRYPTO] §2.3.4.10
//! constrains two of those five: a writer's `PasswordKeyEncryptor` `hashAlgorithm` and
//! `cipherAlgorithm` "MUST be the same as" `Encryption.keyData`'s. The other three —
//! `keyBits`, `blockSize`, `saltSize` — carry no such rule and legitimately differ.
//!
//! A *reader* gets no guarantee from a writer's MUST, and Office writes all five
//! identically, which is exactly what hides a crossed-parameter bug in any round trip
//! against your own writer — this crate shipped exactly that bug once, where the package
//! IVs were derived from the wrong element's parameters and every round trip still
//! passed. So [`Classification::key_data`] and
//! [`Classification::password_key`] are two fields, not one merged tuple, and a caller
//! can see when a file disagrees with itself.

use quick_xml::{events::Event, Reader};

use crate::binary_office;
use crate::cfb_reader;

/// The container [`classify()`] found the bytes wrapped in.
///
/// An Office file encrypted with a password is a CFB container whose `EncryptedPackage`
/// stream holds the original ZIP; an unencrypted `.docx`/`.xlsx`/`.pptx` is the ZIP
/// itself. Anything else is [`Container::Unknown`]. Both containers are decided on their
/// magic alone, so a CFB or ZIP whose header is present is reported as that container
/// even when nothing inside it can be read — what could not be read shows up in
/// [`Classification::family`], not here.
///
/// # Examples
///
/// ```
/// use msoffice_crypto::{classify, Container};
///
/// assert_eq!(
///     classify(include_bytes!("../tests/fixtures/agile_encrypted.docx")).container,
///     Container::Cfb
/// );
/// assert_eq!(
///     classify(include_bytes!("../tests/fixtures/plain.docx")).container,
///     Container::Zip
/// );
/// assert_eq!(classify(b"not a file").container, Container::Unknown);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Container {
    /// Compound Binary File — magic `D0 CF 11 E0 A1 B1 1A E1`. What Office produces
    /// when a document is encrypted with a password.
    Cfb,
    /// A ZIP archive — magic `PK\x03\x04` (also `PK\x05\x06` for an empty archive and
    /// `PK\x07\x08` for a spanned one). An unencrypted OOXML package looks like this.
    Zip,
    /// Neither, or too short to tell.
    Unknown,
}

/// Which application format a container holds.
///
/// Orthogonal to [`Container`] and to [`Family`]: an encrypted `.docx` and an encrypted
/// `.doc` are both [`Container::Cfb`], and both can carry RC4 CryptoAPI, but they are
/// entirely different formats inside and only one of them this crate can read. Without
/// this a caller cannot tell those two apart, which is the difference between
/// "encrypted Word 97-2003 document, unsupported" and "unknown".
///
/// # Examples
///
/// ```
/// use msoffice_crypto::{classify, Document};
///
/// assert_eq!(
///     classify(include_bytes!("../tests/fixtures/plain.docx")).document,
///     Document::OoxmlPackage
/// );
/// assert_eq!(classify(b"????").document, Document::Unknown);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Document {
    /// An OOXML package — `.docx` / `.xlsx` / `.pptx` and their macro-enabled and binary
    /// (`.xlsb`) siblings — either plain, or wrapped in a CFB by ECMA-376 encryption.
    ///
    /// From a plain archive this is decided by the ZIP signature alone and no entry is
    /// read, so any ZIP lands here — an `.odt` for the sibling crate included.
    OoxmlPackage,
    /// Word 97-2003 binary (`.doc`).
    WordBinary,
    /// Excel 97-2003 binary (`.xls`).
    ExcelBinary,
    /// PowerPoint 97-2003 binary (`.ppt`).
    PowerPointBinary,
    /// Not recognised.
    Unknown,
}

/// Which MS-OFFCRYPTO encryption family the `EncryptionInfo` version pair names.
///
/// The pair alone does not always settle it: `vMinor = 2` covers **both** ECMA-376
/// standard (AES) encryption and RC4 CryptoAPI, and the discriminator is the
/// `fAES` bit of `EncryptionHeader.Flags` ([MS-OFFCRYPTO] §2.3.1).
///
/// # Examples
///
/// ```
/// use msoffice_crypto::{classify, Family};
///
/// assert_eq!(
///     classify(include_bytes!("../tests/fixtures/agile_encrypted.docx")).family,
///     Family::Agile
/// );
/// assert_eq!(
///     classify(include_bytes!("../tests/fixtures/plain.docx")).family,
///     Family::Unencrypted
/// );
/// ```
///
/// # See Also
///
/// [`Classification::is_encrypted`] and [`Classification::is_supported`] are the
/// predicates built on this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Family {
    /// Not Office-encrypted: a plain ZIP package, or a container whose own records
    /// *prove* there is no password — a `.doc` with `fEncrypted` clear, a workbook that
    /// reads a must-be-encrypted record in the clear, a presentation whose `UserEditAtom`
    /// is the unencrypted shape.
    ///
    /// A container this crate recognises but cannot read to a verdict is
    /// [`Family::Unknown`], never this: saying "unencrypted" without the proof would be a
    /// guess in the attacker's favour.
    Unencrypted,
    /// ECMA-376 agile encryption, `vMajor = 4`, `vMinor = 4`. Office 2010 and later.
    Agile,
    /// ECMA-376 standard encryption, `vMajor` 2/3/4 with `vMinor = 2` and `fAES` set.
    /// Office 2007.
    Standard,
    /// RC4 CryptoAPI — the same `vMinor = 2` version pair with `fAES` **clear**
    /// ([MS-OFFCRYPTO] §2.3.5). Office XP/2003's password-to-open for the binary
    /// formats, and what Office 16 still writes into a `.doc`, `.xls` or `.ppt`.
    /// Decrypted by `decrypt_binary_office` under the `legacy-binary` feature when the
    /// document is one of those three; an `EncryptionInfo` container declaring it is
    /// recognised and refused.
    Rc4CryptoApi,
    /// Office binary document RC4 encryption — version `1.1`, MD5, "Office 97/2000
    /// Compatible" ([MS-OFFCRYPTO] §2.3.6). Binary documents only; decrypted under
    /// `legacy-binary`.
    Rc4,
    /// XOR obfuscation ([MS-OFFCRYPTO] §2.3.7): a `.xls` whose `FILEPASS` declares
    /// `wEncryptionType = 0`, or a `.doc` with `fObfuscated` set. A distinct scheme, not a
    /// weak RC4. The Excel form is decrypted under `legacy-binary`; the Word form
    /// (Method 2) is named and refused.
    XorObfuscation,
    /// An `EncryptionInfo` stream whose version pair names a family this crate does not
    /// implement — reached by extensible encryption (`vMinor = 3`) and by any pair the
    /// spec does not define at all — or a `vMinor = 2` stream whose `AlgID` names no
    /// cipher this crate recognises with `fAES` clear, or whose `EncryptionHeader` is too
    /// short to read at all, or a binary document that declares encryption without a
    /// header this crate can read. The file *is* encrypted.
    Unsupported,
    /// Nothing could be determined — not a container this crate reads, or one whose
    /// `EncryptionInfo` stream is missing, truncated or unparsable.
    Unknown,
}

/// The cipher a file names for its payload.
///
/// Reported as `Option<CipherAlgorithm>`: `None` means the attribute or field was
/// absent, or named something this crate does not recognise. A classifier that
/// invented a value for either case would be worse than one that says "I could not
/// tell".
///
/// # Examples
///
/// ```
/// use msoffice_crypto::{classify, CipherAlgorithm};
///
/// let class = classify(include_bytes!("../tests/fixtures/agile_encrypted.docx"));
/// assert_eq!(class.key_data.unwrap().cipher, Some(CipherAlgorithm::Aes));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CipherAlgorithm {
    /// Agile `cipherAlgorithm="AES"`, or a standard-encryption header with `fAES` set
    /// or an `AlgID` in the AES range.
    Aes,
    /// RC4 — `AlgID = 0x00006801` with `fAES` clear ([MS-OFFCRYPTO] §2.3.2).
    Rc4,
}

/// The hash a file names.
///
/// This is the same enum the decrypt path runs on (`hash.rs` adds the digest, HMAC and
/// IV-derivation operations to it under the `crypto-ops` feature), so there is one
/// spelling table rather than a reporting copy that can drift from an operational one.
///
/// Reported as `Option<HashAlgorithm>`, with `None` meaning absent **or** not one of the
/// four this crate implements.
///
/// # Examples
///
/// ```
/// use msoffice_crypto::{classify, HashAlgorithm};
///
/// let class = classify(include_bytes!("../tests/fixtures/agile_encrypted.docx"));
/// assert_eq!(class.key_data.unwrap().hash, Some(HashAlgorithm::Sha512));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// SHA-1, 20-byte digest.
    Sha1,
    /// SHA-256, 32-byte digest.
    Sha256,
    /// SHA-384, 48-byte digest.
    Sha384,
    /// SHA-512, 64-byte digest. What Office 16 writes for agile.
    Sha512,
}

impl HashAlgorithm {
    /// Office writes `SHA512`; the hyphenated spelling is accepted defensively.
    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name {
            "SHA1" | "SHA-1" => Some(Self::Sha1),
            "SHA256" | "SHA-256" => Some(Self::Sha256),
            "SHA384" | "SHA-384" => Some(Self::Sha384),
            "SHA512" | "SHA-512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// One parameter set, as the file declares it.
///
/// Every field is `Option` because every one of them is optional in at least one of the
/// two formats: agile writes all six on `<p:encryptedKey>` and five on `<keyData>`
/// (no `spinCount`), while standard encryption declares a cipher, a hash, a key length
/// and a salt size, and fixes the remaining two by spec — AES-ECB has no `blockSize`, and
/// [MS-OFFCRYPTO] §2.3.4.7 fixes the spin count at 50 000 rather than carrying it in the
/// file.
///
/// The numbers are reported **unbounded and unvalidated** — `spin_count` may be
/// `u32::MAX`, `key_bits` may be 7. Bounding them is `decrypt`'s job
/// (`crate::limits`); a classifier that refused to report a hostile value would leave
/// its caller unable to see what it was refusing.
///
/// # Examples
///
/// ```
/// use msoffice_crypto::classify;
///
/// let class = classify(include_bytes!("../tests/fixtures/agile_encrypted.docx"));
/// let password = class.password_key.expect("agile files declare a password encryptor");
/// assert_eq!(password.spin_count, Some(100_000));
/// assert_eq!(password.key_bits, Some(256));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct AlgorithmParams {
    /// `cipherAlgorithm`, or standard encryption's `AlgID` + `fAES`.
    pub cipher: Option<CipherAlgorithm>,
    /// `hashAlgorithm`, or standard encryption's `AlgIDHash`.
    pub hash: Option<HashAlgorithm>,
    /// `keyBits`, or standard encryption's `EncryptionHeader.KeySize`.
    pub key_bits: Option<u32>,
    /// `blockSize` — the cipher block / IV truncation length. Agile only: standard
    /// encryption is AES-ECB and declares no block size field.
    pub block_size: Option<u32>,
    /// `saltSize`, or standard encryption's `EncryptionVerifier.SaltSize`.
    pub salt_size: Option<u32>,
    /// `spinCount` — the password KDF iteration count. Agile `<p:encryptedKey>` only:
    /// `<keyData>` has no such attribute, and standard encryption fixes it at 50 000 by
    /// spec rather than declaring it.
    pub spin_count: Option<u32>,
}

/// Whether the file declares a `dataIntegrity` element (design commitment D1).
///
/// This is the pre-flight answer to "will `IntegrityPolicy::Require` work on
/// this file?" — the after-the-fact answer is `IntegrityOutcome`, which reports
/// what actually happened during a decrypt. Those two names exist only under
/// `crypto-ops`, so they are not linked from this page.
///
/// # Examples
///
/// ```
/// use msoffice_crypto::{classify, IntegrityDeclaration};
///
/// assert_eq!(
///     classify(include_bytes!("../tests/fixtures/agile_encrypted.docx")).data_integrity,
///     IntegrityDeclaration::Declared
/// );
/// assert_eq!(
///     classify(include_bytes!("../tests/fixtures/plain.docx")).data_integrity,
///     IntegrityDeclaration::NotApplicable
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntegrityDeclaration {
    /// `<dataIntegrity>` is present and carries both `encryptedHmacKey` and
    /// `encryptedHmacValue`. `Require` will verify it.
    Declared,
    /// `<dataIntegrity>` is present but one of the two blobs is missing. `decrypt`
    /// refuses this with `Error::BadParameters` (a `crypto-ops` type, so not linked from this doc, which renders in every build): a half-written
    /// element is malformed, not absent. Collapsing the two would report a corrupt tag
    /// as a *stripped* one under the default policy, and under the explicitly chosen
    /// `VerifyIfPresent` and `Skip` policies would decrypt the file and call it
    /// `NotDeclared`.
    Incomplete,
    /// An agile file that declares no `<dataIntegrity>` element.
    ///
    /// **`decrypt` refuses this under the default policy** (GH #12). No agile writer
    /// surveyed omits the element and no file in any local corpus lacks it, so absence
    /// reads as a stripped or malformed file rather than an old one — accepting it by
    /// default would let an attacker disable tamper detection by deleting the thing that
    /// detects tampering. Only the explicitly chosen `VerifyIfPresent` and `Skip`
    /// policies decrypt it, and this variant is the pre-flight warning that one of them
    /// will be needed.
    Absent,
    /// The format defines no integrity element at all — ECMA-376 standard encryption
    /// ([MS-OFFCRYPTO] §2.3.4.5), RC4 CryptoAPI (§2.3.5), Office 97/2000 RC4 (§2.3.6),
    /// XOR obfuscation (§2.3.7) — or the file is not encrypted. Absence here is the spec,
    /// not a defect.
    NotApplicable,
    /// Could not be determined, because nothing about the encryption could be.
    Unknown,
}

/// What [`classify()`] found. Never an error: an unreadable file is `Unknown`, not a
/// failure.
///
/// # Examples
///
/// ```
/// use msoffice_crypto::{classify, Container, Family, IntegrityDeclaration};
///
/// let class = classify(b"not an office file at all");
/// assert_eq!(class.container, Container::Unknown);
/// assert_eq!(class.family, Family::Unknown);
/// assert_eq!(class.data_integrity, IntegrityDeclaration::Unknown);
/// assert!(!class.is_encrypted());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Classification {
    /// The container shape.
    pub container: Container,
    /// The application format inside the container.
    pub document: Document,
    /// `EncryptionVersionInfo` as `(vMajor, vMinor)`: from the `EncryptionInfo` stream
    /// when one is present and at least 8 bytes long, and from the binary formats' own
    /// CryptoAPI `EncryptionHeader` for a `.doc` / `.xls` / `.ppt`, which carry no such
    /// stream. `None` when neither could be read, and for the schemes that predate the
    /// header — XOR obfuscation names no version.
    pub version: Option<(u16, u16)>,
    /// The encryption family the version pair — and, for `vMinor = 2`, the `fAES` flag —
    /// names.
    pub family: Family,
    /// Parameters governing the **payload**: agile `<keyData>`, standard encryption's
    /// `EncryptionHeader` plus `EncryptionVerifier.SaltSize`, or — for a 97-2003 binary
    /// document — the `keyBits` its CryptoAPI `EncryptionHeader` exposes, which is the
    /// only member of the tuple those formats give up without decrypting. The rest stay
    /// `None` rather than being invented.
    pub key_data: Option<AlgorithmParams>,
    /// Parameters governing the **password key encryptor**: agile `<p:encryptedKey>`.
    /// `None` for standard encryption, which has a single parameter set.
    pub password_key: Option<AlgorithmParams>,
    /// Whether a `dataIntegrity` element is declared (D1).
    pub data_integrity: IntegrityDeclaration,
}

impl Classification {
    /// `true` when the file declares a password-to-open — an `EncryptionInfo` stream, or
    /// a 97-2003 binary document's own encryption marker — including a family this crate
    /// cannot decrypt.
    ///
    /// `false` also covers "nothing could be determined": an `EncryptionInfo` too short to
    /// hold a version pair leaves [`Family::Unknown`], which is not a claim that the file
    /// is plain.
    ///
    /// Deliberately not "can I decrypt this": see [`Classification::is_supported`].
    ///
    /// # Examples
    ///
    /// ```
    /// use msoffice_crypto::classify;
    ///
    /// assert!(classify(include_bytes!("../tests/fixtures/agile_encrypted.docx")).is_encrypted());
    /// assert!(!classify(include_bytes!("../tests/fixtures/plain.docx")).is_encrypted());
    /// ```
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        matches!(
            self.family,
            Family::Agile
                | Family::Standard
                | Family::Rc4CryptoApi
                | Family::Rc4
                | Family::XorObfuscation
                | Family::Unsupported
        )
    }

    /// `true` when a decrypt path of this crate implements the (document, family) pair —
    /// `decrypt_ooxml` for an OOXML package under `crypto-ops`, `decrypt_binary_office`
    /// for a `.doc`, `.xls` or `.ppt` under `legacy-binary`. In a build without the
    /// feature this still answers, and describes what enabling it would open.
    ///
    /// Says nothing about whether the *parameters* are ones this crate accepts:
    /// a legal agile file with a `spinCount` over the ceiling classifies as
    /// [`Family::Agile`], reports `true` here, and is refused at decrypt. Family-level,
    /// not tuple-level, by design — the tuple is in [`Classification::key_data`]. The
    /// document matters because the same family means different things in different
    /// containers: an `EncryptionInfo` stream naming RC4 CryptoAPI is refused, a `.doc`
    /// carrying it is read, and XOR obfuscation is read in a `.xls` and refused in a
    /// `.doc`.
    ///
    /// # Examples
    ///
    /// ```
    /// use msoffice_crypto::classify;
    ///
    /// assert!(classify(include_bytes!("../tests/fixtures/agile_encrypted.docx")).is_supported());
    /// assert!(!classify(include_bytes!("../tests/fixtures/plain.docx")).is_supported());
    /// ```
    #[must_use]
    pub fn is_supported(&self) -> bool {
        matches!(
            (self.document, self.family),
            (Document::OoxmlPackage, Family::Agile | Family::Standard)
                | (
                    Document::WordBinary | Document::ExcelBinary | Document::PowerPointBinary,
                    Family::Rc4CryptoApi | Family::Rc4,
                )
                | (Document::ExcelBinary, Family::XorObfuscation)
        )
    }
}

/// Report what encryption `data` declares, without decrypting it.
///
/// Reads the `EncryptionInfo` stream (capped at `limits::ENCRYPTION_INFO_READ_CAP`) and,
/// for a CFB that carries none, the 97-2003 binary streams the probe needs —
/// `/WordDocument` and its table stream at `limits::BINARY_HEADER_READ_CAP`, the workbook
/// at `limits::BIFF_SCAN_CAP`, `/Current User` at `limits::CURRENT_USER_READ_CAP`, and a
/// bounded walk of `/PowerPoint Document`. Every read is capped and the `EncryptedPackage`
/// payload is never touched. Needs no cryptographic dependency and is available in the
/// default build.
///
/// **This function does not panic and does not fail.** Truncated, corrupt, hostile and
/// empty inputs all produce a [`Classification`] whose unreadable parts are `Unknown` or
/// `None`. That is the single property that makes it safe as the first thing a caller
/// runs on a file from outside.
///
/// # Examples
///
/// A real agile-encrypted document:
///
/// ```
/// use msoffice_crypto::{classify, CipherAlgorithm, Container, Family,
///                       HashAlgorithm, IntegrityDeclaration};
///
/// let bytes = include_bytes!("../tests/fixtures/agile_encrypted.docx");
/// let class = classify(bytes);
///
/// assert_eq!(class.container, Container::Cfb);
/// assert_eq!(class.version, Some((4, 4)));
/// assert_eq!(class.family, Family::Agile);
/// assert_eq!(class.data_integrity, IntegrityDeclaration::Declared);
///
/// let key_data = class.key_data.expect("agile files declare <keyData>");
/// assert_eq!(key_data.cipher, Some(CipherAlgorithm::Aes));
/// assert_eq!(key_data.hash, Some(HashAlgorithm::Sha512));
/// assert_eq!(key_data.key_bits, Some(256));
///
/// let password = class.password_key.expect("…and a password key encryptor");
/// assert_eq!(password.spin_count, Some(100_000));
/// ```
///
/// An unencrypted package:
///
/// ```
/// use msoffice_crypto::{classify, Container, Family, IntegrityDeclaration};
///
/// let class = classify(include_bytes!("../tests/fixtures/plain.docx"));
/// assert_eq!(class.container, Container::Zip);
/// assert_eq!(class.family, Family::Unencrypted);
/// assert_eq!(class.data_integrity, IntegrityDeclaration::NotApplicable);
/// assert!(!class.is_encrypted());
/// ```
///
/// # See Also
///
/// [`crate::is_cfb_office`] is the cheaper magic-byte check.
/// [`Classification::is_supported`] is whether a decrypt path of this crate implements
/// the pair; that is not a promise the parameters will be accepted.
#[must_use]
pub fn classify(data: &[u8]) -> Classification {
    if crate::is_cfb_office(data) {
        return classify_cfb(data);
    }
    if is_zip(data) {
        return Classification {
            container: Container::Zip,
            document: Document::OoxmlPackage,
            version: None,
            family: Family::Unencrypted,
            key_data: None,
            password_key: None,
            data_integrity: IntegrityDeclaration::NotApplicable,
        };
    }
    unknown(Container::Unknown)
}

/// Everything-unreadable result for a container we could name but not read.
fn unknown(container: Container) -> Classification {
    unknown_document(container, Document::Unknown)
}

/// `unknown`, for a container whose *format* was recognised even though its encryption
/// was not. A legacy binary document reaches this: we know it is a `.doc`, which is
/// strictly more than we knew before.
fn unknown_document(container: Container, document: Document) -> Classification {
    Classification {
        container,
        document,
        version: None,
        family: Family::Unknown,
        key_data: None,
        password_key: None,
        data_integrity: IntegrityDeclaration::Unknown,
    }
}

fn is_zip(data: &[u8]) -> bool {
    data.len() >= 4
        && data[0] == b'P'
        && data[1] == b'K'
        && matches!((data[2], data[3]), (3, 4) | (5, 6) | (7, 8))
}

fn classify_cfb(data: &[u8]) -> Classification {
    // No `EncryptionInfo` does not mean "unreadable". The 97-2003 binary formats are CFB
    // containers too and carry their encryption inside their own records, so ask them
    // before giving up -- otherwise an encrypted `.doc` classifies identically to a
    // corrupt file, which is the failure this crate made in GH #11 and LibreOffice makes
    // on `.ppt` to this day.
    let Ok(info) = cfb_reader::read_encryption_info(data) else {
        return classify_binary(data);
    };
    if info.len() < 8 {
        return classify_binary(data);
    }

    let v_major = u16::from_le_bytes([info[0], info[1]]);
    let v_minor = u16::from_le_bytes([info[2], info[3]]);
    let version = Some((v_major, v_minor));

    match (v_major, v_minor) {
        (4, 4) => classify_agile(&info[8..], version),
        (2..=4, 2) => classify_standard(&info[8..], version),
        // Everything else carries an EncryptionInfo — so it *is* encrypted — but names a
        // family this crate does not implement. Extensible encryption (vMajor 3 or 4 with
        // vMinor = 3, [MS-OFFCRYPTO] §2.3.4.6) is the case that reaches this in the wild; its
        // parameters live in a provider-defined blob rather than in fields this crate
        // could report, so no tuple comes back with it.
        _ => Classification {
            container: Container::Cfb,
            document: Document::OoxmlPackage,
            version,
            family: Family::Unsupported,
            key_data: None,
            password_key: None,
            data_integrity: IntegrityDeclaration::Unknown,
        },
    }
}

/// Classify a CFB container that carries no `EncryptionInfo`: a 97-2003 binary document,
/// or something this crate does not recognise at all.
///
/// The families here are named for the *scheme*, and the `document` field for the
/// *format*, because they vary independently: ECMA-376 standard encryption can also carry
/// an RC4 AlgID, so `Family::Rc4CryptoApi` alone would not tell a `.doc` from a `.docx`.
fn classify_binary(data: &[u8]) -> Classification {
    let Some(v) = binary_office::probe(data) else {
        return unknown(Container::Cfb);
    };

    let document = match v.format {
        binary_office::BinaryFormat::Word => Document::WordBinary,
        binary_office::BinaryFormat::Excel => Document::ExcelBinary,
        binary_office::BinaryFormat::PowerPoint => Document::PowerPointBinary,
    };

    let family = match (v.encrypted, v.xor_obfuscated, v.version) {
        // Recognised the format, could not reach its encryption marker. Saying
        // "unencrypted" here would be a guess in the attacker's favour.
        (None, _, _) => Family::Unknown,
        (Some(false), _, _) => Family::Unencrypted,
        // XOR obfuscation is a distinct scheme, not a weak RC4.
        (Some(true), true, _) => Family::XorObfuscation,
        (Some(true), false, Some((2..=4, 2))) => Family::Rc4CryptoApi,
        // Office 97/2000 RC4, version 1.1.
        (Some(true), false, Some((1, 1))) => Family::Rc4,
        // Anything else that claims to be encrypted without a version pair this crate
        // can name -- including a PowerPoint file whose CryptSession10Container could
        // not be reached, and a BIFF5 workbook whose FILEPASS has no version at all.
        (Some(true), false, _) => Family::Unsupported,
    };

    Classification {
        container: Container::Cfb,
        document,
        version: v.version,
        // `key_bits` is the only parameter these formats expose without decrypting, and
        // only the CryptoAPI-era header carries it. The rest of `AlgorithmParams` stays
        // `None` rather than being invented.
        key_data: v.key_bits.map(|bits| AlgorithmParams {
            cipher: None,
            hash: None,
            key_bits: Some(bits),
            block_size: None,
            salt_size: None,
            spin_count: None,
        }),
        family,
        password_key: None,
        // None of the binary formats defines an integrity element.
        data_integrity: IntegrityDeclaration::NotApplicable,
    }
}

// ---- agile ---------------------------------------------------------------------------

/// Parse the agile `EncryptionInfo` XML for reporting only.
///
/// Deliberately far more forgiving than `agile::parse_encryption_info`: a missing
/// attribute is a `None` field, a non-numeric one is a `None` field, and an XML error
/// stops the scan and keeps whatever was already read. Nothing here can reject a file —
/// rejecting is `decrypt`'s job, and a classifier that refused to describe a malformed
/// file would be useless in exactly the case a caller most needs a description.
fn classify_agile(xml: &[u8], version: Option<(u16, u16)>) -> Classification {
    let mut key_data = AlgorithmParams::default();
    let mut password_key = AlgorithmParams::default();
    let mut saw_key_data = false;
    let mut saw_password_key = false;
    let mut saw_data_integrity = false;
    let mut saw_hmac_key = false;
    let mut saw_hmac_value = false;

    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let name = e.name().as_ref().to_vec();
                match local_name(&name) {
                    b"keyData" => {
                        saw_key_data = true;
                        read_params(e, &mut key_data);
                    }
                    // Matched on the local name, so `<p:encryptedKey>` and a bare
                    // `<encryptedKey>` both land here — as does a *certificate* key
                    // encryptor's `<c:encryptedKey>`, which this crate cannot use. That
                    // is a known looseness shared with `agile::parse_encryption_info`
                    // and is recorded rather than fixed here: making the two parsers
                    // disagree about which element they mean would be worse than the
                    // looseness itself.
                    b"encryptedKey" => {
                        saw_password_key = true;
                        read_params(e, &mut password_key);
                    }
                    b"dataIntegrity" => {
                        saw_data_integrity = true;
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"encryptedHmacKey" => saw_hmac_key = true,
                                b"encryptedHmacValue" => saw_hmac_value = true,
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            // Stop on EOF *and* on a parse error, keeping whatever was read before it.
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    let data_integrity = match (saw_data_integrity, saw_hmac_key && saw_hmac_value) {
        (true, true) => IntegrityDeclaration::Declared,
        (true, false) => IntegrityDeclaration::Incomplete,
        (false, _) => IntegrityDeclaration::Absent,
    };

    Classification {
        container: Container::Cfb,
        document: Document::OoxmlPackage,
        version,
        family: Family::Agile,
        key_data: saw_key_data.then_some(key_data),
        password_key: saw_password_key.then_some(password_key),
        data_integrity,
    }
}

fn read_params(e: &quick_xml::events::BytesStart<'_>, into: &mut AlgorithmParams) {
    for attr in e.attributes().flatten() {
        match attr.key.as_ref() {
            b"cipherAlgorithm" => {
                into.cipher = attr_str(&attr).and_then(|v| match v.as_str() {
                    "AES" => Some(CipherAlgorithm::Aes),
                    "RC4" => Some(CipherAlgorithm::Rc4),
                    _ => None,
                });
            }
            b"hashAlgorithm" => {
                into.hash = attr_str(&attr).as_deref().and_then(HashAlgorithm::parse);
            }
            b"keyBits" => into.key_bits = attr_u32(&attr),
            b"blockSize" => into.block_size = attr_u32(&attr),
            b"saltSize" => into.salt_size = attr_u32(&attr),
            b"spinCount" => into.spin_count = attr_u32(&attr),
            _ => {}
        }
    }
}

// `normalized_value(Implicit1_0)` rather than the deprecated `unescape_value()`, which
// quick-xml 0.41 removed from the non-deprecated surface. This is not an equivalent call,
// it is the *same* call: 0.41's `unescape_value` is defined as
// `normalized_value_with(XmlVersion::Implicit1_0, 1, resolve_predefined_entity)`
// (quick-xml-0.41.0/src/events/attributes.rs:299) and `normalized_value(v)` as
// `normalized_value_with(v, 1, resolve_predefined_entity)` (:84). So the behaviour of this
// parser on every input, hostile ones included, is unchanged by the rename.
//
// `Implicit1_0` is also the correct version to assert independently of the deprecation.
// It means "no XML declaration was parsed, so 1.0 is assumed" -- and this crate reads
// EncryptionInfo with a plain `Reader` that never inspects the declaration. The only
// thing the choice controls is whether `` and ` 28` normalise to a space, which
// they do in 1.1 and not in 1.0; no value this parser reads (an algorithm token, a
// base64 blob, a decimal integer) may legally contain either.
fn attr_str(attr: &quick_xml::events::attributes::Attribute<'_>) -> Option<String> {
    attr.normalized_value(quick_xml::XmlVersion::Implicit1_0)
        .ok()
        .map(|v| v.into_owned())
}

fn attr_u32(attr: &quick_xml::events::attributes::Attribute<'_>) -> Option<u32> {
    attr_str(attr).and_then(|v| v.parse::<u32>().ok())
}

/// Strip a namespace prefix from an element name (`p:encryptedKey` → `encryptedKey`).
///
/// Shared with `agile::parse_encryption_info` so the two cannot disagree about which
/// elements they are looking at.
pub(crate) fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().position(|&b| b == b':') {
        Some(pos) => &name[pos + 1..],
        None => name,
    }
}

// ---- standard / RC4 CryptoAPI --------------------------------------------------------

/// `EncryptionHeaderFlags.fAES` — [MS-OFFCRYPTO] §2.3.1.
///
/// This bit, not the version pair, is what separates ECMA-376 standard (AES) encryption
/// from RC4 CryptoAPI: both are written with `vMinor = 2`.
const FLAG_AES: u32 = 0x0000_0020;

/// `AlgID` values — [MS-OFFCRYPTO] §2.3.2, the `wincrypt.h` `CALG_*` constants.
const ALG_ID_RC4: u32 = 0x0000_6801;
const ALG_ID_AES_128: u32 = 0x0000_660E;
const ALG_ID_AES_192: u32 = 0x0000_660F;
const ALG_ID_AES_256: u32 = 0x0000_6610;

/// `AlgIDHash` values — [MS-OFFCRYPTO] §2.3.2, the `wincrypt.h` `CALG_*` hash constants.
const ALG_ID_HASH_SHA1: u32 = 0x0000_8004;
const ALG_ID_HASH_SHA256: u32 = 0x0000_800C;
const ALG_ID_HASH_SHA384: u32 = 0x0000_800D;
const ALG_ID_HASH_SHA512: u32 = 0x0000_800E;

/// Offsets within `EncryptionHeader` — [MS-OFFCRYPTO] §2.3.2. `standard::decrypt` reads
/// the same layout; these names exist so the offsets are stated once in prose.
const HDR_FLAGS: usize = 0;
const HDR_ALG_ID: usize = 8;
const HDR_ALG_ID_HASH: usize = 12;
const HDR_KEY_SIZE: usize = 16;
/// `CSPName`, a null-terminated UTF-16LE string, starts here and runs to the
/// `EncryptionVerifier`.
const HDR_CSP_NAME: usize = 32;

/// Parse the binary `EncryptionInfo` body of a `vMinor = 2` file, for reporting only.
///
/// `body` is the stream with the 8-byte `EncryptionVersionInfo` + `EncryptionHeaderFlags`
/// prefix already removed, so it begins at `EncryptionHeaderSize`.
///
/// Two fields are absent by construction rather than by omission and are reported as
/// `None`: `block_size` (this is AES-**ECB**, which has no chaining block to declare) and
/// `spin_count` ([MS-OFFCRYPTO] §2.3.4.7 fixes it at 50 000; the file does not carry it).
fn classify_standard(body: &[u8], version: Option<(u16, u16)>) -> Classification {
    let mut params = AlgorithmParams::default();
    let mut family = Family::Unsupported;

    // `EncryptionHeaderSize`, then the header itself. The size is not read here and does
    // not need to be: every field this function reports lives in the header's 32 fixed
    // bytes, which start immediately after it whatever it says. `standard::decrypt` does
    // read it — it is where the `EncryptionVerifier` begins ([MS-OFFCRYPTO] §2.3.4.5) —
    // and the two still agree about these offsets, which is all that matters for a
    // function whose contract is to report and never to refuse.
    if body.len() >= 4 + HDR_CSP_NAME {
        let header = &body[4..];
        let flags = read_u32(header, HDR_FLAGS);
        let alg_id = read_u32(header, HDR_ALG_ID);
        let alg_id_hash = read_u32(header, HDR_ALG_ID_HASH);
        let key_size = read_u32(header, HDR_KEY_SIZE);

        // fAES first, AlgID second. [MS-OFFCRYPTO] §2.3.1: "If the fAES encryption bit is
        // set, a block cipher that supports ECB mode MUST be used" — RC4 is a stream
        // cipher, so with the bit set the AlgID does not get to name RC4, and §2.3.2's
        // combination table has no `fAES` + `0x00006801` row to fall back on. Which is
        // what the `standard_encrypted.docx` fixture needs: it declares `fAES` **and**
        // `AlgID = 0x6801`, a combination the spec forbids, and it is AES-128 in fact (it
        // decrypts as such). Reading fAES first is both the spec's own precedence and the
        // reading that matches the corpus.
        let aes = flags & FLAG_AES != 0;
        params.cipher = if aes {
            Some(CipherAlgorithm::Aes)
        } else {
            match alg_id {
                ALG_ID_RC4 => Some(CipherAlgorithm::Rc4),
                ALG_ID_AES_128 | ALG_ID_AES_192 | ALG_ID_AES_256 => Some(CipherAlgorithm::Aes),
                _ => None,
            }
        };
        params.hash = match alg_id_hash {
            // 0x00000000 means "determined by Flags", which for every family here is
            // SHA-1: agile is the only MS-OFFCRYPTO format with a choice of hash.
            0 | ALG_ID_HASH_SHA1 => Some(HashAlgorithm::Sha1),
            ALG_ID_HASH_SHA256 => Some(HashAlgorithm::Sha256),
            ALG_ID_HASH_SHA384 => Some(HashAlgorithm::Sha384),
            ALG_ID_HASH_SHA512 => Some(HashAlgorithm::Sha512),
            _ => None,
        };
        params.key_bits = (key_size != 0).then_some(key_size);
        params.salt_size = verifier_salt_size(header);

        family = match params.cipher {
            Some(CipherAlgorithm::Aes) => Family::Standard,
            Some(CipherAlgorithm::Rc4) => Family::Rc4CryptoApi,
            None => Family::Unsupported,
        };
    }

    Classification {
        container: Container::Cfb,
        document: Document::OoxmlPackage,
        version,
        family,
        key_data: Some(params),
        password_key: None,
        // [MS-OFFCRYPTO] §2.3.4.5 defines no integrity element for this format, and the
        // RC4 families define none either. Absence is the spec, not a defect.
        data_integrity: IntegrityDeclaration::NotApplicable,
    }
}

/// `EncryptionVerifier.SaltSize`, found by walking `CSPName` to its UTF-16 terminator.
///
/// **Not** how `standard::decrypt` finds the verifier: that reader takes it at the
/// declared `EncryptionHeaderSize` ([MS-OFFCRYPTO] §2.3.4.5), because the scan lands in
/// the header's own padding on any file that puts bytes after `CSPName`. The two agree on
/// every conforming file, and the scan is kept here for the one property this function
/// needs and that one does not: it cannot fail. `classify` must answer on a header whose
/// size field is a lie, so it reads what is there and answers `None` for anything it
/// cannot reach, rather than refusing the file.
fn verifier_salt_size(header: &[u8]) -> Option<u32> {
    let mut pos = HDR_CSP_NAME;
    while pos + 1 < header.len() {
        if header[pos] == 0 && header[pos + 1] == 0 {
            pos += 2;
            break;
        }
        pos += 2;
    }
    let verifier = header.get(pos..)?;
    if verifier.len() < 4 {
        return None;
    }
    Some(read_u32(verifier, 0))
}

/// Little-endian `u32` at `offset`, or `0` when the slice is too short.
///
/// The zero default is what makes every caller above bound-free: `standard.rs`'s own
/// `read_u32` panics out of range and relies on a length guard forty lines away, which
/// is the shape this function exists not to have.
fn read_u32(data: &[u8], offset: usize) -> u32 {
    match data.get(offset..offset + 4) {
        Some(bytes) => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        None => 0,
    }
}

#[cfg(test)]
#[path = "classify_tests.rs"]
mod tests;
