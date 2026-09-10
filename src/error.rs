//! Failures from decryption and encryption.
//!
//! [`OoXmlCryptoError`] is re-exported at the crate root under `crypto-ops`. In a
//! detection-only build no public function returns a [`Result`], so the type is not
//! public there — see the enum's own docs.

use thiserror::Error;

/// Every reason this crate refuses a file.
///
/// `#[non_exhaustive]`: variants are still arriving — RC4 CryptoAPI decryption (GH #4)
/// and the encrypt path (GH #6) each add their own — and this crate's own testing rule
/// makes consumers match on variants by name, so a wildcard arm has to be theirs to
/// write. Free to add now; a breaking change the moment GH #9 publishes.
///
/// Nine of the fourteen variants exist only under `crypto-ops`, one only under
/// `legacy-binary`, and so does the public re-export of the type itself. In a
/// detection-only build no public function returns a `Result` — [`crate::classify()`]
/// answers every input and [`crate::is_cfb_office()`] is a `bool` — so the type would be a
/// public name nothing
/// produces. The four ungated variants are the ones the container reader constructs on
/// the way to `classify`, which swallows them.
///
/// Messages never carry key material. Where a message quotes the file —
/// [`OoXmlCryptoError::UnsupportedAlgorithm`]'s `name`, the lengths and declared values
/// interpolated into [`OoXmlCryptoError::BadParameters`] — it is bounded and truncated at
/// the construction site, and the variant says so. Match with a `_` arm: the enum does
/// not implement `PartialEq`.
// `unreachable_pub` fires on this type in the **detection** build and only there: the
// re-export at `lib.rs` is `#[cfg(feature = "crypto-ops")]`, so without that feature this
// is a `pub` item in a private module that nothing re-exports. That is the design the doc
// above describes, not an oversight — the type is the crate's public error under
// `crypto-ops` and `legacy-binary`, and `pub(crate)` would delete it from the public API.
//
// `allow` rather than `expect`: the lint fires in one of the three configurations, so an
// `expect` would itself go unfulfilled in the other two.
#[allow(unreachable_pub)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OoXmlCryptoError {
    /// The bytes are not a CFB container: they lack the eight-byte magic, or `cfb`
    /// refused to open them.
    #[error("not a CFB (Compound Binary File) container")]
    NotACfbFile,

    /// A binary document handed to [`crate::decrypt_binary_office()`] carries no password-to-open
    /// at all: the FIB's `fEncrypted` bit is clear, the workbook has no `FILEPASS`
    /// record, the presentation's `UserEditAtom` is the unencrypted shape.
    ///
    /// Its own variant, per CLAUDE.md § *Cryptographic Rules*: "there is nothing to
    /// decrypt" is a fact a caller acts on by using the bytes it already has, which is
    /// the opposite of what it does for every other variant here. [`crate::classify()`]
    /// reports the same file as [`crate::Family::Unencrypted`] wherever its own probe
    /// reached the marker; a workbook whose record walk ran out before proving anything is
    /// [`crate::Family::Unknown`] there — `Unencrypted` is a proof, not a default — while
    /// this path still answers `NotEncrypted`.
    #[error("the document is not encrypted; there is nothing to decrypt")]
    #[cfg(feature = "legacy-binary")]
    NotEncrypted,

    /// A required CFB stream is missing, unreadable, shorter than its header — or
    /// carries a fixed structural field this crate cannot proceed past.
    ///
    /// The payload names the stream or the structure (`"EncryptionInfo"`, `"Workbook"`,
    /// `"EncryptionVerifier missing or truncated"`, …). It is always a fixed
    /// `&'static str`, never attacker-chosen file content.
    #[error("required CFB stream missing or unreadable: {0}")]
    MissingStream(&'static str),

    /// The `EncryptionInfo` version pair names a format this crate does not implement.
    ///
    /// The message says only that, because that is all the pair tells us. It used to
    /// assert "Office XP/2003 RC4 encryption is not supported — re-save the file with
    /// Office 2007 or later" for *every* pair that reached it, including `vMinor = 3`
    /// (extensible encryption) and, until `standard::require_aes_128` landed, every
    /// Office 2007 file whose `AlgID` was the conforming `0x660E`. A cipher this crate
    /// has not implemented is [`OoXmlCryptoError::UnsupportedAlgorithm`]; this variant is
    /// for the version pair alone.
    #[error(
        "unsupported Office encryption version {0}.{1} \
        (this crate implements ECMA-376 standard encryption, vMinor 2, \
        and agile encryption, 4.4)"
    )]
    #[cfg(feature = "crypto-ops")]
    UnsupportedEncryptionVersion(u16, u16),

    /// The agile `EncryptionInfo` XML could not be parsed, or a required attribute was
    /// absent.
    ///
    /// Distinct from [`Self::BadParameters`]: that one is a value that parsed and is
    /// out of range; this one is XML that did not yield a value at all. The string
    /// describes the *shape* of the failure — an attribute name, a parse error — never
    /// key material.
    #[error("EncryptionInfo XML parse error: {0}")]
    #[cfg(feature = "crypto-ops")]
    XmlParse(String),

    /// The password verifier did not match.
    ///
    /// Distinct from [`Self::UnsupportedAlgorithm`] on purpose: that one is a file this
    /// crate cannot act on, and reporting it as a wrong password sends the user looking
    /// for a typo in a password that was right.
    #[error("wrong password")]
    #[cfg(feature = "crypto-ops")]
    WrongPassword,

    /// An AES operation rejected its input.
    ///
    /// Typically a ciphertext length that is not a block multiple — a truncated stream,
    /// not a wrong password. The encrypt path reaches it only if an internal length
    /// invariant fails.
    #[error("cipher operation failed")]
    #[cfg(feature = "crypto-ops")]
    CipherError,

    /// A parameter the file declares is out of range, or is inconsistent with a sibling
    /// parameter.
    ///
    /// The message describes the *shape* of the problem — a length, an attribute name,
    /// an algorithm name. It never carries key material or file content.
    ///
    /// Contrast [`OoXmlCryptoError::UnsupportedAlgorithm`], which is the file being
    /// internally consistent about something this crate has not implemented.
    #[error("unsupported or inconsistent encryption parameter: {0}")]
    BadParameters(String),

    /// The file names an algorithm this crate does not implement.
    ///
    /// **Distinct from [`OoXmlCryptoError::WrongPassword`] on purpose.** The password
    /// may be perfectly correct and simply unusable: before this variant existed, an
    /// agile file declaring `hashAlgorithm="SHA256"` derived a SHA-512 spin hash, failed
    /// the verifier comparison, and was reported as a wrong password — telling the user
    /// the one thing that was not true. `office-crypto` already returned a dedicated
    /// `Unimplemented` here (`src/lib.rs:29`), so silently misdiagnosing was strictly
    /// worse than the alternative this crate exists to improve on.
    ///
    /// `what` names the attribute — a fixed set of `&'static str`, never formatted, so
    /// this cannot become a second free-text channel. `name` is the file's own spelling,
    /// truncated: it is attacker-chosen XML attribute text, bounded only by
    /// `limits::ENCRYPTION_INFO_READ_CAP` (1 MiB) before it reaches here.
    #[error("{what} names an algorithm this crate does not implement: {name}")]
    #[cfg(feature = "crypto-ops")]
    UnsupportedAlgorithm {
        /// Which attribute named it, e.g. `p:encryptedKey/@hashAlgorithm`.
        what: &'static str,
        /// Either the algorithm name as the file spells it, truncated to 32 characters
        /// by `agile::unsupported_algorithm` — the one path where this is
        /// attacker-chosen text — or a fixed description of what was refused, sometimes a
        /// formatted `AlgID`. Never key material, and never unbounded file text.
        name: String,
    },

    /// The `dataIntegrity` HMAC did not match the `EncryptedPackage` stream.
    ///
    /// The password is verified before this check runs, so a failure here means the
    /// package was corrupted or modified — by someone who did *not* hold the password,
    /// since producing a matching tag requires the session key.
    #[error(
        "package integrity check failed: the encrypted package does not match its \
        dataIntegrity HMAC (the file is corrupt or was modified after encryption)"
    )]
    #[cfg(feature = "crypto-ops")]
    IntegrityCheckFailed,

    /// A file declaring **agile** encryption carries no `<dataIntegrity>` element, under
    /// a policy that requires one — which since GH #12 includes the default policy.
    ///
    /// Distinct from [`Self::IntegrityUnavailable`] on purpose, per CLAUDE.md
    /// § *Cryptographic Rules*: that one is a caller asking a format for a guarantee the
    /// format does not define, a property of the **request**. This one is a file that
    /// should carry a tag and does not, a property of the **file** — and deleting the
    /// element is the cheapest tamper there is, needing no password. A caller acts on
    /// the two differently, so they are different variants.
    ///
    /// The message names the opt-out, because at least one consumer flattens this error
    /// to its `Display` string and a dead end is a worse answer than a signposted one.
    /// The `Display` text names [`crate::IntegrityPolicy`]'s opt-out in plain words
    /// because a `#[error]` string cannot carry an intra-doc link.
    #[error(
        "this file declares agile encryption but carries no <dataIntegrity> element: \
        every known agile writer emits one, so it was removed or the file is malformed. \
        Pass IntegrityPolicy::VerifyIfPresent to decrypt it anyway, unverified"
    )]
    #[cfg(feature = "crypto-ops")]
    IntegrityElementMissing,

    /// An integrity guarantee was demanded of a format that defines no integrity tag at
    /// all — `IntegrityPolicy::Require` on ECMA-376 standard encryption (Office 2007).
    ///
    /// An *agile* file missing its element is [`Self::IntegrityElementMissing`] instead:
    /// that is a defect in the file, this is a limit of the format.
    ///
    /// Both this variant and [`crate::IntegrityPolicy`] exist only under `crypto-ops`,
    /// so the link resolves in every configuration that renders it.
    #[error("integrity verification was required, but {0}")]
    #[cfg(feature = "crypto-ops")]
    IntegrityUnavailable(&'static str),

    /// The random source failed while generating key material.
    ///
    /// Its own variant rather than folding into [`Self::CipherError`], per CLAUDE.md
    /// § *Cryptographic Rules*: a CSPRNG that will not produce bytes is an environment
    /// failure a caller may be able to act on — a sandbox with no `getrandom`, an
    /// exhausted file-descriptor table — and it is emphatically **not** the same fact as
    /// "the cipher rejected this input". Encryption is the only path that reaches it;
    /// decryption generates nothing.
    ///
    /// The string is the RNG's own `Display`, which describes *the source* — never its
    /// output. No generated byte can reach here: on failure there is nothing generated.
    #[error("the random source failed while generating key material: {0}")]
    #[cfg(feature = "crypto-ops")]
    RandomSource(String),

    /// Reading or writing the in-memory CFB container failed.
    ///
    /// The inner [`std::io::Error`] describes the operation — a flush, a stream write —
    /// never key material or file content.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
