//! Failures from decryption and encryption.
//!
//! [`Error`] is re-exported at the crate root under `crypto-ops`. In a
//! detection-only build no public function returns a [`Result`], so the type is not
//! public there — see the enum's own docs.

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
/// [`Error::UnsupportedAlgorithm`]'s `name`, the lengths and declared values
/// interpolated into [`Error::BadParameters`] — it is bounded and truncated at
/// the construction site, and the variant says so. Match with a `_` arm: the enum does
/// not implement `PartialEq`.
///
/// # Who the messages are written for
///
/// **A programmer choosing a policy, not the person holding the file.** Several name a
/// [`crate::IntegrityPolicy`] variant, which is a Rust path and useful only to whoever
/// writes the call. A consumer that renders a failure to an end user should **match on
/// the variant and write its own copy**, not forward `Display`.
///
/// That is a real hazard rather than a style note, and it was found by a consumer reading
/// its own test output. The three integrity failures are *not* symmetric in what their
/// opt-out costs:
///
/// - [`Error::IntegrityCheckFailed`] offers none, because there is none.
/// - [`Error::IntegrityUnavailable`]'s is a property of the **format** — a 2007 file has
///   no tag to check, and opening it anyway concedes only what that format never offered.
/// - [`Error::IntegrityElementMissing`]'s is "decrypt evidence of tampering anyway", on a
///   file whose missing element is, per that variant's docs, never innocent.
///
/// Forwarded uniformly, the third reaches the person holding the file as instructions for
/// opening the document an attacker prepared for them. The message says what the opt-out
/// concedes, so that forwarding it is at worst unhelpful rather than misleading — but the
/// fix is to map the variant, and this paragraph exists so that nobody has to discover
/// that by reading test output a second time.
///
/// # What `source()` returns, and why it is mostly `None`
///
/// `None` for every variant except [`Error::Io`] — deliberately, and not for want of
/// `thiserror`. The variants that wrap a foreign failure reduce it to a string instead of
/// holding it behind `#[source]`. Holding it would reopen, in two places rather than one,
/// the conduit that reduction exists to close: `source()` would hand a caller the
/// dependency's `Display`, and this enum's derived `Debug` would print it. A walkable
/// error chain is worth less here than a message this crate can characterise completely —
/// this type's whole input is a document an attacker wrote.
///
/// The three foreign failures are not treated alike, and the difference is the point:
///
/// | Variant | Foreign `Display` | Why |
/// | --- | --- | --- |
/// | [`Error::XmlParse`] | **never** — classified by an exhaustive match | quick-xml quotes text drawn from the document |
/// | [`Error::RandomSource`] | forwarded, truncated to 200 characters | names an environment failure; on a failure nothing was generated |
/// | [`Error::Io`] | forwarded | `cfb` 0.14.0 audited: lengths and fixed strings only |
///
/// [`Error::Io`] is the one `#[from]`, and it does forward `std::io::Error`'s `Display`.
/// That is audited rather than assumed: on these paths the only producers are `cfb`,
/// whose `invalid_data!` messages interpolate lengths and fixed strings and never a
/// stream name or a file byte (`direntry.rs:118-140` in 0.14.0), and `std::io::Cursor`,
/// which fails only on allocation. **Re-check it on a `cfb` bump** — that is the standing
/// cost of a `#[from]` on a foreign error type, and the reason there is only one.
// `unreachable_pub` fires on this type in the **detection** build and only there: the
// re-export at `lib.rs` is `#[cfg(feature = "crypto-ops")]`, so without that feature this
// is a `pub` item in a private module that nothing re-exports. That is the design the doc
// above describes, not an oversight — the type is the crate's public error under
// `crypto-ops` and `legacy-binary`, and `pub(crate)` would delete it from the public API.
//
// `allow` rather than `expect`: the lint fires in one of the three configurations, so an
// `expect` would itself go unfulfilled in the other two.
#[allow(unreachable_pub)]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
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
    /// has not implemented is [`Error::UnsupportedAlgorithm`]; this variant is
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
    /// out of range; this one is XML that did not yield a value at all.
    ///
    /// **The string is always one this crate wrote.** No dependency's `Display` reaches
    /// it: `agile::xml_error` and `agile::base64_error` classify quick-xml and base64
    /// failures into fixed descriptions, and both match exhaustively, so a variant added
    /// upstream is a compile error here rather than a silent forward.
    ///
    /// That is a correction and not a description of how it always was. Until
    /// 2026-09-11 the quick-xml `Display` was forwarded verbatim by four call sites, three
    /// of which run on attribute *values* — `saltValue`, `encryptedKeyValue` and the two
    /// verifier blobs. quick-xml quotes the text between `&` and the next `;` of whatever
    /// it is unescaping, so a crafted `encryptedKeyValue` put its own text here, bounded
    /// only by `limits::ENCRYPTION_INFO_READ_CAP` — 1 MiB. Not key material, since the
    /// attacker supplies the text, but unbounded attacker-chosen content in an error
    /// string is the thing [`Error::UnsupportedAlgorithm`] truncates to 32 characters and
    /// documents doing. Found by the downstream consumer, reading this file.
    ///
    /// The guard is
    /// `malformed_input::a_hostile_entity_in_an_attribute_value_never_reaches_the_error_message`,
    /// with a well-formed-value control beside it; reverting `xml_error` to
    /// `e.to_string()` fails it with a 4609-byte message quoting 4608 bytes of the file.
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
    /// Contrast [`Error::UnsupportedAlgorithm`], which is the file being
    /// internally consistent about something this crate has not implemented.
    #[error("unsupported or inconsistent encryption parameter: {0}")]
    BadParameters(String),

    /// The file names an algorithm this crate does not implement.
    ///
    /// **Distinct from [`Error::WrongPassword`] on purpose.** The password
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
    ///
    /// **This is the one opt-out in the enum that concedes something a caller should not
    /// concede lightly**, and the message therefore carries its cost rather than only its
    /// name. [`Self::IntegrityCheckFailed`] offers no way out because none exists, and
    /// [`Self::IntegrityUnavailable`]'s is a limit of the format; this one is "accept a
    /// file whose tamper-evidence was deleted", on a file where — see above — the deletion
    /// is never innocent. A consumer that forwards `Display` to an end user forwards that
    /// too. See the enum's own docs: render integrity failures by matching the variant.
    #[error(
        "this file declares agile encryption but carries no <dataIntegrity> element: \
        every known agile writer emits one, so it was removed or the file is malformed. \
        IntegrityPolicy::VerifyIfPresent decrypts it unverified, which accepts a file \
        whose tamper-evidence is absent"
    )]
    #[cfg(feature = "crypto-ops")]
    IntegrityElementMissing,

    /// An integrity guarantee was demanded of a format that defines no integrity tag at
    /// all — `IntegrityPolicy::Require` on ECMA-376 standard encryption (Office 2007).
    ///
    /// An *agile* file missing its element is [`Self::IntegrityElementMissing`] instead:
    /// that is a defect in the file, this is a limit of the format. The two want different
    /// words in front of a user — "this format cannot prove it was not modified" against
    /// "this file's proof was removed" — which is the whole reason they are two variants.
    ///
    /// Like that sibling, the message names the way out, because a consumer flattens this
    /// to its `Display`. Measured at one: the string reaches a user as *"integrity
    /// verification was required, but ECMA-376 standard encryption (Office 2007) defines
    /// no integrity element…"*, and a message that states the problem without the remedy
    /// is a dead end where a signposted one costs nothing.
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
    /// Truncated to 200 characters at the construction site, `agile_encrypt::random_source`,
    /// which explains why this one foreign `Display` is forwarded where
    /// [`Self::XmlParse`]'s is not.
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

/// The coverage half of the CLI's exit-code proof.
///
/// `src/bin/msoffice-crypto.rs` maps every [`Error`] to an exit code, and its `match`
/// needs a `_` arm: the enum is `#[non_exhaustive]` and the binary is a separate crate.
/// A `_` arm produces no diagnostic when a variant is added, so a fifteenth variant
/// would silently become exit 7 with nothing red anywhere.
///
/// This table duplicates that one **without** a `_` arm, inside the defining crate,
/// where `#[non_exhaustive]` does not apply. Adding a variant to [`Error`] and not
/// deciding its exit code is then `E0004` here, naming the variant. It is deliberately
/// a duplicate: the alternative — a public `Error::exit_code()` — would make an API
/// promise at publish for a binary's benefit.
///
/// The values are checked against the binary's own table by
/// `exit_codes_map_every_error_class` in `src/bin/msoffice-crypto_tests.rs`. This test
/// is the coverage evidence; that one is the value evidence. Both are required.
#[cfg(test)]
mod exit_code_canary {
    use super::Error;

    fn exit_code(e: &Error) -> u8 {
        match e {
            Error::NotACfbFile => 3,
            Error::MissingStream(_) => 6,
            Error::BadParameters(_) => 6,
            Error::Io(_) => 2,
            #[cfg(feature = "legacy-binary")]
            Error::NotEncrypted => 5,
            #[cfg(feature = "crypto-ops")]
            Error::UnsupportedEncryptionVersion(_, _) => 9,
            #[cfg(feature = "crypto-ops")]
            Error::XmlParse(_) => 6,
            #[cfg(feature = "crypto-ops")]
            Error::WrongPassword => 4,
            #[cfg(feature = "crypto-ops")]
            Error::CipherError => 6,
            #[cfg(feature = "crypto-ops")]
            Error::UnsupportedAlgorithm { .. } => 9,
            #[cfg(feature = "crypto-ops")]
            Error::IntegrityCheckFailed => 8,
            #[cfg(feature = "crypto-ops")]
            Error::IntegrityElementMissing => 8,
            #[cfg(feature = "crypto-ops")]
            Error::IntegrityUnavailable(_) => 8,
            #[cfg(feature = "crypto-ops")]
            Error::RandomSource(_) => 7,
        }
    }

    #[test]
    fn every_error_variant_is_named_in_the_exit_code_table() {
        assert_eq!(exit_code(&Error::NotACfbFile), 3);
        assert_eq!(exit_code(&Error::Io(std::io::Error::other("x"))), 2);
        #[cfg(feature = "crypto-ops")]
        assert_eq!(exit_code(&Error::IntegrityElementMissing), 8);
        #[cfg(feature = "legacy-binary")]
        assert_eq!(exit_code(&Error::NotEncrypted), 5);
    }
}
