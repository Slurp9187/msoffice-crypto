//! What [`crate::Error::BadParameters`] carries: which field a file declares
//! wrongly, the value it declares, and what was allowed — and what
//! [`crate::Error::InvariantViolated`] names instead when the fault is ours.
//!
//! **No byte of the file is in either.** Every payload is a fieldless enum or
//! an integer, and every `Display` renders only those (the owner, 2026-10-19;
//! plan `docs/plans/msoffice-crypto-structured-bad-parameters-2026-10-19.md`).
//! A consumer writes its own sentence from `got` and `max`: *"this file declares
//! a spinCount of 12,000,000; the format allows at most 10,000,000"*.
//!
//! Under `crypto-ops`, with the `Error` that carries it. The detection build's one
//! refusal, a stream over its read cap, is `Error::StreamTooLarge`.
//!
//! The write side's `EncryptParamProblem` is not reused: its wording speaks to a
//! caller about a tuple they chose, and "whose number it is" is the reason the
//! two variants are separate. They share the `limits.rs` taxonomy, not a type
//! ([`Bound`]).

/// Which field of the file a [`crate::Error::BadParameters`] is about, in the
/// specification's own spelling. Where the format carries two copies of one
/// field (agile `keyData` and `p:encryptedKey`), each has its own entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileField {
    // ── Agile EncryptionInfo ([MS-OFFCRYPTO] 2.3.4.10) ──
    /// The agile EncryptionInfo's `Reserved` field.
    AgileReserved,
    /// `p:encryptedKey/@spinCount`.
    SpinCount,
    /// `keyData/@keyBits`.
    KeyDataKeyBits,
    /// `p:encryptedKey/@keyBits`.
    EncryptedKeyKeyBits,
    /// `keyData/@blockSize`.
    KeyDataBlockSize,
    /// `p:encryptedKey/@blockSize`.
    EncryptedKeyBlockSize,
    /// `keyData/@hashSize`.
    KeyDataHashSize,
    /// `p:encryptedKey/@hashSize`.
    EncryptedKeyHashSize,
    /// `keyData/@saltSize`.
    KeyDataSaltSize,
    /// `p:encryptedKey/@saltSize`.
    EncryptedKeySaltSize,
    /// `keyData/@saltValue`, its decoded length.
    KeyDataSaltValue,
    /// `p:encryptedKey/@saltValue`, its decoded length.
    EncryptedKeySaltValue,
    /// `p:encryptedKey/@encryptedKeyValue`, its decoded length.
    EncryptedKeyValue,
    /// `p:encryptedKey/@encryptedVerifierHashInput`, its decoded length.
    EncryptedVerifierHashInput,
    /// `p:encryptedKey/@encryptedVerifierHashValue`, its decoded length.
    EncryptedVerifierHashValue,
    /// The `keyEncryptor` / `p:encryptedKey` elements.
    PasswordKeyEncryptor,
    /// The `dataIntegrity` element.
    DataIntegrity,
    /// `dataIntegrity/@encryptedHmacKey`, its decoded length.
    EncryptedHmacKey,
    /// `dataIntegrity/@encryptedHmacValue`, its decoded length.
    EncryptedHmacValue,
    /// The session key `keyData/@keyBits` describes, as recovered.
    SessionKey,

    // ── Binary EncryptionInfo: standard and CryptoAPI (2.3.2, 2.3.3, 2.3.5.1) ──
    /// The binary EncryptionInfo as a whole: its fixed prefix.
    EncryptionInfo,
    /// `EncryptionHeaderSize`.
    EncryptionHeaderSize,
    /// The `EncryptionHeader` structure's fixed fields.
    EncryptionHeader,
    /// `EncryptionHeader.Flags`.
    EncryptionHeaderFlags,
    /// `EncryptionHeader.KeySize`.
    EncryptionHeaderKeySize,
    /// `EncryptionHeader.AlgID`.
    EncryptionHeaderAlgId,
    /// The `EncryptionVerifier` structure.
    EncryptionVerifier,
    /// `EncryptionVerifier.SaltSize`.
    VerifierSaltSize,
    /// `EncryptionVerifier.VerifierHashSize`.
    VerifierHashSize,
    /// `EncryptedPackage`'s `StreamSize`.
    EncryptedPackageSize,
    /// The Office 97/2000 RC4 header (2.3.6.1).
    Rc4Office97Header,

    // ── Word 97 ([MS-DOC]) ──
    /// `FibBase.wIdent`.
    FibWIdent,
    /// `FibBase.lKey`.
    FibLKey,
    /// The `EncryptionVersionInfo` a FIB or FILEPASS points at.
    EncryptionVersionInfo,

    // ── Excel 97 ([MS-XLS]) ──
    /// A BIFF record header.
    BiffRecord,
    /// The Workbook stream's opening BOF record.
    WorkbookBof,
    /// The FILEPASS record.
    Filepass,
    /// `FILEPASS.wEncryptionType`.
    FilepassEncryptionType,

    // ── PowerPoint 97 ([MS-PPT], [MS-ODRAW]) ──
    /// The `UserEditAtom`.
    UserEditAtom,
    /// `UserEditAtom.offsetLastEdit`.
    OffsetLastEdit,
    /// The `PersistDirectoryAtom`.
    PersistDirectory,
    /// `UserEditAtom.encryptSessionPersistIdRef`.
    EncryptSessionPersistIdRef,
    /// The `CryptSession10Container`.
    CryptSession10Container,
    /// A persist object's offset.
    PersistObject,
    /// A record of the `Pictures` stream.
    PicturesRecord,

    // ── The encrypted summary stream (2.3.5.4) ──
    /// The `encryption` stream as a whole.
    SummaryStream,
    /// The `EncryptedStreamDescriptor` array.
    SummaryDescriptorArray,
    /// `EncryptedStreamDescriptorCount`.
    SummaryDescriptorCount,
    /// One `EncryptedStreamDescriptor`.
    SummaryDescriptor,
    /// An `EncryptedStreamDescriptor`'s stream name.
    SummaryStreamName,
    /// An encrypted stream's extent.
    SummaryStreamExtent,
}

impl core::fmt::Display for FileField {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Exhaustive, with no `_` arm: a new field fails to compile here until it
        // is given its spelling.
        f.write_str(match self {
            Self::AgileReserved => "agile EncryptionInfo Reserved",
            Self::SpinCount => "p:encryptedKey/@spinCount",
            Self::KeyDataKeyBits => "keyData/@keyBits",
            Self::EncryptedKeyKeyBits => "p:encryptedKey/@keyBits",
            Self::KeyDataBlockSize => "keyData/@blockSize",
            Self::EncryptedKeyBlockSize => "p:encryptedKey/@blockSize",
            Self::KeyDataHashSize => "keyData/@hashSize",
            Self::EncryptedKeyHashSize => "p:encryptedKey/@hashSize",
            Self::KeyDataSaltSize => "keyData/@saltSize",
            Self::EncryptedKeySaltSize => "p:encryptedKey/@saltSize",
            Self::KeyDataSaltValue => "keyData/@saltValue",
            Self::EncryptedKeySaltValue => "p:encryptedKey/@saltValue",
            Self::EncryptedKeyValue => "p:encryptedKey/@encryptedKeyValue",
            Self::EncryptedVerifierHashInput => "p:encryptedKey/@encryptedVerifierHashInput",
            Self::EncryptedVerifierHashValue => "p:encryptedKey/@encryptedVerifierHashValue",
            Self::PasswordKeyEncryptor => "keyEncryptor (password)",
            Self::DataIntegrity => "dataIntegrity",
            Self::EncryptedHmacKey => "dataIntegrity/@encryptedHmacKey",
            Self::EncryptedHmacValue => "dataIntegrity/@encryptedHmacValue",
            Self::SessionKey => "the recovered session key",
            Self::EncryptionInfo => "EncryptionInfo",
            Self::EncryptionHeaderSize => "EncryptionHeaderSize",
            Self::EncryptionHeader => "EncryptionHeader",
            Self::EncryptionHeaderFlags => "EncryptionHeader.Flags",
            Self::EncryptionHeaderKeySize => "EncryptionHeader.KeySize",
            Self::EncryptionHeaderAlgId => "EncryptionHeader.AlgID",
            Self::EncryptionVerifier => "EncryptionVerifier",
            Self::VerifierSaltSize => "EncryptionVerifier.SaltSize",
            Self::VerifierHashSize => "EncryptionVerifier.VerifierHashSize",
            Self::EncryptedPackageSize => "EncryptedPackage StreamSize",
            Self::Rc4Office97Header => "the RC4 (Office 97) header",
            Self::FibWIdent => "FibBase.wIdent",
            Self::FibLKey => "FibBase.lKey",
            Self::EncryptionVersionInfo => "EncryptionVersionInfo",
            Self::BiffRecord => "a BIFF record",
            Self::WorkbookBof => "the Workbook BOF record",
            Self::Filepass => "the FILEPASS record",
            Self::FilepassEncryptionType => "FILEPASS.wEncryptionType",
            Self::UserEditAtom => "the UserEditAtom",
            Self::OffsetLastEdit => "UserEditAtom.offsetLastEdit",
            Self::PersistDirectory => "the PersistDirectoryAtom",
            Self::EncryptSessionPersistIdRef => "UserEditAtom.encryptSessionPersistIdRef",
            Self::CryptSession10Container => "the CryptSession10Container",
            Self::PersistObject => "a persist object",
            Self::PicturesRecord => "a Pictures record",
            Self::SummaryStream => "the encrypted summary stream",
            Self::SummaryDescriptorArray => "the EncryptedStreamDescriptor array",
            Self::SummaryDescriptorCount => "EncryptedStreamDescriptorCount",
            Self::SummaryDescriptor => "an EncryptedStreamDescriptor",
            Self::SummaryStreamName => "an EncryptedStreamDescriptor's stream name",
            Self::SummaryStreamExtent => "an encrypted stream's extent",
        })
    }
}

/// Whose number a range or required value is: the `limits.rs` taxonomy,
/// phrased for a file. A test holds every `limits.rs` label to a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bound {
    /// The specification states it ([MS-OFFCRYPTO], [MS-DOC], [MS-XLS],
    /// [MS-PPT], ECMA-376).
    Spec,
    /// The cipher or hash cannot run anything else (an AES block of 16 bytes).
    Cipher,
    /// A margin of this crate's, above anything Office writes.
    Margin,
    /// A choice of this crate's that is not a margin, such as refusing to pad a
    /// key with 0x36 bytes.
    Crate,
}

impl core::fmt::Display for Bound {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Spec => "the specification's",
            Self::Cipher => "the cipher's",
            Self::Margin => "this crate's margin",
            Self::Crate => "this crate's",
        })
    }
}

/// A closed set of allowed values, so a set is never printed as a range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AllowedSet {
    /// AES key sizes in bits: 128, 192, 256.
    AesKeyBits,
    /// `FILEPASS.wEncryptionType`: 0 (XOR) or 1 (RC4).
    XorOrRc4,
    /// RC4 CryptoAPI key sizes in bits: 40 to 128 in steps of 8.
    Rc4KeyBits,
    /// `Pictures` record types: a blip or a file-block entry.
    PicturesRecordTypes,
}

impl core::fmt::Display for AllowedSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::AesKeyBits => "128, 192 or 256",
            Self::XorOrRc4 => "0 (XOR) or 1 (RC4)",
            Self::Rc4KeyBits => "40 to 128 in steps of 8",
            Self::PicturesRecordTypes => "a blip or a file-block entry",
        })
    }
}

/// What is wrong with a [`FileField`]. Integers and closed enums only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileProblem {
    /// Outside an inclusive range.
    OutOfRange {
        /// The value the file declares.
        got: u64,
        /// Inclusive floor.
        min: u64,
        /// Inclusive ceiling.
        max: u64,
        /// Whose range it is.
        bound: Bound,
    },
    /// Not one of a closed set of values.
    NotInSet {
        /// The value the file declares.
        got: u64,
        /// The values allowed.
        allowed: AllowedSet,
        /// Whose set it is.
        bound: Bound,
    },
    /// Not the one value allowed.
    NotRequiredValue {
        /// The value the file declares.
        got: u64,
        /// The value required.
        required: u64,
        /// Whose requirement it is.
        bound: Bound,
    },
    /// Disagrees with another value the file declares or holds.
    Disagrees {
        /// The value of this field.
        got: u64,
        /// What the other field implies it must be.
        expected: u64,
        /// The other field.
        with: FileField,
    },
    /// A length or bit count the named hash cannot produce or take.
    DigestMismatch {
        /// The value the file declares.
        got: u64,
        /// The hash the file names.
        hash: crate::HashAlgorithm,
    },
    /// Fewer bytes than the structure needs.
    Truncated {
        /// The bytes there are.
        have: u64,
        /// The bytes it needs.
        need: u64,
    },
    /// An extent runs past the end of what holds it.
    OutOfBounds {
        /// Where it starts.
        offset: u64,
        /// How long it is.
        len: u64,
        /// Where what holds it ends.
        end: u64,
    },
    /// Cannot be read where it starts: no whole header, or a length past the end.
    Unreadable {
        /// Where it starts.
        offset: u64,
    },
    /// Required and absent.
    Missing,
    /// Present more than once where the format allows one.
    Duplicate,
    /// Overlaps another extent.
    Overlaps,
    /// A string that is not terminated.
    Unterminated,
    /// A flag the format requires is clear.
    FlagClear,
    /// A signature or identifier is not the format's.
    BadSignature,
    /// In the wrong place in a sequence.
    OutOfOrder {
        /// The record it follows.
        after_record: u16,
    },
    /// A value the format does not define.
    Unrecognized {
        /// The value the file declares.
        got: u64,
    },
}

impl core::fmt::Display for FileProblem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfRange {
                got,
                min,
                max,
                bound,
            } => write!(f, "is {got}, outside {min}..={max} ({bound} range)"),
            Self::NotInSet {
                got,
                allowed,
                bound,
            } => write!(f, "is {got}, not {allowed} ({bound} set)"),
            Self::NotRequiredValue {
                got,
                required,
                bound,
            } => write!(f, "is {got}, not {required} ({bound} requirement)"),
            Self::Disagrees {
                got,
                expected,
                with,
            } => write!(f, "is {got}, but {with} requires {expected}"),
            Self::DigestMismatch { got, hash } => {
                write!(f, "is {got}, which {} cannot produce", hash.name())
            }
            Self::Truncated { have, need } => write!(f, "is {have} bytes, needs {need}"),
            Self::OutOfBounds { offset, len, end } => {
                write!(f, "runs from {offset} for {len} bytes, past {end}")
            }
            Self::Unreadable { offset } => write!(f, "cannot be read at offset {offset}"),
            Self::Missing => f.write_str("is missing"),
            Self::Duplicate => f.write_str("appears more than once"),
            Self::Overlaps => f.write_str("overlaps another"),
            Self::Unterminated => f.write_str("is not terminated"),
            Self::FlagClear => f.write_str("has a required flag clear"),
            Self::BadSignature => f.write_str("does not carry the format's signature"),
            Self::OutOfOrder { after_record } => {
                write!(f, "follows record 0x{after_record:04X}")
            }
            Self::Unrecognized { got } => write!(f, "is {got}, a value the format does not define"),
        }
    }
}

/// An invariant of this crate's that something upstream should have enforced:
/// reaching one is a bug here, not a property of the file
/// ([`crate::Error::InvariantViolated`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Invariant {
    /// An AES key the cipher would not take reached it.
    AesKeyLength,
    /// An AES IV the cipher would not take reached it.
    AesIvLength,
    /// A block size larger than the digest reached IV derivation.
    BlockSizeOverDigest,
    /// More segments or blocks than a 32-bit counter numbers.
    CounterOverflow,
    /// An in-place rewrite changed a stream's length.
    RewriteLength,
    /// An EncryptionInfo placeholder changed length on rewrite.
    PlaceholderLength,
    /// A serializer produced a blob of the wrong length.
    SerializedLength,
    /// Integrity sealing reached padding arithmetic that cannot hold.
    IntegrityPadding,
    /// An RC4 key outside 5..=16 bytes reached the key schedule.
    Rc4KeyLength,
    /// An RC4 block size of zero reached the block loop.
    Rc4BlockSize,
    /// A key size the screen refuses reached the SHA-1 key ladder.
    KeyLadderLength,
    /// A value from the file does not fit this host's `usize`.
    Unrepresentable,
    /// A slice of our own computation fell outside its buffer.
    InternalSlice,
}

impl core::fmt::Display for Invariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::AesKeyLength => "an AES key length the screen passed",
            Self::AesIvLength => "an AES IV length the screen passed",
            Self::BlockSizeOverDigest => "a block size longer than its digest",
            Self::CounterOverflow => "more blocks than a 32-bit counter numbers",
            Self::RewriteLength => "an in-place rewrite changed a stream's length",
            Self::PlaceholderLength => "the EncryptionInfo placeholder changed length",
            Self::SerializedLength => "a serialized blob has the wrong length",
            Self::IntegrityPadding => "integrity padding arithmetic overflowed",
            Self::Rc4KeyLength => "an RC4 key length outside 5..=16 bytes",
            Self::Rc4BlockSize => "an RC4 block size of zero",
            Self::KeyLadderLength => "a key size the SHA-1 ladder cannot yield",
            Self::Unrepresentable => "a value that does not fit this host's usize",
            Self::InternalSlice => "a slice outside its buffer",
        })
    }
}

/// What [`crate::Error::UnsupportedAlgorithm`] names: never the file's own text.
///
/// Until 0.1.0-rc.9 the agile path put the file's spelling here, truncated to
/// 32 characters: text the file chose. A name [MS-OFFCRYPTO] §2.3.4.10 defines
/// is now one of [`KnownAlgorithm`], and any other is only its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AlgorithmName {
    /// A name the specification defines and this crate does not implement.
    Known(KnownAlgorithm),
    /// A name the specification does not define, by its length in characters.
    Unknown {
        /// How many characters the file's name has.
        len: u32,
    },
    /// A binary `AlgID` or `AlgIDHash` value.
    AlgId(u32),
    /// A fixed description this crate wrote of what was refused.
    Fixed(&'static str),
}

impl core::fmt::Display for AlgorithmName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Known(k) => write!(f, "{k}"),
            Self::Unknown { len } => {
                write!(f, "a name the format does not define ({len} characters)")
            }
            Self::AlgId(id) => write!(f, "{id:#010x}"),
            Self::Fixed(s) => f.write_str(s),
        }
    }
}

/// An algorithm or chaining mode [MS-OFFCRYPTO] §2.3.4.10 names that this
/// crate does not implement, which the format permits ("a compliant
/// implementation is not required to support all defined values").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KnownAlgorithm {
    /// `MD5`.
    Md5,
    /// `MD4`.
    Md4,
    /// `MD2`.
    Md2,
    /// `RIPEMD-128`.
    Ripemd128,
    /// `RIPEMD-160`.
    Ripemd160,
    /// `WHIRLPOOL`.
    Whirlpool,
    /// `RC2`.
    Rc2,
    /// `RC4`.
    Rc4,
    /// `DES`.
    Des,
    /// `DESX`.
    Desx,
    /// `3DES`.
    TripleDes,
    /// `3DES_112`.
    TripleDes112,
    /// `ChainingModeCFB`.
    ChainingModeCfb,
}

impl KnownAlgorithm {
    const ALL: [KnownAlgorithm; 13] = [
        Self::Md5,
        Self::Md4,
        Self::Md2,
        Self::Ripemd128,
        Self::Ripemd160,
        Self::Whirlpool,
        Self::Rc2,
        Self::Rc4,
        Self::Des,
        Self::Desx,
        Self::TripleDes,
        Self::TripleDes112,
        Self::ChainingModeCfb,
    ];

    /// The specification's spelling.
    pub fn spelling(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Md4 => "MD4",
            Self::Md2 => "MD2",
            Self::Ripemd128 => "RIPEMD-128",
            Self::Ripemd160 => "RIPEMD-160",
            Self::Whirlpool => "WHIRLPOOL",
            Self::Rc2 => "RC2",
            Self::Rc4 => "RC4",
            Self::Des => "DES",
            Self::Desx => "DESX",
            Self::TripleDes => "3DES",
            Self::TripleDes112 => "3DES_112",
            Self::ChainingModeCfb => "ChainingModeCFB",
        }
    }
}

impl core::fmt::Display for KnownAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.spelling())
    }
}

/// The closed name for a spelling the file chose: a [`KnownAlgorithm`] matched
/// exactly (case-sensitively, as `HashAlgorithm::parse` matches), else its
/// length.
pub(crate) fn algorithm_name(spelled: &str) -> AlgorithmName {
    KnownAlgorithm::ALL
        .into_iter()
        .find(|k| k.spelling() == spelled)
        .map_or_else(
            || AlgorithmName::Unknown {
                len: u32::try_from(spelled.chars().count()).unwrap_or(u32::MAX),
            },
            AlgorithmName::Known,
        )
}

/// `n` as a `u64`, saturating: a length that does not fit is reported as
/// `u64::MAX` rather than panicking.
pub(crate) fn wide<T: TryInto<u64>>(n: T) -> u64 {
    n.try_into().unwrap_or(u64::MAX)
}

/// The refusal for `field` with `problem`.
pub(crate) fn bad(field: FileField, problem: FileProblem) -> crate::Error {
    crate::Error::BadParameters { field, problem }
}
