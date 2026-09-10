//! Numeric bounds on the parameters a file declares about itself.
//!
//! Everything here arrives as a bare `u32` out of an attacker-supplied
//! `EncryptionInfo` stream, and each one is used as a loop count or a slice length
//! before anything else in the crate has had a chance to reject the file. The sibling
//! crate `odf-crypto` keeps the same list for the same reason (`odf-crypto/src/limits.rs`
//! — `PBKDF2_MAX_ITER`, `DERIVED_KEY_MIN_LEN`/`MAX_LEN`); the shapes match deliberately.
//!
//! What is deliberately *not* here: lengths fixed by the on-disk format rather than by
//! a field in it — the 72-byte `EncryptionVerifier`, the 16-byte AES block. Those are
//! layout facts and live beside the code that reads the layout, so a reader checking
//! "is this the number the spec gives?" finds them next to the offsets they describe.
//!
//! The bounds `classify` reads are compiled in every configuration — the read caps and
//! structure bounds above the gate, which is what keeps detection safe on an untrusted
//! upload without a cipher in the graph. The rest exist solely for a `crypto-ops` path, [`PAYLOAD_CEILING`]
//! included since `classify` never opens the payload, and live in [`crypto`] behind one
//! gate, so
//! `dead_code` stays live everywhere rather than being silenced by a module-wide `allow`
//! that would hide a genuinely unused bound as readily as an expected one. That split is
//! `odf-crypto/src/limits.rs`'s shape, deliberately.

/// Ceiling on the `\EncryptionInfo` stream this crate will read into memory.
///
/// The stream is a version header plus either a ~1.5 KB XML document (agile — the fixture
/// here is 1 441 bytes) or a ~220-byte binary header (standard). 1 MiB is roughly 700x the
/// larger of those, so no writer this crate expects to meet comes near it — and it is read
/// *before* anything has authenticated the file, which is the whole point: `classify` reads
/// it on an untrusted upload by definition.
///
/// The `\EncryptedPackage` stream's counterpart is [`PAYLOAD_CEILING`], which is a
/// `crypto-ops` bound rather than one of these: `classify` never opens the payload, so the
/// "detection is free" property does not depend on it.
pub(crate) const ENCRYPTION_INFO_READ_CAP: usize = 1 << 20;

/// Bytes of a legacy binary format's header stream that [`crate::binary_office`] reads.
///
/// Word's FIB puts its flags at offset 0x0A and the table stream puts the whole
/// `EncryptionHeader` in its first ~200 bytes, so 512 covers both with margin. Read
/// before anything has authenticated the file, like everything else in `classify`.
pub(crate) const BINARY_HEADER_READ_CAP: usize = 512;

/// Ceiling on the BIFF stream `classify` will walk looking for a `FILEPASS` record.
///
/// `FILEPASS` is mandated to appear in the globals substream near the top of the workbook
/// — the fixture here has it at offset 0x14 — so a megabyte is roughly five orders of
/// magnitude of margin over where it legitimately occurs.
///
/// One use site, `binary_office`'s workbook read. It used to bound PowerPoint's
/// attacker-chosen `offsetToCurrentEdit` as well, and no longer does: that walk reads at
/// the offset rather than up to it, so there is no buffer to cap — the bound that
/// replaced it is the container's own extent.
///
/// **A bound on hostile input, not on how large a legitimate workbook may be.** The walk
/// never needs to reach the end of the stream to say "not encrypted": [MS-XLS] permits
/// only six records in the clear ahead of `FILEPASS`, so the first record outside that set
/// proves there is none, and a real plain workbook is decided at its third record. A
/// stream that exhausts this cap before any record decides it is reported as unknown —
/// never as unencrypted — so the figure has no margin to justify against the size of a
/// globals substream, which can run to megabytes of shared strings.
pub(crate) const BIFF_SCAN_CAP: usize = 1 << 20;

/// Bytes of PowerPoint's `Current User` stream that are read.
///
/// `CurrentUserAtom` is 20 bytes plus an 8-byte record header, and the fixture's whole
/// stream is 32. 256 is generous and still refuses to materialise a hostile stream that
/// merely claims the name.
pub(crate) const CURRENT_USER_READ_CAP: usize = 256;

/// Ceiling on `EncryptionHeaderSize` — the same `EncryptionHeader` of [MS-OFFCRYPTO]
/// §2.3.2, used by RC4 CryptoAPI (§2.3.5.1) and by ECMA-376 standard encryption (§2.3.4.5).
///
/// The header is 32 bytes of fixed fields followed by `CSPName`, a null-terminated
/// UTF-16LE cryptographic-service-provider name. The longest name Windows ships is
/// "Microsoft Enhanced RSA and AES Cryptographic Provider" — 53 characters, 108 bytes
/// with its terminator — and every legacy fixture here carries the 47-character Enhanced
/// provider (a 126-byte header). 1 024 is roughly seven times the longest real header.
/// The field is a `u32` the file declares, and it is the distance from the header to the
/// `EncryptionVerifier`; LibreOffice bounds it only from below
/// (`sw/source/filter/ww8/ww8par.cxx:5617-5621`, behaviour only), which is enough for a
/// seek and not for a slice. Compiled in every configuration because
/// [`ENCRYPTION_HEADER_STRUCTURE_MAX`] is derived from it, and that derived bound is what
/// `classify` applies to a `.ppt`'s `CryptSession10Container`. The standard decrypt path
/// uses the same number for the same field.
pub(crate) const RC4_ENCRYPTION_HEADER_SIZE_MAX: usize = 1024;

/// Ceiling on a whole RC4 CryptoAPI encryption header *structure*: the 12-byte prefix,
/// a header at [`RC4_ENCRYPTION_HEADER_SIZE_MAX`], and the 60-byte RC4-shaped verifier.
///
/// Two file fields are checked against this before they slice: `FibBase.lKey` in a `.doc`
/// ([MS-DOC] §2.5.2, `word97.rs`) and the `CryptSession10Container`'s `recLen` in a `.ppt`
/// ([MS-PPT] §2.3.7, `binary_office.rs`). The fixtures' structures are 198 bytes.
///
/// The `.xls` leg is **not** one of them, and the reason is not the one this comment used
/// to give. A `FILEPASS` record length is a `u16`, which is 65 535 and therefore *not*
/// inherently under 1 096; what bounds it is that the record body is sliced out of a
/// buffer already capped at [`BIFF_SCAN_CAP`], so an over-long declaration runs out of
/// bytes rather than out of memory.
pub(crate) const ENCRYPTION_HEADER_STRUCTURE_MAX: usize = 12 + RC4_ENCRYPTION_HEADER_SIZE_MAX + 60;

/// The most persist objects a PowerPoint persist directory can name.
///
/// Not a margin: `PersistDirectoryEntry.persistId` is a 20-bit field and "MUST be less
/// than or equal to 0xFFFFE" ([MS-PPT] §2.3.5), so a directory naming more identifiers
/// than that names one twice. The count bounds the work of walking the directory and,
/// on the decrypt path, the number of persist objects rekeyed.
pub(crate) const PPT_PERSIST_OBJECTS_MAX: usize = 1 << 20;

/// Ceiling on a `PersistDirectoryAtom`'s `recLen` — the bytes read to walk it.
///
/// Derived from [`PPT_PERSIST_OBJECTS_MAX`]: each identifier costs at most 8 bytes, a
/// 4-byte offset plus, in the least compact packing of one identifier per entry, a
/// 4-byte entry word. The fixture's atom is 64 bytes for 15 objects. `classify` reads the
/// atom on a hostile upload, so the bound is compiled into every configuration.
pub(crate) const PPT_PERSIST_DIRECTORY_READ_CAP: usize = PPT_PERSIST_OBJECTS_MAX * 8;

#[cfg(feature = "crypto-ops")]
pub(crate) use crypto::*;

#[cfg(feature = "legacy-binary")]
pub(crate) use legacy::*;

/// Bounds only the `legacy-binary` decrypt paths reach. Gated as a module for the reason
/// [`crypto`] is.
#[cfg(feature = "legacy-binary")]
mod legacy {
    /// The read cap on each stream a binary document's decrypt holds in memory —
    /// `WordDocument`, the table stream and `Data`; `Workbook`; `PowerPoint Document` —
    /// aliased to [`super::PAYLOAD_CEILING`] rather than given its own number.
    ///
    /// The same memory bound as `EncryptedPackage`'s, for the same reason: a decrypt holds
    /// a stream and its plaintext at once, and `cfb` already refuses a forged length, so
    /// what remains to bound is the allocation. A `.doc` cannot legitimately be this
    /// large — its FIB offsets are 32-bit and Word's own limit is 32 MB — and the
    /// number is deliberately not tightened per format: one ceiling, one place, one
    /// `const` assertion tying it to the shared figure (GH #10's patterns 3 and 5).
    pub(crate) const LEGACY_STREAM_READ_CAP: usize = super::PAYLOAD_CEILING;

    const _: () = assert!(LEGACY_STREAM_READ_CAP == super::PAYLOAD_CEILING);

    /// `EncryptionHeader.KeySize` for RC4 CryptoAPI, in bits — [MS-OFFCRYPTO] §2.3.5.1:
    /// "greater than or equal to 0x00000028 bits and less than or equal to 0x00000080
    /// bits, in increments of 8 bits". The spec's own range, not a margin. It sizes the
    /// key every block is decrypted under, and `rc4::Keystream::new` dispatches a cipher
    /// on the byte length it produces, so it is checked at parse and again where the key
    /// is derived.
    pub(crate) const RC4_KEY_BITS: core::ops::RangeInclusive<u32> = 40..=128;

    /// What a `KeySize` of zero means — §2.3.5.1: "If set to 0x00000000, it MUST be
    /// interpreted as 0x00000028 bits."
    pub(crate) const RC4_KEY_BITS_DEFAULT: u32 = 40;

    /// The longest password XOR obfuscation can take — [MS-OFFCRYPTO] §2.3.7.2:
    /// "Password MUST NOT be longer than 15 characters". A structural fact, not a margin:
    /// `InitialCode` has 15 entries indexed by length minus one, and `XorMatrix` is walked
    /// seven entries per character from index 0x68, which 15 characters exhaust exactly.
    /// A longer password indexes past both tables, so it is refused as a password Excel
    /// could not have set rather than sliced.
    pub(crate) const XOR_PASSWORD_MAX_LEN: usize = 15;
}

/// Bounds no detection-only build can reach. One gate on the module covers all of them:
/// `crypto-ops` is a single feature, so there is no configuration in which some of these
/// are live and others are not.
#[cfg(feature = "crypto-ops")]
mod crypto {
    /// **1 GiB** — the largest `EncryptedPackage` payload this crate will hold in memory.
    ///
    /// This is the bound GH #10 asked for and could not honestly pick, deferred to plan D4
    /// and landed with the segment iterator (GH #6 step 2). Two things had to be true first,
    /// and now are: the segmentation is explicit rather than an inline `chunks(4096)`, so
    /// there is a stated working set to reason about; and the figure has somewhere to be
    /// shared from, rather than being repeated at each `Vec` that grows.
    ///
    /// **The figure is `odf-crypto`'s, deliberately** (`odf-crypto/src/limits.rs`
    /// `PAYLOAD_CEILING`, also `1 << 30`). The two crates do the same job on the same class
    /// of file, so a different number here would need a reason this crate has and the
    /// sibling does not, and there is none. CLAUDE.md § *Sibling crate* asks for exactly
    /// this when a rule is thin.
    ///
    /// **What it is not.** It is not an anti-amplification bound: `cfb` 0.14 bounds every
    /// read by the directory entry's `stream_len` *and* by the real FAT chain, so a forged
    /// length fails the read instead of allocating, and a file claiming a gigabyte must
    /// actually be a gigabyte. It is a memory bound — a decrypt holds the ciphertext and the
    /// plaintext at once, so 1 GiB of payload is ~2 GiB of peak, which is why the number is
    /// well under what a 64-bit machine could survive.
    ///
    /// **Margin.** Office's own guidance keeps PowerPoint decks far below this, and the
    /// per-file limits these documents travel under (OneDrive/SharePoint uploads, mail
    /// gateways) have historically sat at or under 2 GB. A `.pptx` in the hundreds of
    /// megabytes — the size the deferral note in GH #10 worried about — has 2-10x of room.
    ///
    /// **If this ever refuses a real document, the fix is the streaming API, not a bigger
    /// number.** Raising it buys one more document and moves the same wall; `Read + Write +
    /// Seek` over [`crate::segments`] removes the wall, which is what D4 is for.
    pub(crate) const PAYLOAD_CEILING: usize = 1 << 30;

    /// The read cap on `\EncryptedPackage`, aliased to [`PAYLOAD_CEILING`] rather than
    /// given its own number.
    ///
    /// GH #10's pattern 3, from `odf-crypto`: one shared named ceiling per use site, so a
    /// hostile size cannot allocate past it on one path while another still would. The
    /// stream read and the plaintext buffer are the two allocation paths here, and they are
    /// the same figure by construction.
    pub(crate) const ENCRYPTED_PACKAGE_READ_CAP: usize = PAYLOAD_CEILING;

    /// GH #10's pattern 5 — `const`-assert that related constants agree.
    ///
    /// A compile error rather than a test failure, deliberately: "the payload read cap is
    /// the shared ceiling" is a statement about two constants, and there is no input that
    /// makes it more or less true. The runtime tests in `cfb_reader` prove the *mechanism*
    /// refuses and that the payload cap reaches the payload stream; this proves the number
    /// they cannot afford to exercise at size.
    ///
    /// The second assertion is the one that catches a plausible edit: a ceiling that
    /// drifted down to the 1 MiB header figure would refuse every real document, and every
    /// test in the suite would still pass, because no fixture here is over a megabyte.
    const _: () = {
        assert!(ENCRYPTED_PACKAGE_READ_CAP == PAYLOAD_CEILING);
        assert!(PAYLOAD_CEILING > super::ENCRYPTION_INFO_READ_CAP);
        assert!(PAYLOAD_CEILING == 1 << 30);
    };

    /// Inclusive ceiling on agile `p:encryptedKey/@spinCount`.
    ///
    /// `spin_hash` runs this many SHA-512 rounds *before* the password check, before the
    /// integrity check, before anything that could reject the file — so the cost is paid by
    /// any caller that merely attempts to open the document. Unbounded, a 41 KB file buys
    /// roughly 50 minutes of one core (`u32::MAX` rounds, measured in release), and there is
    /// no in-process defence against it: it is a hang, not a panic, so a caller's
    /// `catch_unwind` never fires and a Rust worker thread cannot be interrupted.
    ///
    /// **Tighter than the spec's own ceiling, deliberately.** [MS-OFFCRYPTO] §2.3.4.10
    /// bounds `ST_SpinCount` at `maxInclusive="10000000"` and says "It MUST NOT be greater
    /// than 10,000,000" — which is ~100x what Office writes and, at ~7 µs per SHA-512
    /// round pair, still minutes of one core per open attempt. A spec maximum that permits
    /// a denial of service is not a bound this crate can adopt as its own; the figure below
    /// is chosen against what writers emit, and a file between the two ceilings is
    /// conforming and refused.
    ///
    /// Office writes 100 000. `1 << 21` is ~21x that and about 1.5 s of SHA-512 on a current
    /// core — the same order of margin `odf-crypto` allows PBKDF2 (`1 << 23`, ~14x
    /// LibreOffice's 600 000). Standard encryption does not need an entry here: its spin
    /// count is the hardcoded `standard::SPIN_COUNT`, not a file field.
    ///
    /// **No floor.** `spinCount="0"` makes a weak file, not a dangerous one: the stretching
    /// its writer chose is the writer's decision, and refusing to decrypt a document its
    /// owner already holds buys this crate nothing. Once the slices below are bounded, a
    /// zero spin count just reaches a clean error faster.
    pub(crate) const SPIN_COUNT_MAX: u32 = 1 << 21;

    /// Pins the figure itself, for the same reason `PAYLOAD_CEILING` is pinned one screen
    /// away — and it was not pinned until the 2026-09-10 pre-publish audit demonstrated
    /// why. **Every test of this bound is written relative to the constant**
    /// (`SPIN_COUNT_MAX + 1`, `SPIN_COUNT_MAX.to_string()`), so the guards move with it:
    /// raising this to `u32::MAX - 1` leaves all 205 tests green while the hang guard it
    /// exists to be is gone. A ceiling that its own tests cannot see move is not a ceiling.
    ///
    /// The upper bound is the property that matters — a *lower* value only refuses files
    /// this crate could have opened, which is a compatibility bug and loud. So the
    /// assertion names the magnitude rather than merely a range: 2^21, about 21x the
    /// 100 000 Office writes, and 21x under [MS-OFFCRYPTO] §2.3.4.10's own 10,000,000.
    const _: () = {
        assert!(SPIN_COUNT_MAX == 1 << 21);
        assert!(SPIN_COUNT_MAX > 100_000); // must not refuse what Office itself writes
        assert!(SPIN_COUNT_MAX < 10_000_000); // must stay stricter than the spec ceiling
    };

    /// The values of agile `keyBits` this crate will act on — on **either** element.
    ///
    /// `<keyData>` and `<p:encryptedKey>` each declare one, about two different keys:
    /// the package key and the key that wraps it. Only the second was bounded here at
    /// first, which left `<keyData>`'s unread entirely — see
    /// `agile::check_key_bits`, which asks the question of both, and
    /// `AgileParams::key_data_key_bits` for what the unread one cost.
    ///
    /// ECMA-376 admits exactly these three for AES, and LibreOffice's reader accepts the
    /// same set (`AgileEngine.cxx:574-612`, behaviour only). `keyBits / 8` is used verbatim
    /// as a truncation length inside `agile::derive_block_key`, reachable before any
    /// password is checked, so an unbounded value slices off the end of the digest.
    ///
    /// **This bound is necessary and no longer sufficient for that slice.** It was written
    /// when the digest was always SHA-512's 64 bytes, which made "≤ 512 bits" the whole
    /// story. Since the password path honours `p:encryptedKey/@hashAlgorithm` (issue #11)
    /// the digest may be 20 bytes, and 192 and 256 are both longer than that — so the
    /// slice's safety comes from `agile`'s explicit `keyBits / 8 ≤ digest_len` check
    /// against the *named* hash, and this list only says which key sizes AES defines. Do
    /// not read the two as one guard again.
    ///
    /// All three open. Until GH #13 the cipher was AES-256 only and 128 and 192 were
    /// accepted here and refused one frame later; now `agile::aes_cbc_decrypt` dispatches
    /// on the key length, so this list is the format's and the cipher's at once.
    pub(crate) const AGILE_KEY_BITS_ALLOWED: [u32; 3] = [128, 192, 256];

    /// The range agile `saltSize` may declare, on either `<keyData>` or
    /// `<p:encryptedKey>`.
    ///
    /// [MS-OFFCRYPTO] §2.3.4.10 states it "MUST be at least 1 and no greater than 65,536".
    /// This is the spec's own number rather than a margin this crate picked — LibreOffice
    /// quotes the same sentence at `AgileEngine.cxx:557` and herumi enforces the identical
    /// range at `include/crypto_util.hpp:138-140`, which makes the figure available from a
    /// BSD-3 source and not only from the MPL one.
    ///
    /// It bounds real work: `roundUp(saltSize, blockSize)` is how many bytes of decrypted
    /// `encryptedVerifierHashInput` `agile::verify_password` hashes, and the salt itself is
    /// used verbatim as a CBC IV. The tighter constraint in practice is the cross-check
    /// beside it — `saltSize` must equal the decoded `saltValue`'s length — which pins the
    /// value to whatever base64 the file actually carries.
    pub(crate) const AGILE_SALT_SIZE: std::ops::RangeInclusive<u32> = 1..=65536;

    /// The only `EncryptionHeader.KeySize` this crate's standard-encryption path accepts.
    ///
    /// AES-128 means a 128-bit key; [MS-OFFCRYPTO] §2.3.2 gives AES-192 and AES-256 their
    /// own AlgIDs (`0x0000660F` / `0x00006610`, against AES-128's `0x0000660E`), which
    /// `standard::require_aes_128` rejects by name before this is read. The
    /// field is nevertheless an unconstrained u32 in the file, and it sizes two things:
    /// `KeySize / 8` truncates the fixed 40-byte SHA-1 XOR-ladder buffer, and the result is
    /// then handed to AES-128, which accepts exactly 16 bytes and panics otherwise.
    pub(crate) const STANDARD_KEY_BITS_AES128: u32 = 128;
}
