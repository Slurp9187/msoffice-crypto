//! The streaming entry points (#27): `decrypt_ooxml_to`, the four `encrypt_*_to`, and
//! `classify_from` / `is_cfb_office_from`.
//!
//! Three kinds of test, each answering a question the whole-buffer suite cannot:
//!
//! - **Agreement.** The streaming and whole-buffer forms give the same answer on the same
//!   input, byte for byte. Since the whole-buffer functions became `Cursor` wrappers this
//!   is partly structural, so the agreement tests also run the streaming form over
//!   writers that are not a `Cursor<Vec<u8>>`.
//! - **What only a stream can do.** A reader that is cancelled, one that lies about its
//!   length, one that changes between the two passes of a verified decrypt.
//! - **Where the bounds moved.** The 1 GiB ceiling stays on the whole-buffer paths and
//!   leaves the streaming ones; the version 3 container cap arrives on the streaming
//!   encrypt.
//!
//! Each guard here was deleted once and its test watched failing; the PR that added
//! them records what each failure looked like.

use crate::*;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

const PASSWORD: &str = "testpass";

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("fixture {name} must be present, not optional: {e}"))
}

/// A writer that counts what reaches it and keeps none of it: the evidence that a
/// refusal happened before any plaintext was released, and the shape of EFV's hashing
/// sink, which is `Write` and nothing else.
#[derive(Default)]
struct Counting {
    bytes: usize,
}

impl Write for Counting {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A readable, seekable, writable sink that records whether anything was written: the
/// encrypt side's `W`, for proving a refusal left the caller's writer untouched.
#[derive(Default)]
struct Untouched {
    inner: Cursor<Vec<u8>>,
    writes: usize,
}

impl Read for Untouched {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}
impl Write for Untouched {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Seek for Untouched {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// A reader over `data` that fails with `ErrorKind::Other` once `fail_after` bytes have
/// been read — how a caller cancels a pass.
struct Cancelling {
    inner: Cursor<Vec<u8>>,
    fail_after: u64,
}

impl Read for Cancelling {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.inner.position() >= self.fail_after {
            return Err(io::Error::other("cancelled by the caller"));
        }
        let room = usize::try_from(self.fail_after - self.inner.position()).unwrap_or(usize::MAX);
        let n = buf.len().min(room);
        self.inner.read(&mut buf[..n])
    }
}
impl Seek for Cancelling {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

// ---- agreement --------------------------------------------------------------------

/// The streaming encrypt writes what the whole-buffer one returns, through a writer that
/// is a real file rather than a `Cursor`. Same seed, same bytes — so the seeded goldens
/// that pin `encrypt` pin `encrypt_to` too, whichever writer it is given.
#[test]
fn the_streaming_writers_write_the_whole_buffer_writers_bytes_into_a_file() {
    use chacha20::rand_core::SeedableRng;
    let plain = fixture("plain.docx");
    let dir = std::env::temp_dir().join(format!("msoc-streaming-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let params = EncryptParams::default();
    let whole = agile_encrypt::encrypt(
        &plain,
        PASSWORD,
        params,
        &mut chacha20::ChaCha12Rng::seed_from_u64(7),
    )
    .unwrap();
    let path = dir.join("agile.docx");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    agile_encrypt::encrypt_to(
        &mut Cursor::new(&plain),
        &mut file,
        PASSWORD,
        params,
        &mut chacha20::ChaCha12Rng::seed_from_u64(7),
    )
    .unwrap();
    drop(file);
    assert_eq!(std::fs::read(&path).unwrap(), whole, "agile");

    let whole = standard_encrypt::encrypt(
        &plain,
        PASSWORD,
        standard_encrypt::DEFAULT_KEY_BITS,
        &mut chacha20::ChaCha12Rng::seed_from_u64(7),
    )
    .unwrap();
    let path = dir.join("standard.docx");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    standard_encrypt::encrypt_to(
        &mut Cursor::new(&plain),
        &mut file,
        PASSWORD,
        standard_encrypt::DEFAULT_KEY_BITS,
        &mut chacha20::ChaCha12Rng::seed_from_u64(7),
    )
    .unwrap();
    drop(file);
    assert_eq!(std::fs::read(&path).unwrap(), whole, "standard");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// One of the four public streaming encrypts, over a package and a writer.
type EncryptTo = fn(&[u8], &mut Cursor<Vec<u8>>) -> Result<(), Error>;

/// Every public streaming encrypt round-trips through every decrypt form, and the
/// streaming decrypt reports what the whole-buffer one does.
#[test]
fn every_streaming_encrypt_round_trips() {
    let plain = fixture("plain.docx");
    let cases: [(&str, EncryptTo, IntegrityOutcome); 4] = [
        (
            "encrypt_ooxml_to",
            |p, w| encrypt_ooxml_to(Cursor::new(p), w, PASSWORD),
            IntegrityOutcome::Verified,
        ),
        (
            "encrypt_ooxml_with_params_to",
            |p, w| {
                encrypt_ooxml_with_params_to(Cursor::new(p), w, PASSWORD, EncryptParams::default())
            },
            IntegrityOutcome::Verified,
        ),
        (
            "encrypt_ooxml_standard_to",
            |p, w| encrypt_ooxml_standard_to(Cursor::new(p), w, PASSWORD),
            IntegrityOutcome::NotApplicable,
        ),
        (
            "encrypt_ooxml_standard_with_key_bits_to(256)",
            |p, w| encrypt_ooxml_standard_with_key_bits_to(Cursor::new(p), w, PASSWORD, 256),
            IntegrityOutcome::NotApplicable,
        ),
    ];
    for (name, encrypt, want) in cases {
        let mut out = Cursor::new(Vec::new());
        encrypt(&plain, &mut out).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let encrypted = out.into_inner();

        assert_eq!(
            decrypt_ooxml(&encrypted, PASSWORD).unwrap(),
            plain,
            "{name}"
        );
        let mut streamed = Vec::new();
        let outcome = decrypt_ooxml_to(
            Cursor::new(&encrypted),
            &mut streamed,
            PASSWORD,
            IntegrityPolicy::default(),
        )
        .unwrap();
        assert_eq!(streamed, plain, "{name} through decrypt_ooxml_to");
        assert_eq!(outcome.integrity, want, "{name}");
    }
}

/// The streaming decrypt agrees with the whole-buffer one on every encrypted OOXML file
/// in the corpus, Office-written ones included, under every policy that opens it.
#[test]
#[cfg_attr(
    not(fixture_corpus),
    ignore = "needs the fixture corpus, which the published crate does not ship"
)]
fn the_streaming_decrypt_agrees_with_the_whole_buffer_one_on_the_corpus() {
    for name in [
        "agile_encrypted.docx",
        "agile_aes128_sha1.docx",
        "agile_aes128_sha384.docx",
        "agile_aes192_sha384.docx",
        "agile_aes256_sha256.docx",
        "agile_aes256_sha384.docx",
        "word16_agile.docx",
        "excel16_agile.xlsx",
        "powerpoint16_agile.pptx",
        "standard_encrypted.docx",
    ] {
        let data = fixture(name);
        for policy in [
            IntegrityPolicy::RequireWhereDefined,
            IntegrityPolicy::VerifyIfPresent,
            IntegrityPolicy::Skip,
        ] {
            let whole = decrypt_ooxml_with_policy(&data, PASSWORD, policy).unwrap();
            let mut streamed = Vec::new();
            let outcome =
                decrypt_ooxml_to(Cursor::new(&data), &mut streamed, PASSWORD, policy).unwrap();
            assert_eq!(streamed, whole.package, "{name} under {policy:?}");
            assert_eq!(
                outcome.integrity, whole.integrity,
                "{name} under {policy:?}"
            );
        }
    }
}

/// `classify_from` gives `classify`'s answer on every fixture, encrypted or not, OOXML or
/// binary — and `is_cfb_office_from` gives `is_cfb_office`'s.
#[test]
#[cfg_attr(
    not(fixture_corpus),
    ignore = "needs the fixture corpus, which the published crate does not ship"
)]
fn classify_from_agrees_with_classify_on_the_corpus() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let data = std::fs::read(&path).unwrap();
        let name = path.display();
        assert_eq!(classify_from(Cursor::new(&data)), classify(&data), "{name}");
        assert_eq!(
            is_cfb_office_from(Cursor::new(&data)),
            is_cfb_office(&data),
            "{name}"
        );
        seen += 1;
    }
    assert!(seen >= 20, "the corpus is all here: {seen} files");
}

/// The shipped pair, so the published crate's own suite exercises the reader forms too,
/// and every truncation of the agile file: the prefixes are the hostile inputs `classify`
/// is hardened against, through the second door.
#[test]
fn classify_from_agrees_with_classify_on_the_shipped_fixtures_and_their_prefixes() {
    for name in ["plain.docx", "agile_encrypted.docx"] {
        let data = fixture(name);
        assert_eq!(classify_from(Cursor::new(&data)), classify(&data), "{name}");
        assert!(classify_from(Cursor::new(&data)).container != Container::Unknown);
    }
    let agile = fixture("agile_encrypted.docx");
    for len in [
        0,
        1,
        7,
        8,
        9,
        511,
        512,
        513,
        1024,
        4096,
        agile.len() / 2,
        agile.len() - 1,
    ] {
        let prefix = &agile[..len];
        assert_eq!(
            classify_from(Cursor::new(prefix)),
            classify(prefix),
            "{len}-byte prefix"
        );
        assert_eq!(
            is_cfb_office_from(Cursor::new(prefix)),
            is_cfb_office(prefix)
        );
    }
}

/// A reader that fails while being classified is "could not look", not a verdict about
/// the file, and never a panic.
#[test]
fn classify_from_reports_a_failing_reader_as_unreadable() {
    let agile = fixture("agile_encrypted.docx");
    // Past the magic, inside the header `cfb` reads to open the container.
    let class = classify_from(Cancelling {
        inner: Cursor::new(agile.clone()),
        fail_after: 100,
    });
    assert_eq!(class.container, Container::Cfb);
    assert_eq!(class.container_read, ContainerRead::Unreadable);
    assert_eq!(class.document, Document::Unknown);

    // Before the magic: nothing could be read, so nothing is claimed about the container.
    let class = classify_from(Cancelling {
        inner: Cursor::new(agile.clone()),
        fail_after: 0,
    });
    assert_eq!(class.container, Container::Unknown);
    assert!(!is_cfb_office_from(Cancelling {
        inner: Cursor::new(agile),
        fail_after: 4,
    }));
}

// ---- what only a stream can do ----------------------------------------------------

/// A tampered ciphertext body is refused before a single byte of plaintext reaches the
/// writer, and `Skip` on the same file is the negative control: it decrypts, and writes.
///
/// The byte flipped is deep in the package's ciphertext, not the container or the size
/// prefix, so the refusal is the MAC's and not a parse failure's.
#[test]
fn a_tampered_package_is_refused_before_any_plaintext_is_written() {
    let mut data = Cursor::new(Vec::new());
    encrypt_ooxml_to(Cursor::new(fixture("plain.docx")), &mut data, PASSWORD).unwrap();
    let mut data = data.into_inner();
    let offset = package_offset(&data) + 8 + 5000;
    data[offset] ^= 0x01;

    let mut sink = Counting::default();
    let got = decrypt_ooxml_to(
        Cursor::new(&data),
        &mut sink,
        PASSWORD,
        IntegrityPolicy::default(),
    );
    assert!(
        matches!(got, Err(Error::IntegrityCheckFailed)),
        "got {got:?}"
    );
    assert_eq!(
        sink.bytes, 0,
        "no plaintext may reach the writer before the tag verifies"
    );

    let mut sink = Counting::default();
    let got = decrypt_ooxml_to(
        Cursor::new(&data),
        &mut sink,
        PASSWORD,
        IntegrityPolicy::Skip,
    )
    .unwrap();
    assert_eq!(got.integrity, IntegrityOutcome::Skipped);
    assert!(sink.bytes > 0, "the control decrypts");
}

/// Where the `\EncryptedPackage` stream starts in a container this crate wrote: its
/// first sector. Found by the size prefix rather than by parsing the FAT, which is all a
/// test that flips one byte inside it needs.
fn package_offset(container: &[u8]) -> usize {
    let mut cfb = cfb::CompoundFile::open(Cursor::new(container)).unwrap();
    let mut prefix = [0u8; 16];
    cfb.open_stream("/EncryptedPackage")
        .unwrap()
        .read_exact(&mut prefix)
        .unwrap();
    container
        .windows(16)
        .position(|w| w == prefix)
        .expect("the package's first sector is in the file")
}

/// A package stream that reads one way the first time and another the second: the file
/// changed between the verified decrypt's two passes. The second pass's tag disagrees,
/// and the result is `IntegrityCheckFailed` — after plaintext reached the writer, which
/// is why the contract says to discard it on any `Err`.
///
/// Driven at `agile::decrypt_to` with the package stream itself as the reader, because
/// through a container `cfb`'s 1 MiB stream buffer serves the second pass from memory for
/// a file this small, and the change would never be seen.
#[test]
fn a_package_that_changes_between_the_two_passes_is_refused() {
    struct Shifting {
        inner: Cursor<Vec<u8>>,
        flip_at: u64,
        seen: bool,
        flipped: bool,
    }
    impl Read for Shifting {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let start = self.inner.position();
            if (start..start + buf.len() as u64).contains(&self.flip_at) {
                if self.seen && !self.flipped {
                    let at = usize::try_from(self.flip_at).unwrap();
                    self.inner.get_mut()[at] ^= 0x01;
                    self.flipped = true;
                }
                self.seen = true;
            }
            self.inner.read(buf)
        }
    }
    impl Seek for Shifting {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    let mut container = Cursor::new(Vec::new());
    encrypt_ooxml_to(Cursor::new(fixture("plain.docx")), &mut container, PASSWORD).unwrap();
    let mut cfb = cfb::CompoundFile::open(Cursor::new(container.into_inner())).unwrap();
    let info = cfb_reader::read_encryption_info_in(&mut cfb).unwrap();
    let mut package = Vec::new();
    cfb.open_stream("/EncryptedPackage")
        .unwrap()
        .read_to_end(&mut package)
        .unwrap();

    let mut shifting = Shifting {
        inner: Cursor::new(package.clone()),
        flip_at: 8 + 5000,
        seen: false,
        flipped: false,
    };
    let mut sink = Counting::default();
    let got = agile::decrypt_to(
        &info[8..],
        &mut shifting,
        &mut sink,
        PASSWORD,
        IntegrityPolicy::default(),
    );
    assert!(
        matches!(got, Err(Error::IntegrityCheckFailed)),
        "got {got:?}"
    );
    assert!(shifting.flipped, "the change happened, on the second pass");
    assert!(
        sink.bytes > 0,
        "the second pass had written plaintext when it caught it"
    );

    // The control: the same stream, unchanged, decrypts under the same policy.
    let mut sink = Counting::default();
    let got = agile::decrypt_to(
        &info[8..],
        &mut Cursor::new(package),
        &mut sink,
        PASSWORD,
        IntegrityPolicy::default(),
    );
    assert_eq!(got.unwrap(), IntegrityOutcome::Verified);
}

/// A cancelled reader stops a decrypt or an encrypt with its own error, as `Error::Io`
/// — not as a damaged file — wherever in the pass it fires: while the container is
/// opened, and in the middle of the package.
#[test]
fn a_cancelled_reader_surfaces_as_its_own_io_error() {
    let encrypted = fixture("agile_encrypted.docx");
    for fail_after in [100, encrypted.len() as u64 - 4096] {
        let got = decrypt_ooxml_to(
            Cancelling {
                inner: Cursor::new(encrypted.clone()),
                fail_after,
            },
            Counting::default(),
            PASSWORD,
            IntegrityPolicy::default(),
        );
        assert!(
            matches!(&got, Err(Error::Io(e)) if e.kind() == io::ErrorKind::Other),
            "decrypt cancelled after {fail_after} bytes: {got:?}"
        );
    }

    let plain = fixture("plain.docx");
    let got = encrypt_ooxml_to(
        Cancelling {
            inner: Cursor::new(plain.clone()),
            fail_after: plain.len() as u64 / 2,
        },
        Cursor::new(Vec::new()),
        PASSWORD,
    );
    assert!(
        matches!(&got, Err(Error::Io(e)) if e.kind() == io::ErrorKind::Other),
        "encrypt cancelled half-way: {got:?}"
    );
}

/// A truncated container is still `NotACfbFile`, as it always was: the error-kind split
/// that lets a cancellation through must not let a damaged file through as `Io`.
#[test]
fn a_truncated_container_is_still_not_a_cfb_file() {
    let encrypted = fixture("agile_encrypted.docx");
    let got = decrypt_ooxml_to(
        Cursor::new(&encrypted[..600]),
        Counting::default(),
        PASSWORD,
        IntegrityPolicy::default(),
    );
    assert!(matches!(got, Err(Error::NotACfbFile)), "got {got:?}");
}

/// A reader is held to the length it was measured at. One that ends early, or has more to
/// give, changed while it was being encrypted, and the size prefix already written would
/// describe a document that does not exist.
#[test]
fn a_reader_that_does_not_keep_its_measured_length_is_refused() {
    let plain = fixture("plain.docx");
    let key = sensitive::SessionKey::new(vec![0x5A; 32]);
    let salt = [0x11u8; 16];
    let encrypt = |len: u64| {
        agile_encrypt::encrypt_package_to(
            &mut Cursor::new(&plain),
            len,
            &mut Vec::new(),
            &key,
            &salt,
            HashAlgorithm::Sha512,
            None,
        )
    };
    let short = encrypt(plain.len() as u64 + 1);
    assert!(
        matches!(&short, Err(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof),
        "a reader shorter than measured: {short:?}"
    );
    let long = encrypt(plain.len() as u64 - 1);
    assert!(
        matches!(&long, Err(Error::Io(e)) if e.kind() == io::ErrorKind::InvalidData),
        "a reader longer than measured: {long:?}"
    );
    encrypt(plain.len() as u64).expect("the control: exactly the measured length");

    let dk = sensitive::DerivedKey::new(vec![0x5A; 16]);
    let standard = |len: u64| {
        standard_encrypt::encrypt_package_to(&mut Cursor::new(&plain), len, &mut Vec::new(), &dk)
    };
    assert!(matches!(
        standard(plain.len() as u64 + 1),
        Err(Error::Io(_))
    ));
    assert!(matches!(
        standard(plain.len() as u64 - 1),
        Err(Error::Io(_))
    ));
    standard(plain.len() as u64).expect("the standard control");
}

// ---- where the bounds moved -------------------------------------------------------

/// A plain package that claims to be larger than a version 3 container can carry: a ZIP
/// signature and then, as far as `Seek` is concerned, `len` bytes of zeros. It actually
/// ends after 4096, so that a writer which skipped the cap fails fast on the short reader
/// instead of encrypting two gigabytes of zeros before the test can say anything.
struct Huge {
    pos: u64,
    len: u64,
}

impl Read for Huge {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(4096usize.saturating_sub(self.pos as usize));
        for (i, b) in buf[..n].iter_mut().enumerate() {
            *b = *b"PK\x03\x04".get(self.pos as usize + i).unwrap_or(&0);
        }
        self.pos += n as u64;
        Ok(n)
    }
}
impl Seek for Huge {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(d) => self.len.saturating_add_signed(d),
            SeekFrom::Current(d) => self.pos.saturating_add_signed(d),
        };
        Ok(self.pos)
    }
}

/// Past the version 3 stream cap the streaming encrypt refuses by name, with the measured
/// length and the limit, and leaves the caller's writer untouched — in both formats.
#[test]
fn a_package_past_the_v3_stream_cap_is_refused_before_anything_is_written() {
    let max = limits::STREAMED_PACKAGE_MAX;
    for over in [max + 1, max + 16, u64::MAX / 2] {
        for standard in [false, true] {
            let mut sink = Untouched::default();
            let reader = Huge { pos: 0, len: over };
            let got = if standard {
                encrypt_ooxml_standard_to(reader, &mut sink, PASSWORD)
            } else {
                encrypt_ooxml_to(reader, &mut sink, PASSWORD)
            };
            assert!(
                matches!(&got, Err(Error::PackageTooLarge { len, limit })
                    if *len == over && *limit == max),
                "standard={standard} len={over}: {got:?}"
            );
            assert_eq!(
                sink.writes, 0,
                "standard={standard}: the writer was touched"
            );
        }
    }
}

/// The cap is inclusive and lands where [MS-CFB] §2.6.1 puts it: the largest accepted
/// plaintext makes a stream of exactly 0x80000000 bytes or fewer, and one byte more would
/// make a longer one.
#[test]
fn the_v3_stream_cap_is_inclusive() {
    let max = limits::STREAMED_PACKAGE_MAX;
    assert!(agile_encrypt::refuse_past_v3_stream(max).is_ok());
    assert!(agile_encrypt::refuse_past_v3_stream(0).is_ok());
    assert!(matches!(
        agile_encrypt::refuse_past_v3_stream(max + 1),
        Err(Error::PackageTooLarge { .. })
    ));
    let stream_len = |n: u64| 8 + n.div_ceil(16) * 16;
    assert!(stream_len(max) <= limits::CFB_V3_STREAM_MAX);
    assert!(stream_len(max + 1) > limits::CFB_V3_STREAM_MAX);
}

/// The whole-buffer decrypt's ceiling is checked against the `\EncryptedPackage` stream's
/// length before a byte of it is read, and the streaming decrypt has none.
///
/// Driven through the shared core with a ceiling a test can afford, as the read cap it
/// replaced was; the real figure is the `const` assertion in `limits.rs`. The stream is
/// exactly the ceiling in the control, so the bound is inclusive and not off by one.
#[test]
fn the_whole_buffer_ceiling_measures_the_package_stream() {
    let data = fixture("agile_encrypted.docx");
    let stream_len = {
        let mut cfb = cfb::CompoundFile::open(Cursor::new(&data)).unwrap();
        cfb.open_stream("/EncryptedPackage").unwrap().len()
    };

    let mut sink = Counting::default();
    let got = decrypt_ooxml_core(
        Cursor::new(&data),
        &mut sink,
        PASSWORD,
        IntegrityPolicy::default(),
        Some(stream_len - 1),
    );
    assert!(
        matches!(&got, Err(Error::PackageTooLarge { len, limit })
            if *len == stream_len && *limit == stream_len - 1),
        "got {got:?}"
    );
    assert_eq!(sink.bytes, 0);

    let got = decrypt_ooxml_core(
        Cursor::new(&data),
        &mut Counting::default(),
        PASSWORD,
        IntegrityPolicy::default(),
        Some(stream_len),
    );
    assert_eq!(got.unwrap(), IntegrityOutcome::Verified);
}

/// `Require` on a standard file is refused before the payload is touched: the format
/// cannot give the guarantee asked for, so nothing is written.
#[test]
#[cfg_attr(
    not(fixture_corpus),
    ignore = "needs the fixture corpus, which the published crate does not ship"
)]
fn require_on_a_standard_file_writes_nothing() {
    let mut sink = Counting::default();
    let got = decrypt_ooxml_to(
        Cursor::new(fixture("standard_encrypted.docx")),
        &mut sink,
        PASSWORD,
        IntegrityPolicy::Require,
    );
    assert!(
        matches!(got, Err(Error::IntegrityUnavailable(_))),
        "got {got:?}"
    );
    assert_eq!(sink.bytes, 0);
}
