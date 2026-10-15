//! What the streaming entry points hold in memory, measured rather than argued (#35).
//!
//! The round-trip tests in `src/streaming_tests.rs` would pass just the same against an
//! implementation that read the whole package into a `Vec` and wrote it out again; only a
//! memory bound tells streaming from buffering. So this binary installs a counting global
//! allocator, pushes a package through each streaming path at two sizes, and asserts the
//! peak heap each one adds above where it started.
//!
//! **The bound is a slope, not a constant, and the slope is `cfb`'s.** Every byte of the
//! document passes through one 4096-byte segment slot, so the crate's own working set is
//! flat; but `cfb` 0.15 keeps the whole sector table of the container in memory, 4 bytes
//! per 512-byte sector, and a cached sector list for the stream being read or written,
//! the same again — 1/64 of the payload as data, and more as `Vec`s that grow by
//! doubling; opening a container also reads its table through a temporary buffer.
//! Measured in a release build on 2026-10-15, the peak each pass adds is:
//!
//! | payload | encrypt | decrypt |
//! | --- | --- | --- |
//! | 256 MiB | 9.0 MiB | 11.5 MiB |
//! | 1 GiB | 33 MiB | 46 MiB |
//!
//! a slope of about 1/32 on encrypt and 1/22 on decrypt, the same for agile and standard
//! — so about 66 and 92 MiB at the 2 GiB a version 3 container can hold. The owner chose
//! to keep `cfb` as released rather than fork it (plan #27, decision 1). The assertion
//! allows 1/16 plus a fixed working set, room for a doubling at any size; a buffering
//! implementation needs at least the payload itself, which is what it is set to tell
//! apart.
//!
//! Its own test binary because a `#[global_allocator]` is process-wide: anywhere else it
//! would count every test running beside it. One test, one binary, one measurement — the
//! shape `tests/legacy_allocation.rs` set.
#![cfg(feature = "crypto-ops")]

use msoffice_crypto::{
    decrypt_ooxml_to, encrypt_ooxml_standard_to, encrypt_ooxml_to, IntegrityOutcome,
    IntegrityPolicy,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Live bytes, and the high-water mark of live bytes since the last reset. `Relaxed`
/// throughout, for `tests/legacy_allocation.rs`'s reason: one thread measuring itself.
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

impl Counting {
    fn grew(by: usize) {
        let live = LIVE.fetch_add(by, Ordering::Relaxed) + by;
        PEAK.fetch_max(live, Ordering::Relaxed);
    }
}

// SAFETY: every method forwards to `System` with the same arguments and returns its
// pointer unchanged; the counters are the only addition and touch no allocation state.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Self::grew(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size > layout.size() {
            Self::grew(new_size - layout.size());
        } else {
            LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// The crate's own working set and everything it allocates per pass that does not scale
/// with the document: the segment slot, the HMAC and cipher states, the `EncryptionInfo`
/// document, `cfb`'s 1 MiB stream buffer and its directory. Measured at a little over
/// 2 MiB; the margin is for `cfb`'s vectors growing by doubling.
const FIXED: usize = 6 << 20;

/// `cfb`'s share, per byte of payload: its sector table and the cached sector list, 4
/// bytes each per 512-byte sector, held in `Vec`s that may be twice the size of what they
/// hold. Measured at about 1/22 at worst; see the module docs.
const SLOPE_DIVISOR: usize = 16;

/// The two sizes measured. The larger is what a buffering path could not fit under the
/// bound — it would need at least this much again — and the pair together pins the slope.
const SMALL: u64 = 32 << 20;
const LARGE: u64 = 128 << 20;

/// The heap a phase may add, for a payload of `len` bytes.
fn bound(len: u64) -> usize {
    FIXED + usize::try_from(len).unwrap() / SLOPE_DIVISOR
}

/// Run `f` and return the most it added to the heap above where it started.
fn peak_growth<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let out = f();
    (out, PEAK.load(Ordering::Relaxed) - base)
}

/// The byte at `i` of a plain package `len` long: a ZIP signature, so the encrypt paths'
/// shape guard takes it for a package, then a pattern that is not all one byte, so a
/// segment that was dropped or repeated would not read back the same.
fn pattern_byte(i: u64) -> u8 {
    match i {
        0 => b'P',
        1 => b'K',
        2 => 3,
        3 => 4,
        _ => (i % 251) as u8,
    }
}

/// `len` bytes of [`pattern_byte`], produced as they are read. Allocates nothing.
struct Pattern {
    pos: u64,
    len: u64,
}

impl Read for Pattern {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = usize::try_from(self.len.saturating_sub(self.pos))
            .unwrap_or(usize::MAX)
            .min(buf.len());
        for (k, b) in buf[..n].iter_mut().enumerate() {
            *b = pattern_byte(self.pos + k as u64);
        }
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Pattern {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(d) => self.len.saturating_add_signed(d),
            SeekFrom::Current(d) => self.pos.saturating_add_signed(d),
        };
        Ok(self.pos)
    }
}

/// A writer that checks every byte against [`pattern_byte`] as it arrives and keeps none
/// of them: the decrypt paths' plaintext, verified without being held.
struct Verify {
    pos: u64,
}

impl Write for Verify {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for (k, &b) in buf.iter().enumerate() {
            let at = self.pos + k as u64;
            if b != pattern_byte(at) {
                return Err(io::Error::other(format!("plaintext differs at byte {at}")));
            }
        }
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A scratch file the container is assembled in: `cfb` reads back what it writes, so the
/// encrypt side's writer must be readable too, and on disk so that the container itself
/// is not counted against the bound.
fn scratch(name: &str) -> (File, PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "msoffice-crypto-streaming-memory-{}-{name}",
        std::process::id()
    ));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    (file, path)
}

/// Encrypt `len` bytes into a scratch file and decrypt them back out of it, measuring
/// both. Returns the two growths.
fn measure(standard: bool, len: u64) -> (usize, usize) {
    let (mut file, path) = scratch(if standard { "standard" } else { "agile" });

    let (result, encrypt) = peak_growth(|| {
        let reader = Pattern { pos: 0, len };
        if standard {
            encrypt_ooxml_standard_to(reader, &mut file, "testpass")
        } else {
            encrypt_ooxml_to(reader, &mut file, "testpass")
        }
    });
    result.unwrap();

    file.seek(SeekFrom::Start(0)).unwrap();
    let mut sink = Verify { pos: 0 };
    let (outcome, decrypt) = peak_growth(|| {
        decrypt_ooxml_to(&mut file, &mut sink, "testpass", IntegrityPolicy::default())
    });
    let want = if standard {
        IntegrityOutcome::NotApplicable
    } else {
        IntegrityOutcome::Verified
    };
    assert_eq!(outcome.unwrap().integrity, want);
    assert_eq!(sink.pos, len, "every byte came back");

    drop(file);
    std::fs::remove_file(&path).unwrap();
    (encrypt, decrypt)
}

#[test]
fn streaming_holds_a_working_set_and_cfbs_sector_table_not_the_document() {
    for standard in [false, true] {
        let format = if standard { "standard" } else { "agile" };
        let (encrypt_small, decrypt_small) = measure(standard, SMALL);
        let (encrypt_large, decrypt_large) = measure(standard, LARGE);
        println!(
            "{format}: encrypt {encrypt_small} -> {encrypt_large} bytes, decrypt {decrypt_small} \
             -> {decrypt_large} bytes, for {SMALL} -> {LARGE} bytes of payload"
        );

        for (phase, small, large) in [
            ("encrypt", encrypt_small, encrypt_large),
            ("decrypt", decrypt_small, decrypt_large),
        ] {
            assert!(
                small <= bound(SMALL),
                "{format} {phase} added {small} bytes for {SMALL}; the bound is {}",
                bound(SMALL)
            );
            assert!(
                large <= bound(LARGE),
                "{format} {phase} added {large} bytes for {LARGE}; the bound is {}",
                bound(LARGE)
            );
            // The slope on its own, so that a fixed cost which happened to fit both
            // absolute bounds cannot hide a per-byte one: what four times the payload
            // added must be no more than `cfb`'s share of the difference, plus slack for
            // one doubling of its vectors.
            let delta = large.saturating_sub(small);
            let allowed = usize::try_from(LARGE - SMALL).unwrap() / SLOPE_DIVISOR + (2 << 20);
            assert!(
                delta <= allowed,
                "{format} {phase} grew by {delta} bytes for {} more payload; at most {allowed}",
                LARGE - SMALL
            );
        }
    }
}
