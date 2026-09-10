//! What a hostile `.xls` may cost in memory, measured rather than argued.
//!
//! CLAUDE.md § *Every input is hostile* calls unbounded work a vulnerability and names a
//! file-controlled allocation as one of its two shapes. A BIFF record count is exactly
//! that: the smallest legal record is four bytes on the wire, so a stream declares as
//! many records as it likes, and anything the walk keeps *per record* is multiplied by a
//! number the attacker chose.
//!
//! `excel97::decrypt` used to keep 24 bytes per record — it collected the whole walk into
//! a `Vec<BiffRecord>` before looking for FILEPASS, so before any key schedule and before
//! any password check. Two independent reviewers measured the same 9.0x peak-allocation
//! amplification on 2026-09-05, linear across 4/16/64 MiB, reached with a **wrong**
//! password. Against `LEGACY_STREAM_READ_CAP` (1 GiB) that is ~9 GiB: not an error a
//! caller can handle but an allocator abort no caller can catch.
//!
//! The walk is now two streaming passes that keep one record and two flags, so the record
//! count costs time (which the stream cap bounds) and not memory. This test is the guard:
//! it builds a workbook that is nothing but four-byte records and fails if the cost of
//! reading it ever again scales with how many there are.
//!
//! It lives in `tests/` rather than beside the code because a `#[global_allocator]` is
//! process-wide — in the lib's own test binary it would measure every other test running
//! in parallel too. One test, one binary, one measurement.
#![cfg(feature = "legacy-binary")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Cursor, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Live bytes, and the high-water mark of live bytes. `Relaxed` throughout: this counts
/// its own process for a single-threaded measurement, and the ordering between the
/// counter and the code under test is established by the call returning, not by the
/// atomics.
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

/// `[MS-XLS]` §2.1.4: every record is `id: u16`, `len: u16`, then `len` bytes. A BOF to
/// open the stream, then `count` records that are header and nothing else — the cheapest
/// thing a workbook can legally be made of, and so the worst case per byte.
fn workbook_of_empty_records(count: usize) -> Vec<u8> {
    const BOF: u16 = 0x0809;
    const INTERFACE_HDR: u16 = 0x00E1; // never-encrypted, so ordering is not the subject
    let mut book = Vec::with_capacity(4 + 16 + count * 4);
    book.extend_from_slice(&BOF.to_le_bytes());
    book.extend_from_slice(&16u16.to_le_bytes());
    book.extend_from_slice(&[0u8; 16]);
    for _ in 0..count {
        book.extend_from_slice(&INTERFACE_HDR.to_le_bytes());
        book.extend_from_slice(&0u16.to_le_bytes());
    }
    book
}

fn xls_containing(book: &[u8]) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut container = cfb::CompoundFile::create_with_version(cfb::Version::V3, &mut cursor)
            .expect("create CFB");
        {
            let mut stream = container.create_new_stream("Workbook").expect("Workbook");
            stream.write_all(book).expect("write Workbook");
            stream.flush().expect("flush stream");
        }
        container.flush().expect("flush container");
    }
    cursor.into_inner()
}

/// Reading a workbook of a million four-byte records must not cost a million records'
/// worth of heap.
///
/// The bar is **4x the file**, chosen to sit clearly between the two behaviours rather
/// than to pin an implementation detail: the collecting walk measured 9.0x, and the
/// streaming one costs the container's copy of the input plus the stream itself — about
/// 2x, with the decrypted twin never allocated at all because a workbook with no FILEPASS
/// is refused before it. Delete either streaming pass and this fails; it is the mutation
/// that proves the guard.
#[test]
fn a_workbook_of_a_million_tiny_records_does_not_allocate_per_record() {
    const RECORDS: usize = 1_000_000;
    let book = workbook_of_empty_records(RECORDS);
    let data = xls_containing(&book);
    assert!(
        book.len() > 4 * RECORDS,
        "the stream must really be built of {RECORDS} records"
    );

    // Measure only the call: start the high-water mark from what is already live.
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
    let before = LIVE.load(Ordering::Relaxed);
    let outcome = msoffice_crypto::decrypt_binary_office(&data, "not-the-password");
    let peak_during = PEAK.load(Ordering::Relaxed).saturating_sub(before);

    // No FILEPASS, so this is a plain workbook and is refused by name — reached without
    // deriving a key, which is the point: the cost above is what an unauthenticated
    // caller can impose.
    assert!(
        matches!(outcome, Err(msoffice_crypto::Error::NotEncrypted)),
        "a workbook with no FILEPASS is not encrypted, got: {outcome:?}"
    );

    let budget = 4 * data.len();
    assert!(
        peak_during <= budget,
        "reading a {} B .xls of {RECORDS} four-byte records peaked at {} B ({:.1}x the \
         file); the budget is {} B (4x). A per-record allocation is back.",
        data.len(),
        peak_during,
        peak_during as f64 / data.len() as f64,
        budget,
    );
}
