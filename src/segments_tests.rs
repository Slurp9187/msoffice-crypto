//! Segmentation and per-segment IV derivation.
//!
//! These are the tests the inline `chunks(4096).enumerate()` in `decrypt_package` could
//! not have: it was reachable only with a session key and a parsed `AgileParams`, so every
//! statement about *segmentation* had to be made through a full decrypt, and a boundary
//! bug was only ever visible as a wrong plaintext. Extracting the loop (plan D4) is what
//! makes the boundaries assertable on their own — and the encrypt path leans on the same
//! guarantees from the other side.
//!
//! Since the streaming API the segmenter reads rather than borrows, so every test here
//! drives it through a reader, and three of them are about reading itself: a reader that
//! returns short, one that is interrupted, and one that fails.

use super::*;
use std::io::{Cursor, Error as IoError};

const SALT: [u8; 16] = [0x5Au8; 16];

/// One segment as the slot held it: the input bytes, the padded bytes and the IV.
struct Seg {
    bytes: Vec<u8>,
    padded: Vec<u8>,
    iv: Vec<u8>,
}

/// Segment everything `reader` yields under `hash` with a 16-byte block.
fn segment_reader(reader: &mut impl Read, hash: HashAlgorithm) -> Result<Vec<Seg>, Error> {
    let mut segmenter = Segmenter::new(hash, &SALT, 16)?;
    let mut slot = [0xEEu8; SEGMENT_LEN];
    let mut out = Vec::new();
    while let Some(f) = segmenter.fill(reader, &mut slot)? {
        out.push(Seg {
            bytes: slot[..f.len].to_vec(),
            padded: slot[..f.padded_len].to_vec(),
            iv: f.iv,
        });
    }
    Ok(out)
}

/// Segment `data` under SHA-512 with a 16-byte block, the tuple every fixture uses.
fn segments(data: &[u8]) -> Vec<Seg> {
    segment_reader(&mut Cursor::new(data), HashAlgorithm::Sha512)
        .expect("SHA-512 with a 16-byte block is always segmentable")
}

/// Where the cuts fall, across every shape the final segment can take.
///
/// The three interesting cases are an exact multiple (no short tail), one byte over (a
/// 1-byte tail, the most likely off-by-one), and one byte under (a 4095-byte tail). Empty
/// input yields nothing rather than one empty segment — a writer handed an empty package
/// must emit no ciphertext, not one segment of padding.
#[test]
fn the_cuts_fall_where_the_format_says() {
    for (len, want_lens) in [
        (0usize, vec![]),
        (1, vec![1usize]),
        (SEGMENT_LEN - 1, vec![SEGMENT_LEN - 1]),
        (SEGMENT_LEN, vec![SEGMENT_LEN]),
        (SEGMENT_LEN + 1, vec![SEGMENT_LEN, 1]),
        (SEGMENT_LEN * 2, vec![SEGMENT_LEN, SEGMENT_LEN]),
        (SEGMENT_LEN * 2 + 17, vec![SEGMENT_LEN, SEGMENT_LEN, 17]),
    ] {
        let data = vec![0u8; len];
        let got: Vec<usize> = segments(&data).iter().map(|s| s.bytes.len()).collect();
        assert_eq!(got, want_lens, "wrong cuts for a {len}-byte payload");
    }
}

/// The segments partition the input: concatenating them reproduces it exactly.
///
/// A cut that dropped or duplicated a byte would still produce plausible segment
/// *lengths*, so the lengths above are not sufficient on their own. Distinct bytes rather
/// than zeros, so a duplicated segment is visible.
#[test]
fn the_segments_partition_the_payload_without_loss() {
    let data: Vec<u8> = (0..SEGMENT_LEN * 3 + 123)
        .map(|i| (i % 251) as u8)
        .collect();
    let rejoined: Vec<u8> = segments(&data)
        .iter()
        .flat_map(|s| s.bytes.iter().copied())
        .collect();
    assert_eq!(rejoined, data);
}

/// Each segment's IV is `H(salt || LE32(index))[..block_size]`, derived independently.
///
/// The expectation is recomputed here from the formula rather than taken from the
/// iterator, so this is a statement about the format and not a restatement of the code.
/// The `enumerate()` index is what the segment's IV must agree with — which is also why
/// `Segment` need not carry the index itself.
#[test]
fn each_segment_gets_the_iv_its_index_derives() {
    let data = vec![0u8; SEGMENT_LEN * 3 + 1];
    for (index, segment) in segments(&data).iter().enumerate() {
        let want = derive_iv(
            HashAlgorithm::Sha512,
            &SALT,
            &(index as u32).to_le_bytes(),
            16,
        )
        .unwrap();
        assert_eq!(segment.iv, want, "segment {index} has the wrong IV");
        assert_eq!(segment.iv.len(), 16, "the IV is truncated to blockSize");
    }
}

/// No two segments share an IV.
///
/// The failure this exists for is a counter that never advances — every segment encrypted
/// under IV zero. Under CBC with one key that is a catastrophic reuse, and a round-trip
/// test cannot see it at all: encrypt and decrypt would agree with each other perfectly.
#[test]
fn no_two_segments_share_an_iv() {
    let data = vec![0u8; SEGMENT_LEN * 8];
    let ivs: Vec<Vec<u8>> = segments(&data).into_iter().map(|s| s.iv).collect();
    assert_eq!(ivs.len(), 8);
    let mut unique = ivs.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), ivs.len(), "an IV was reused across segments");
}

/// The IV follows the hash the file names, not a hardcoded SHA-512.
///
/// This is GH #11's bug expressed at the level it actually lived at. Two algorithms over
/// the same salt and index must not produce the same IV; when `decrypt_package` hardcoded
/// SHA-512, a SHA-1 file decrypted under IVs from the wrong hash *after* `integrity::verify`
/// had reported `Verified` under the right ones.
#[test]
fn the_iv_follows_the_named_hash_algorithm() {
    let data = vec![0u8; SEGMENT_LEN + 1];
    let sha512 = segments(&data);
    let sha1 = segment_reader(&mut Cursor::new(&data), HashAlgorithm::Sha1).unwrap();

    assert_eq!(sha1.len(), sha512.len());
    for (i, (a, b)) in sha1.iter().zip(sha512.iter()).enumerate() {
        assert_ne!(
            a.iv, b.iv,
            "segment {i} derived the same IV under two hashes"
        );
    }
}

/// A block size longer than the digest is an error, not a slice past the end.
///
/// SHA-1 produces 20 bytes, so a 32-byte block size has nothing to truncate from. The
/// constructor is where this is caught, so it costs one check for the whole payload rather
/// than one per segment — and the message names the field the file declared.
#[test]
fn a_block_size_past_the_digest_is_an_error_not_a_panic() {
    let got = Segmenter::new(HashAlgorithm::Sha1, &SALT, 32).map(|_| ());
    assert!(
        matches!(
            &got,
            Err(Error::InvariantViolated(crate::Invariant::BlockSizeOverDigest))
        ),
        "a 32-byte block under SHA-1 must be refused, got: {got:?}"
    );

    // The control: 20 is exactly the digest length and is accepted, so the refusal is
    // about the excess and not about SHA-1 being rejected outright.
    assert!(Segmenter::new(HashAlgorithm::Sha1, &SALT, 20).is_ok());
}

/// Padding rounds the final segment up to an AES block and leaves the rest alone.
///
/// Zeros, matching herumi's `data.resize(RoundUp(size, 16))` (`include/encode.hpp:79`).
/// The pad is invisible to a caller — the reader truncates to the stream's declared
/// plaintext size — but it is part of the ciphertext a writer emits, so it has to match
/// what other implementations produce for the encrypt path's golden output to mean
/// anything.
#[test]
fn the_final_segment_pads_up_to_an_aes_block_with_zeros() {
    let data: Vec<u8> = (0..SEGMENT_LEN + 17).map(|_| 0xAB).collect();
    let segs = segments(&data);
    assert_eq!(segs.len(), 2);

    // A full segment is already a block multiple: padding does not grow it.
    assert_eq!(segs[0].padded.len(), SEGMENT_LEN);
    assert_eq!(segs[0].padded, segs[0].bytes);

    // 17 bytes rounds up to 32, and the fifteen added bytes are zero — written over the
    // slot's previous contents (0xEE in `segment_reader`), not merely left as found.
    let padded = &segs[1].padded;
    assert_eq!(padded.len(), 32);
    assert_eq!(&padded[..17], &[0xABu8; 17]);
    assert_eq!(&padded[17..], &[0u8; 15]);
}

/// A reader that returns short still yields whole segments.
///
/// `Read::read` may hand back one byte at a time and still be nowhere near the end — a
/// pipe, a decompressor and a cancelling wrapper all do — so a segmenter that took one
/// call for one segment would cut a 4096-byte segment into one-byte ones, each under its
/// own IV, and write a file no reader can open.
#[test]
fn a_reader_that_returns_short_still_yields_whole_segments() {
    struct OneByte<'a>(&'a [u8]);
    impl Read for OneByte<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let (Some((first, rest)), Some(slot)) = (self.0.split_first(), buf.first_mut()) else {
                return Ok(0);
            };
            *slot = *first;
            self.0 = rest;
            Ok(1)
        }
    }
    let data: Vec<u8> = (0..SEGMENT_LEN * 2 + 9).map(|i| (i % 251) as u8).collect();
    let got = segment_reader(&mut OneByte(&data), HashAlgorithm::Sha512).unwrap();
    let lens: Vec<usize> = got.iter().map(|s| s.bytes.len()).collect();
    assert_eq!(lens, vec![SEGMENT_LEN, SEGMENT_LEN, 9]);
    let rejoined: Vec<u8> = got.iter().flat_map(|s| s.bytes.iter().copied()).collect();
    assert_eq!(rejoined, data);
}

/// `Interrupted` is retried; any other reader error is the caller's, as `Error::Io`.
///
/// The second half is the cancellation contract: a caller stops a pass by making its
/// reader fail, and that failure must come back as itself rather than as a short,
/// apparently complete payload.
#[test]
fn an_interrupted_read_is_retried_and_a_failing_one_is_returned() {
    struct Flaky {
        calls: usize,
        third: Option<std::io::ErrorKind>,
    }
    impl Read for Flaky {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.calls += 1;
            match (self.calls, self.third) {
                (1, _) => Err(IoError::from(std::io::ErrorKind::Interrupted)),
                (2, _) => {
                    let n = buf.len().min(100);
                    buf[..n].fill(7);
                    Ok(n)
                }
                (3, Some(kind)) => Err(IoError::from(kind)),
                _ => Ok(0),
            }
        }
    }

    let mut cancelled = Flaky {
        calls: 0,
        third: Some(std::io::ErrorKind::Other),
    };
    let got = segment_reader(&mut cancelled, HashAlgorithm::Sha512).map(|v| v.len());
    assert!(
        matches!(&got, Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::Other),
        "a failing reader must surface as Error::Io, got: {got:?}"
    );

    // The control: the same reader with its third call ending cleanly. The `Interrupted`
    // first call is retried, and the 100 bytes arrive as one short segment.
    let mut finishing = Flaky {
        calls: 0,
        third: None,
    };
    let got = segment_reader(&mut finishing, HashAlgorithm::Sha512).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].bytes, vec![7u8; 100]);
}

/// Past index `u32::MAX` the segmenter refuses rather than wraps to IV zero.
///
/// Four billion segments is 16 TiB, so this sets the counter to its end directly rather
/// than reaching it through a payload. The last legal index is used once, and the segment
/// after it is an error, not a reuse of segment 0's IV.
#[test]
fn the_segment_index_refuses_to_wrap() {
    let mut segmenter = Segmenter::new(HashAlgorithm::Sha512, &SALT, 16).unwrap();
    segmenter.next_index = Some(u32::MAX);
    let mut slot = [0u8; SEGMENT_LEN];
    let data = vec![0u8; SEGMENT_LEN * 2];
    let mut reader = Cursor::new(&data);

    let last = segmenter.fill(&mut reader, &mut slot).unwrap().unwrap();
    let want = derive_iv(HashAlgorithm::Sha512, &SALT, &u32::MAX.to_le_bytes(), 16).unwrap();
    assert_eq!(last.iv, want, "index u32::MAX is still a legal segment");

    let past = segmenter
        .fill(&mut reader, &mut slot)
        .map(|f| f.map(|f| f.len));
    assert!(
        matches!(
            &past,
            Err(Error::InvariantViolated(crate::Invariant::CounterOverflow))
        ),
        "the segment after u32::MAX must be refused, got: {past:?}"
    );
}
