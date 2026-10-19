//! Capped reads of the CFB streams classification and decryption share.
//!
//! [`read_encryption_info_in`] takes `\EncryptionInfo` from an open container and refuses
//! anything over `ENCRYPTION_INFO_READ_CAP`; `classify_from` and the decrypt path both
//! call it, so the header stream has one cap and one set of error mappings, and a hostile
//! directory tree is an error (or, for `classify`, `Unknown`), never a panic.
//!
//! `\EncryptedPackage` is no longer read here. Since the streaming API the decrypt path
//! reads it a segment at a time straight out of the container, and the whole-buffer
//! ceiling is checked against the stream's length before the first byte is read.

use crate::error::Error;
use crate::limits::ENCRYPTION_INFO_READ_CAP;
use std::io::{Read, Seek};

/// Take `\EncryptionInfo` from a container already open — the shape `classify` and the
/// decrypt path use, which open the container once and ask it several things. The
/// payload is never read, so classifying a 200 MB document costs the container header
/// and one small stream.
///
/// # Errors
///
/// [`Error::MissingStream`] if the container holds no `EncryptionInfo`,
/// [`Error::BadParameters`] if that stream is larger than [`ENCRYPTION_INFO_READ_CAP`],
/// and [`Error::Io`] on a read failure.
pub(crate) fn read_encryption_info_in<F: Read + Seek>(
    cfb: &mut cfb::CompoundFile<F>,
) -> Result<Vec<u8>, Error> {
    read_capped(
        cfb.open_stream("/EncryptionInfo")
            .map_err(|_| Error::MissingStream("EncryptionInfo"))?,
        ENCRYPTION_INFO_READ_CAP,
        "EncryptionInfo",
    )
}

/// Read at most `cap` bytes, and report anything longer as a bad parameter.
///
/// `take(cap + 1)` rather than `take(cap)`: the extra byte is what distinguishes "exactly
/// at the ceiling" from "over it" without ever allocating past it. The same idiom
/// `odf-crypto` uses for its `MANIFEST_READ_CAP` reads (`odf-crypto/src/classify.rs`).
///
/// `pub(crate)` for `legacy_container`, which reads a binary document's streams under
/// the same idiom and the same kind of cap.
pub(crate) fn read_capped(
    mut stream: impl Read,
    cap: usize,
    what: &'static str,
) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    stream.by_ref().take(cap as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() > cap {
        return Err(Error::StreamTooLarge {
            stream: what,
            limit: cap as u64,
        });
    }
    Ok(buf)
}

/// Fill `buf` from `reader` until it is full or the reader is exhausted, and return how
/// many bytes arrived.
///
/// `Read::read` may return short at any point before the end, so one call is not a
/// segment; `read_exact` treats a short final segment as an error, which here it is not.
/// `Interrupted` is retried, as `read_exact` does; every other error is the caller's —
/// including the one a cancelling reader returns to stop the pass.
///
/// Here rather than in `segments`, which needs a cipher: `classify_from` reads its eight
/// bytes of magic with it, in the detection build too.
pub(crate) fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while let Some(rest) = buf.get_mut(filled..).filter(|rest| !rest.is_empty()) {
        match reader.read(rest) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    /// `read_encryption_info_in` over a container built in memory.
    fn read_encryption_info(data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut cfb = cfb::CompoundFile::open(Cursor::new(data)).expect("a test container");
        read_encryption_info_in(&mut cfb)
    }

    /// A CFB container holding one `/EncryptionInfo` stream of `len` bytes.
    ///
    /// The content is never parsed by anything these tests call — `read_encryption_info`
    /// hands back raw bytes — so zeros are enough and the only variable is the length.
    fn cfb_with_encryption_info(len: usize) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut container = cfb::CompoundFile::create(&mut cursor).unwrap();
            let mut stream = container.create_stream("/EncryptionInfo").unwrap();
            stream.write_all(&vec![0u8; len]).unwrap();
            stream.flush().unwrap();
            container.flush().unwrap();
        }
        cursor.into_inner()
    }

    /// The cap is the one bound compiled into **every** configuration, because
    /// `classify` reaches it: this is the first read the crate performs on a file from
    /// outside, before a single version byte has been looked at. Every other bound in
    /// `limits` shipped with a test and this one did not.
    ///
    /// Both halves matter. The over-cap case proves the refusal exists; the
    /// exactly-at-cap case proves the ceiling is inclusive rather than off by one, which
    /// is the whole reason `read_capped` takes `cap + 1` bytes rather than `cap`.
    #[test]
    fn an_encryption_info_stream_over_the_cap_is_refused_and_the_cap_itself_is_not() {
        let over = cfb_with_encryption_info(ENCRYPTION_INFO_READ_CAP + 1);
        // The length, not the bytes: an accepted over-cap stream is a megabyte, and
        // `Vec<u8>`'s `Debug` would bury the assertion that failed under all of it.
        let got = read_encryption_info(&over).map(|b| b.len());
        assert!(
            matches!(&got, Err(Error::BadParameters(msg))
                if msg.contains("EncryptionInfo") && msg.contains("larger than")),
            "one byte over the cap must be refused, got: {got:?}"
        );

        // The control: the same container one byte shorter is accepted whole, so the
        // refusal above is attributable to the length and not to the synthetic file.
        let at = cfb_with_encryption_info(ENCRYPTION_INFO_READ_CAP);
        let bytes = read_encryption_info(&at).expect("exactly at the cap must be accepted");
        assert_eq!(bytes.len(), ENCRYPTION_INFO_READ_CAP);
    }

    /// A stream nowhere near the cap — the size every real file has; the agile fixture
    /// is 1 441 bytes — comes back verbatim. Without this the test above would still
    /// pass on a `read_capped` that refused everything over a much smaller number.
    #[test]
    fn an_ordinary_encryption_info_stream_is_returned_whole() {
        let data = cfb_with_encryption_info(1441);
        assert_eq!(read_encryption_info(&data).unwrap().len(), 1441);
    }
}
