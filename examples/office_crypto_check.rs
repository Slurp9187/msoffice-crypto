//! The `office-crypto` leg of the four-reader acceptance gate (GH #8).
//!
//! `office-crypto` is an independent MIT implementation of [MS-OFFCRYPTO] and a
//! dev-dependency of this crate. The unit test
//! `an_independent_implementation_reads_what_encrypt_ooxml_wrote` already runs it on an
//! in-memory container every `cargo test`; this example exists so that
//! `tools/acceptance_gate.py` can run it on a *file* — the same artifact the other three
//! readers are handed — and byte-compare the result itself, rather than trusting that the
//! suite ran. A gate that assumes a leg passed is not a gate.
//!
//! It does nothing but decrypt and write. The comparison lives in the harness, so all
//! four readers are judged by one piece of code. Nothing here touches this crate's own
//! API, on purpose: a leg that called `msoffice_crypto::decrypt_ooxml` would be this crate
//! agreeing with itself.
//!
//! Usage:
//!
//! ```text
//! MSOFFICE_CRYPTO_PASSWORD=testpass \
//!   cargo run --example office_crypto_check -- <encrypted artifact> <plaintext out>
//! ```
//!
//! The password travels in the environment, not `argv`, so it is not visible in a process
//! listing for the life of the run (the sibling crate's `validate_encrypt.py` does the
//! same). Exit status: 0 decrypted and written; 3 `office-crypto` refused the file — its
//! error is printed on stderr, verbatim, and is what the harness records; 2 usage or I/O.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, artifact, out] = args.as_slice() else {
        eprintln!("usage: office_crypto_check <encrypted artifact> <plaintext out>");
        return ExitCode::from(2);
    };
    let Ok(password) = std::env::var("MSOFFICE_CRYPTO_PASSWORD") else {
        eprintln!("MSOFFICE_CRYPTO_PASSWORD is not set");
        return ExitCode::from(2);
    };
    let data = match std::fs::read(artifact) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot read {artifact}: {e}");
            return ExitCode::from(2);
        }
    };
    match office_crypto::decrypt_from_bytes(data, &password) {
        Ok(plain) => {
            if let Err(e) = std::fs::write(out, &plain) {
                eprintln!("cannot write {out}: {e}");
                return ExitCode::from(2);
            }
            println!("office-crypto: decrypted {} bytes to {out}", plain.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("office-crypto: REFUSED: {e} ({e:?})");
            ExitCode::from(3)
        }
    }
}
