# Security policy

## Reporting a vulnerability

Report privately through GitHub's **[Report a vulnerability]** button on this repository's
Security tab. That opens a draft advisory visible only to you and the maintainer; it is
the whole intake process, and it is deliberately the only one, so that no address needs to
be published or kept working.

Please do not open a public issue for anything in the next section. For anything in the
section after that, a public issue is exactly right.

Expect an acknowledgement within a week. There is no bounty.

## What counts as a vulnerability here

This crate's entire job is parsing files whose bytes an attacker chose. A caller opens an
untrusted `.docx` and hands it to `classify` or `decrypt_ooxml` **before anything else has
validated it**. That makes several things vulnerabilities that would be ordinary bugs in
another crate:

- **A panic on any input.** Slice indexing, `unwrap`, `expect`, an integer cast or a
  subtraction on a file-derived number — any of them reached by a crafted file is a denial
  of service for every caller not catching unwind. There is no such thing as a
  "malformed input" panic that is merely a bug. Return an error instead.
- **`classify` returning anything but a classification.** It is the first call made on an
  unknown file. It has no `Result` and must never panic; an unreadable file is `Unknown`.
- **Unbounded work or unbounded allocation.** `spinCount` is a file-controlled iteration
  count and a declared plaintext size is a file-controlled allocation. A file that makes
  the crate hang or exhaust memory is a denial of service that no `Result` can report.
  Every such parameter is bounded in `src/limits.rs`; a reachable path around one of those
  bounds is a vulnerability.
- **Key material escaping its wrapper.** The spin hash, the block keys and the session key
  are held in `secure-gate` types so they zeroize on drop. Any path that copies one into an
  error, a log line, a panic message, a `format!`, or a container that outlives the
  wrapper defeats the property this crate exists for.
- **A non-constant-time comparison on secret-derived data.** The `dataIntegrity` check
  compares a MAC this crate computes against a value the *file* supplies, which is the
  textbook MAC-forgery oracle. A short-circuiting comparison there leaks how many leading
  bytes of a forged tag were correct.
- **Returning plaintext that failed verification.** The agile package HMAC is computed over
  ciphertext and is checked before decryption. Bytes that failed that check must not reach
  the caller under the fail-closed `IntegrityPolicy`.
- **Reporting the wrong failure.** "Wrong password" and "file tampered" are different facts
  about an untrusted file. Telling a user their password is wrong when the file was
  modified is actively misleading, and the error variants are separate for that reason.

## What is not a vulnerability

- **The weakness of the formats themselves.** RC4 CryptoAPI ([MS-OFFCRYPTO] §2.3.5),
  Office 97/2000 RC4 (§2.3.6) and XOR obfuscation (§2.3.7) are broken by any modern
  standard — XOR is not encryption at all. They are implemented behind the off-by-default
  `legacy-binary` feature so that existing files can be *read*, and nothing in this crate
  writes them. A report that RC4 is weak is a report about 1997.
- **Low `spinCount`, weak passwords, or Office's own key derivation.** This crate
  implements the specified derivations. It cannot make a four-character password strong.
- **The password being `&str` at the public boundary, and the plaintext being `Vec<u8>`.**
  Neither is zeroized on the caller's copy. This is a documented design decision, not an
  oversight: no `secure-gate` type crosses the public API, which is what lets a consumer on
  a different `secure-gate` version link this crate at all. Wrapping happens the moment the
  password is used, and everything derived from it is wrapped. If you want the caller's copy
  zeroized, that is the caller's `Zeroizing<String>` to hold.
- **Anything requiring the attacker to already control the calling process.**
- **Findings in a dependency** with an advisory already published. Those belong upstream;
  `cargo deny check advisories` runs here on every push and will surface them.

## Scope

| | |
| --- | --- |
| In scope | `src/**` in every one of the three feature configurations — the default detection build, `crypto-ops`, and `legacy-binary`. |
| In scope | The published crate on crates.io, at the latest version. |
| Out of scope | `tools/**` — fixture generators and the acceptance-gate drivers. They run on a maintainer's machine against files the maintainer chose, and are not shipped in the crate. |
| Out of scope | The test fixtures, which are deliberately hostile inputs. |

## Supported versions

Pre-1.0 and pre-release. **Only the most recently published version is supported.** A fix
ships as a new release rather than a backport; there is no version to backport to yet.

## Design notes a reporter may find useful

- The **default build links no cryptography at all** — no cipher, hash, MAC, RNG or
  key-wrapping crate. CI asserts that property on every push. A consumer who only calls
  `classify` has none of the attack surface below it.
- The crate contains **no `unsafe`**, enforced by `#![forbid(unsafe_code)]` at the crate
  root, so memory-safety findings would have to originate in a dependency.
- Every module that parses a file denies `clippy::unwrap_used`, `expect_used` and `panic`
  on itself, and CI runs clippy under `-D warnings`.

None of these are guarantees against a logic flaw, which is what the list above is about.
