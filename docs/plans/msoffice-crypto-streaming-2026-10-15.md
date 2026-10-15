Status: Planned (approved 2026-10-15)

# Plan: streaming OOXML encrypt and decrypt (`Read + Seek` in, `Write` out)

Opened 2026-10-15 by the MSOC STREAMING session for the EFV streaming arc (EFV master issue
Slurp9187/encrypted-file-vault#1193). The owner approved it on 2026-10-15.

## Context

rc.6 works on whole buffers only. Every entry point takes `&[u8]` and returns `Vec<u8>`, so a
consumer must hold the whole file, and a 1 GiB ceiling (`PAYLOAD_CEILING`) bounds the size.
`src/limits.rs` already says the fix for a real document refused by that ceiling is
"`Read + Write + Seek` over `crate::segments`", not a bigger number. This arc builds that fix.

The new API is **additive** and lands in an rc after rc.6. The `Vec` entry points stay, but become
`Cursor` wrappers over the streaming core, so there is one code path. The consumer's rc.6 pin is
not affected.

## Verdicts

| Operation | Verdict | Why |
|---|---|---|
| Agile encrypt | **Feasible** | Segments are 4096 bytes, and each IV depends only on the salt and the segment index (`segments.rs`). HMAC can be computed incrementally. `\EncryptionInfo` has a fixed length once the parameters are chosen, so a placeholder is written first and patched in place, which keeps today's stream order and layout. |
| Agile decrypt + verify | **Feasible, two passes** | Pass 1 computes the HMAC over `\EncryptedPackage`. Pass 2 decrypts and **recomputes** the HMAC; an input that changed between passes gives `IntegrityCheckFailed`. `IntegrityPolicy::Skip` is the only one-pass path, and it already carries that name. No new unverified path. |
| Standard encrypt / decrypt | **Feasible** | AES-ECB works per 16-byte block. The format defines no MAC, so decrypt is one pass by design. `Require` refuses before a byte is written. |
| Binary Strip (97–2003) | **Feasible; out of this arc** | RC4 is rekeyed per block (Word 512 bytes, Excel 1024). The Word and Excel walks are forward-only, and PowerPoint seeks only within its input. The design: copy R to W byte for byte, open W as a CFB and overwrite each stream in place, chunk by chunk. These files are rarely large, so the work is not filed. Revisit only if a consumer meets a real refusal. |

### The `cfb` crate

Read in `cfb` 0.14.0, the version pinned at rc.6:

- `Stream` reads lazily through `Seek`, with a 1 MiB buffer.
- The whole FAT stays in memory as a `Vec<u32>`, which is 1/128 of the payload under V3
  (512-byte sectors, the version Office writes and `build_container` uses). Each chain's sector
  list adds another 1/128.
- Time is quadratic in 0.14, because every buffer refill re-walks the whole chain.
  **cfb 0.15.0 fixes this** (upstream #89 reuses the chain's sector list, and #87 sends large
  reads and writes past the buffer).
- The writer needs `Read + Write + Seek`.
- [MS-CFB] §2.6.1 caps a V3 stream at 0x80000000 bytes.

## Decisions (owner, 2026-10-15)

- **Memory: no `cfb` fork.** Use released cfb 0.15. The memory test asserts an explicit bound:
  peak growth ≤ payload/64 plus a fixed working set, about 32 MiB at the V3 2 GiB cap. It does not
  assert flat memory. Paging the FAT upstream is optional and outside this arc. The reasons: the
  format's own cap already bounds the memory, and a third fork (beside lopdf and sevenz-rust2)
  would cost rebases, a patch line in the consumer and another security review.
- **No V4.** Encrypt stays on V3 and refuses packages past the V3 stream maximum, with a specific
  error, before writing anything.
- **Binary Strip is out of this arc** (see the verdict above).
- **One shape for both crates, agreed with odf-crypto's streaming arc:**
  - `(reader, writer, password, …)`, with extra arguments last;
  - encrypt returns `Result<(), Error>`;
  - decrypt returns `Result<DecryptOutcome, Error>`, where `DecryptOutcome { integrity: IntegrityOutcome }`
    is `#[non_exhaustive]`;
  - `IntegrityPolicy` stays. Its difference from odf-crypto comes from the formats: agile's
    `dataIntegrity` is `minOccurs="0"`, and Standard defines no tag.
- **Bounds:** decrypt `R: Read + Seek`, `W: Write`; encrypt `R: Read + Seek`,
  `W: Read + Write + Seek` (the `cfb` writer needs `Read`).
- **Three conventions, the same in both crates:**
  - The docs say "On any `Err` the caller discards W" in those words.
  - Verified decrypt is two passes, with the tag recomputed on the second.
  - A cancelling reader's `io::Error` comes back as `Error::Io`. The KDF itself cannot be interrupted.

## Slices

| # | Work | Done when |
|---|---|---|
| S1 | Bump `cfb` to 0.15. Re-run the five-configuration matrix, `cargo deny` and MSRV 1.85, and check the goldens, which pin byte-identical container output. | The matrix is green and the goldens are unchanged. If they changed, the change is explained and recorded in the CHANGELOG. The four-reader gate PASSes on an encrypt artifact built against 0.15. |
| S2 | Make the internals reader-driven: (a) `Segments` gains a per-index IV helper and a reader-driven iterator; (b) `HashAlgorithm` gains an incremental HMAC; (c) the core of `integrity::verify`/`generate` takes chunks; (d) a `PlaintextChunk` alias in `sensitive.rs`, a secure-gate wrapper wiped on drop, following the `msoffice-crypto-secure-gate` skill. | Unit tests show chunked and one-shot results are equal for the IV, the HMAC and the segments, at chunk sizes 1, 15, 4096 and 4097. |
| S3 | `encrypt_ooxml_to` and `encrypt_ooxml_with_params_to`. `build_container` becomes generic over `W`: it writes a placeholder `\EncryptionInfo`, streams `\EncryptedPackage` (size prefix from R's length, then a count check), and patches `\EncryptionInfo` once the HMAC is final. `encrypt_ooxml` and `encrypt_ooxml_with_params` become `Cursor` wrappers. | The goldens are byte-identical through both entry points. The four-reader gate PASSes, and so do `--tamper --expect-fail` and `--corrupt-integrity --expect-fail`. A test shows a reader failing mid-stream gives `Error::Io`. |
| S4 | `decrypt_ooxml_to(r, w, password, policy) -> Result<DecryptOutcome, Error>`. Detection (`is_cfb_office`, `rights_management_in`) runs on `CompoundFile<R>`. Two passes plus the recompute check. `decrypt_ooxml` and `decrypt_ooxml_with_policy` become wrappers. | The corpus tests pass through both paths. A tamper in the ciphertext body gives `IntegrityCheckFailed`, and a counting W proves 0 bytes were written. A negative control: `Skip` on the same file succeeds. An input changed between passes gives `IntegrityCheckFailed`. Each guard is deleted once and seen to fail. |
| S5 | Standard: `encrypt_ooxml_standard_to`, `encrypt_ooxml_standard_with_key_bits_to(r, w, password, key_bits)`, and the Standard branch of `decrypt_ooxml_to`. The `Vec` forms become wrappers. | The goldens are identical. The four-reader gate PASSes, with LibreOffice tested at AES-128 only, which is all it reads for 2007 files. |
| S6 | `classify_from(R: Read + Seek)` and `is_cfb_office_from`. They read headers only and **never panic**. | The classify corpus gives the same result through the slice form and the reader form. The hostile-input tests are re-run through the reader form. |
| S7 | Limits. The `_to` paths drop `PAYLOAD_CEILING` (the `Vec` wrappers keep it, because they allocate). Add `CFB_V3_STREAM_MAX = 0x8000_0000`, citing [MS-CFB] §2.6.1. It is checked on R's length, taken by seeking, before any byte reaches W, and refused with a new variant, `Error::PackageTooLarge { len: u64, limit: u64 }`. The maximum plaintext is 2 GiB − 16 bytes (stream = 8-byte prefix + ciphertext padded to 16), and it applies to agile and Standard alike. The `Vec` paths' 1 GiB `PAYLOAD_CEILING` refusals, on encrypt and on decrypt, move from `BadParameters` to `PackageTooLarge` too, because `BadParameters` is documented as *a parameter the file declares*, which an input size is not. That moves an existing refusal to another variant, so the CHANGELOG states it plainly as a breaking change. spinCount, the declared-size ≤ stream-length check and the `u32::MAX` segment guard are unchanged. | Each bound has a test proven to fail without it, and asserts `PackageTooLarge` (never `is_err()`). `limits.rs` carries each bound's provenance label. |
| S8 | Memory-bound test: `tests/streaming_memory.rs`, its own test binary with a counting global allocator. It runs agile encrypt, agile decrypt+verify and Standard, at 64 MiB and at 256 MiB from a pattern reader, and asserts peak growth ≤ payload/64 plus a fixed working set. | Green. Falsified by routing through a `Vec` wrapper, which must fail, and the failure is recorded in the PR. Corpus-independent, so it runs in CI and in the tarball. |
| S9 | Docs and the CHANGELOG `[0.1.0-rc.7] - Unreleased` entry: the new API, the wrappers that are now `Cursor`-based, "discard W on Err", the `cfb` bump, the memory bound, and, stated as a breaking change, oversize refusals moving from `BadParameters` to `PackageTooLarge` (owner approved 2026-10-15). The README spine skill applies. | CI's `prose` job is green, including `tools/audit_claims.py`. |

Order: S1 → S2 → S3, S4 and S6 in parallel → S5 → S7 → S8 → S9. Cutting the rc is the owner's call.

## Out of scope

- Binary Strip streaming (see the verdict above).
- V4 containers and packages past 2 GiB.
- FAT paging in `cfb`.
- Any change to the `Vec` entry points' signatures.

## Verification

- The five-configuration matrix in CLAUDE.md, run one cargo at a time in the worktree, with
  `-j 2` and two test threads.
- The four-reader acceptance gate, run on a private `MSOFFICE_CRYPTO_ARTIFACT_DIR`, plus both
  `--expect-fail` mutation runs and a `tasklist` check afterwards.
- The S8 memory test and its falsification.
- `gh pr view --json closingIssuesReferences` before every merge.

## Corrections made during the build

Recorded here rather than rewritten into the sections above, so the plan the owner
approved stays readable as approved.

- **The cap's citation is [MS-CFB] §2.6.1** (Compound File Directory Entry, the Stream
  Size field), not §2.6.3 as first written. Checked against the specification's own table
  of contents; corrected above, in #34 and in the code.
- **The memory slope is larger than decision 1 assumed.** Measured in a release build:
  33 MiB on encrypt and 46 MiB on decrypt at 1 GiB, about 1/32 and 1/22, so about 66 and
  92 MiB at the 2 GiB cap rather than ~32 MiB. `cfb`'s `Vec`s grow by doubling, and
  opening a container reads its sector table through a temporary buffer as well. Reported
  to EFV STREAMING for the owner with a recommendation to accept. S8 asserts
  `FIXED + payload/16` rather than `payload/64`, and runs at 32 and 128 MiB rather than 64
  and 256: in a debug build those sizes take about 50 seconds, and the larger one still
  fails a buffering implementation by two orders of magnitude.
- **S2's names.** The plaintext buffer is `PlaintextSegment` (`Fixed<[u8; 4096]>`), not
  `PlaintextChunk`. `Segments`, the iterator over a slice, became `Segmenter`, which reads;
  the iterator had no caller left.

