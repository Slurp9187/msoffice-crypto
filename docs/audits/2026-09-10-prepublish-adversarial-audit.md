# Pre-publish adversarial audit — 2026-09-10

Audited tree: `main` at `1f00bdb`, six commits, version `0.1.0-rc.1`.
Pending irreversible actions: `cargo publish` to crates.io, and the private→public flip.

**Deltas only.** Nothing here restates the design, and a claim that is true is not listed. Where a
whole category came back clean it gets one line at the end, not a section.

Findings are ranked by severity. Every one was raised by an independent finder and then handed to a
separate agent whose instructions were to *refute* it; the verdict column reflects that pass. Where I
re-verified a finding myself at the terminal, it says so. Sixty-one findings were raised, sixty
survived refutation, one was refuted and is not reported.

> **A note on how this document is written.** Two findings below concern identifiers that leak in
> commit messages. This file is in the repository and becomes public at the flip, so it deliberately
> does **not** reproduce those strings — it cites the commit and the command that reveals them.
> Please keep it that way in any edit.

---

## Verdict

**Publish with qualifications — and hold the visibility flip until finding 1 is adjudicated.**

The crate itself is in good shape: all sixteen matrix commands exit 0, the packaged tarball is green
in every feature configuration with the corpus absent (20+10 / 156+19 / 175+30, reconciling exactly
against this repository's 30 / 175 / 205 at 0 ignored), and the corpus-detection mechanism CLAUDE.md
describes does work as documented. No finding says the cryptography is wrong in a way that produces
incorrect plaintext for a well-formed file. What the audit found instead falls into three groups:
one privacy defect in git history whose fix window closes permanently at the flip; a set of
claims in shipped documents that are stronger than the code (`SECURITY.md` most consequentially,
because it travels inside the `.crate` and cannot be corrected there); and a set of guards that are
real but untested, in a project whose own stated bar is "delete the check, watch the test fail".

The flip is the action to hold. Finding 1 is cheap to fix now and impossible to fix afterwards, and
the commits are already pushed to the private remote, so the remedy is more than a local rebase.
The crates.io publish should wait on the short list in findings 4, 8 and 15 — three edits to files
that ship — and on a decision about finding 4, which is a rename that stops being free the moment
`cargo publish` runs.

---

## 1. The commits that perform the redaction disclose what they redacted

**Severity: blocker for the flip** · confidence: high · verified at the terminal by me ·
verdict: CONFIRMED

**Where.** Commit `8f6c8f9` (message body, paragraph 2) and commit `d9db95c` (message body,
paragraph 3). Both are message-only; no blob at any revision contains either string.

**What is wrong.** `8f6c8f9`'s subject is *"…keep the downstream consumer unnamed"*, and its body
states that the consumer is not named anywhere — while quoting, verbatim, the abbreviation it had
just removed from 38 places, together with an inventory of where the name used to live (counts, file
names, and four categories of internal detail that went with it). `d9db95c` does the same for a
distinctive internal type name of the same private application, in the sentence recording that it
was scrubbed from the shipped skill. The working tree is clean in both cases; the redaction is
complete everywhere except in the messages that describe it.

CLAUDE.md's own framing is the argument against this: *"Naming a private repository from a public one
is one-way: the name can be added later, and cannot be withdrawn."* Commit messages are objects like
any other. At the flip they become world-readable, alongside the public author identity on all six
commits, which turns both strings into durable correlation handles for an application that is
supposed to be unnamed.

**How to verify.**

```bash
git log -1 --format='%B' 8f6c8f9 | sed -n '5,12p'      # the abbreviation, and the inventory
git log -1 --format='%B' d9db95c | grep -n 'own `'     # the type name
git log --all --pickaxe-all -S'<either string>' --oneline   # empty: no blob carries them
```

**Why it matters at publication.** This is the one finding whose fix window closes for good at the
flip, and it is not a plain rebase: `git reflog show --all` records `refs/remotes/origin/main@{0}:
update by push`, so all six commits already exist on GitHub. A history rewrite plus force-push leaves
the original objects on GitHub's servers, fetchable by SHA and surfaced by some API paths, which is
precisely the hazard the audit brief names. For a private six-commit repository the clean remedy is
to rewrite the two messages locally and then **replace the remote** — delete the GitHub repository
and push the rewritten history to a fresh one — rather than force-pushing over it. Doing that before
the flip costs minutes; doing it after is not possible.

**One caveat worth stating plainly:** how much this matters is the owner's call, not mine. If the
private application is not sensitive, this is a shrug. But the repository spent a whole commit and a
38-site edit establishing that it *is* sensitive, so the audit takes that at face value.

---

## 2. `build.rs` can drop out of `include` and nothing — including CI — notices

**Severity: high** · confidence: high · verdict: CONFIRMED by independent reproduction

**Where.** `Cargo.toml:24-28` and `:47-56` (the `include` allowlist and its comment);
`.github/workflows/ci.yml:333-350` (the `package` job).

**What is wrong.** Cargo.toml's comment — echoed in `build.rs`'s module doc — states that without
`build.rs` the published crate's `cargo test` "reports 30 failures". It does not. Removing the
`"build.rs",` line makes `cargo package` exit 0 with a single easily-missed warning
(`ignoring package.build entry build.rs as it is not included in the published package`) and rewrite
the normalized manifest to `build = false`. `cfg(fixture_corpus)` is then never set by anyone, so
every corpus test is ignored unconditionally and forever — producing `175 passed; 0 failed;
30 ignored`, which is **byte-identical to the correct tarball's output**. The documented failure mode
is loud; the real one is invisible, and the two states cannot be told apart from the test summary.

**How to verify.** In a throwaway worktree with its own `CARGO_TARGET_DIR`: delete `"build.rs",` from
the `include` array, `cargo package --locked --allow-dirty --features legacy-binary` (exit 0), unpack
the `.crate` and confirm its `Cargo.toml` carries `build = false`, then `cargo test --features
legacy-binary` inside it and compare against `tarball_test_legacy`'s numbers. Two agents did this
independently and got the same result.

**Why it matters at publication.** CLAUDE.md's stated audit heuristic for this mechanism — *"Read the
ignored count in both directions"* — silently assumes `build.rs` itself always ships. Nothing enforces
that assumption, and the `package` job is the only CI step that touches packaging and never runs
`cargo test` against its output. A later routine `Cargo.toml` edit disables the corpus safety net for
every downstream consumer with a fully green CI. The fix is to have the `package` job test the
unpacked tarball and assert a non-zero ignored count, which is the check CLAUDE.md already describes
in prose.

---

## 3. The `spinCount` ceiling is not pinned, and both guard tests move with it

**Severity: high** · confidence: high · verdict: CONFIRMED, with a mutation proof ·
constant and absent pin re-verified by me

**Where.** `src/limits.rs:250` (`pub(crate) const SPIN_COUNT_MAX: u32 = 1 << 21;`); use site at
`src/agile.rs:1068`; guard tests at `src/agile.rs:1614-1622`, `src/encryption_info_tests.rs:283`,
`src/malformed_input.rs:593-608`.

**What is wrong.** Every guard test is written *relative to the constant* (`limits::SPIN_COUNT_MAX`,
`SPIN_COUNT_MAX + 1`), so none of them can see the constant move. The one absolute-valued test feeds
`u32::MAX` and asserts refusal inside 5 s — true for any ceiling below `u32::MAX`. Raising
`SPIN_COUNT_MAX` to `10_000_000`, and then to `u32::MAX - 1`, leaves the whole suite green
(`205 passed; 0 failed; 0 ignored`). The mechanism is tested; the number is not.

The crate applied the opposite discipline one screen away: `limits.rs:218-222` pins `PAYLOAD_CEILING`
with `const _: () = { assert!(PAYLOAD_CEILING == 1 << 30); }` and the doc comment explains exactly why
("a ceiling that drifted down … every test in the suite would still pass"). `SPIN_COUNT_MAX` has no
such pin, and its dangerous drift direction is *upward* — the direction that buys an attacker CPU.
`limits.rs:233-239` argues at length that the spec's own 10,000,000 maximum "is not a bound this crate
can adopt as its own"; nothing in the tree enforces that argument.

**Why it matters at publication.** This is the crate's pre-authentication CPU ceiling, sold as
measured in both `CHANGELOG.md` and `SECURITY.md`, and it is a guard test that passes with and without
the thing it guards — the exact anti-pattern Design Value 4 names. Fix is one line beside the existing
pin.

---

## 4. `OoXmlCryptoError` is the wrong name by the project's own argument, and the rename stops being free at publish

**Severity: high** · confidence: high · verdict: CONFIRMED · name re-verified by me at
`src/error.rs:40`

**Where.** `src/error.rs:40`; the argument against the name is at `README.md:167-169` and repeated in
`docs/plans/msoffice-crypto-foundation-2026-09-04.md`.

**What is wrong.** README argues that "OOXML" is the wrong qualifier for a crate whose surface is
roughly half legacy binary formats, and that this is *why* the crate is not called `ooxml-crypto`. The
sole public error type for every fallible function — including `decrypt_binary_office`, which touches
no OOXML at all, and whose `NotEncrypted` variant exists *because of* the binary formats — is
`OoXmlCryptoError`. The same naming mistake the crate name was deliberately changed to avoid, left in
place one level down.

**Why it matters at publication.** It is `#[non_exhaustive]`, which protects variant additions, not the
type name. After `cargo publish`, every downstream `use msoffice_crypto::OoXmlCryptoError` is locked
in, and a rename is a breaking change in a crate whose CLAUDE.md says breaking changes are free *only*
while unpublished. This is the single most time-sensitive API decision in the audit: `0.1.0-rc.1` is a
pre-release, so renaming in `rc.2` is defensible, but the decision has to be taken deliberately now
rather than discovered later. If the name stays, say so in the development record so the next reader
does not re-litigate it.

---

## 5. "No cipher in the detection build" is a 17-name denylist, not the property three documents claim

**Severity: high** · confidence: high · verdict: CONFIRMED · regex and graphs re-verified by me

**Where.** `.github/workflows/ci.yml:206`, `:215`, `:220`; the claims at `CLAUDE.md` (Build and
verify), `SECURITY.md` (Design notes) and `README.md:227-231`; a narrower repro pattern at
`Cargo.toml:72-74`.

**What is wrong.** CLAUDE.md and SECURITY.md describe the job as asserting *the property* — "no
cipher, hash, MAC, RNG or key-wrapping crate". The mechanism is a hand-maintained list of 17 exact
crate names. `cipher v0.4.4` and `digest v0.10.7` — the RustCrypto cipher and hash trait crates — are
in this crate's own `crypto-ops` and `legacy-binary` graphs today and appear in none of the three
regexes. Neither do `sha3`, `blake2`, `blake3`, `hkdf`, `pbkdf2`, `argon2`, `ring`, `aes-gcm`,
`aes-kw`, `des`, `poly1305` or `chacha20poly1305`. Separately, `Cargo.toml:74`'s "reproduce with"
command omits `rc4|md-5`, so the documented local repro answers a different question than CI does.

The detection build is clean today, so the property *holds*; what is wrong is the claim that CI
*asserts* it. To the job's credit, its third check is a genuine vacuity guard — it fails if the
`legacy-binary` graph does not contain both `rc4` and `md-5` — and that part of CLAUDE.md's
description is accurate.

**Why it matters at publication.** SECURITY.md cites this property as the reason "a consumer who only
calls `classify` has none of the attack surface below it" — a security claim a downstream user is
meant to trust without re-deriving. A transitive dependency bump that pulled `digest` or `cipher` into
the *default* graph would pass this job green while the claim quietly stopped being true.

---

## 6. `cargo deny check advisories` never runs after publication

**Severity: high** · confidence: high · verdict: CONFIRMED

**Where.** `.github/workflows/ci.yml:3-11` (triggers) with the deny job at `:257-266`. `.github/`
contains exactly one file — there is no `schedule:` and no `dependabot.yml`.

**What is wrong.** Advisories are evaluated only when a human pushes or clicks Run workflow. The
project itself establishes the job is load-bearing: `Cargo.toml:155-156` records that
`cargo deny check advisories` "is what found this, on the day the job was added — the first thing it
did. Before that the crate would have gone to crates.io carrying a reachable DoS in its default
build", and `README.md:227` sells it as one of two "properties enforced rather than claimed".

**Why it matters at publication.** Before publication a stale advisory check costs nothing, because
the only consumer rebuilds from this tree. After publication the crate has strangers relying on that
standing assurance, and a `0.1.0-rc` has no reason for weekly pushes — the quiet period is exactly
when a new RUSTSEC against `cfb`, `quick-xml`, `thiserror` or a RustCrypto crate would land unnoticed.
Noticing an advisory is what triggers a yank, and nothing here will notice one. Fix is a three-line
`schedule:` block.

---

## 7. The flip publishes five unreported upstream defects, one of them a cryptographic weakness

**Severity: high** · confidence: high · verdict: raised by the completeness critic; upstream claim
verified against the local clone

**Where.** `docs/design/development-record.md:199-206` (section 4, "Findings *about the references*");
also `.claude/skills/msoffice-crypto-secure-gate/SKILL.md`.

**What is wrong.** The development record documents five concrete defects in named, live third-party
projects: a halved-entropy session key in herumi/msoffice (the write-up names the call site and the
constant pad, and it checks out against `O:/projects-github-clones/msoffice/include/encode.hpp:177`),
three msoffcrypto-tool defects, and one in LibreOffice. The herumi item is not a bug report — files
written by that project claim AES-256 and carry half the key entropy, which is a vulnerability
disclosure. Nothing in the repository records that any of the five was reported upstream;
`git grep -inE "reported upstream|filed upstream|upstream issue"` returns one unrelated hit in
`deny.toml`.

**Why it matters at publication.** Going public *is* the disclosure event, and it is irreversible.
This crate's own `SECURITY.md` asks reporters to come to it privately first — publishing another
project's unfixed key-entropy weakness without extending the same courtesy is inconsistent on its
face, and it is the sort of thing readers of a new crypto crate notice and quote. The four
non-security items are ordinary bug reports and need nothing. The fix is cheap: file the herumi issue
(or confirm it was filed) before the flip, or add one sentence per bullet saying when and where each
was reported.

---

## 8. `SECURITY.md` ships a universal claim about panic-denial that is false for the modern-format parsers

**Severity: medium** (raised as medium by two lenses independently) · confidence: high ·
verdict: CONFIRMED · re-verified by me

**Where.** `SECURITY.md:88` (ships inside the `.crate`); the counterexamples at `src/agile.rs:521`,
`src/standard.rs:485`, `src/standard.rs:582-584`.

**What is wrong.** SECURITY.md states, without qualification, "Every module that parses a file denies
`clippy::unwrap_used`, `expect_used` and `panic` on itself". Ten modules do: `classify.rs`,
`binary_office.rs` and the eight `legacy-binary` ones. Seven that also parse hostile input do not —
`agile.rs`, `standard.rs`, `integrity.rs`, `cfb_reader.rs`, `hash.rs`, `segments.rs`, `dataspaces.rs`.
I confirmed the split with `grep -l` over `src/*.rs`. Concretely, `standard.rs:582-584` is
`u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())`, a slice-unwrap helper taking a
caller-supplied offset, called seven times on attacker-supplied `EncryptionInfo` bytes.

Every such site is safe **today** — both the finder and the refuter traced the guards
(`info.len() >= 36` at `standard.rs:152`, `header_size >= HEADER_FIXED_LEN` at `:172`, the `len() < 8`
checks at `agile.rs:493` / `standard.rs:479`) and agreed there is no live panic. This is a
lint-coverage and honesty gap, not a vulnerability. But it is the compiler-enforced backstop the rest
of the crate relies on, and it is absent on the path that 100% of `crypto-ops` consumers use, including
the first read `classify()` makes on an untrusted file via `cfb_reader::read_encryption_info` — which
is *not* feature-gated, so it is in the default detection build too.

**Why it matters at publication.** `SECURITY.md` travels in the tarball and cannot be corrected there.
It is the document a vulnerability reporter reads, and the sentence is the crate's headline mechanical
defence against its own stated #1 risk class. Either add the header to the seven modules (each needs
the same inner `#[allow]` in its test module that `rc4.rs:154` already has), or narrow the sentence to
name the ten, the way CLAUDE.md already does.

---

## 9. `classify()` allocates the declared record length before proving the stream holds it

**Severity: medium** · confidence: high · verdict: CONFIRMED

**Where.** `src/binary_office.rs:564-570` (the `ReadAt for cfb::Stream` impl), reached from
`:702-707` → `:772-774` → `classify()`.

**What is wrong.** `vec![0u8; len]` commits the full declared length before `read_exact` can fail, so a
file that merely *claims* a large `PersistDirectoryAtom.recLen` gets that allocation regardless of the
stream's real length. `PPT_PERSIST_DIRECTORY_READ_CAP` bounds it at 8 MiB, so this is amplification
(~410×: 8.4 MB from a 20 KB crafted `.ppt`), not unboundedness. Every other stream read in the crate
uses `cfb_reader::read_capped`'s `take(cap + 1).read_to_end(…)` idiom, which grows incrementally; this
reader is the exception. It is reachable in the **default, no-cryptography build**.

**Why it matters at publication.** Three documents sell `classify` as the cheap, safe thing to run on
an untrusted upload — `README.md:125` ("Detection costs nothing"), `SECURITY.md:82-84`, and
`cfb_reader.rs:94` ("classifying a 200 MB document costs the container header and one small stream").
A triage service running `classify` over a queue gets 410× memory amplification per file with no
cryptography in the graph. The fix matches the crate's own idiom.

---

## 10. Standard decryption fabricates ciphertext padding instead of refusing a malformed body

**Severity: medium** · confidence: high · verdict: CONFIRMED, with a probe test

**Where.** `src/standard.rs:509-515`; the same shape for agile at `src/segments.rs:73-79`.

**What is wrong.** AES-CBC/ECB preserve length, so a well-formed `EncryptedPackage` body is always a
multiple of 16. When it is not — truncated, patched or hand-built — this code appends up to 15 zero
*ciphertext* bytes, decrypts the manufactured block and returns success. Without the pad,
`aes128_ecb_decrypt`'s `NoPadding` would return `CipherError`, which the existing test
`a_partial_block_is_a_cipher_error_in_both_directions` (`src/standard.rs:855`) already proves.
ECMA-376 standard encryption defines no `dataIntegrity`, so nothing downstream notices: the caller
gets a package with a garbage tail, `IntegrityOutcome::NotApplicable`, and no error. A `.docx`'s ZIP
central directory lives at the end of the file, so this is the worst place for a corrupt tail. The
agile twin is covered by the HMAC under the fail-closed default but reachable under
`IntegrityPolicy::Skip`.

`src/segments.rs:30-32` states the opposite of what the padding does — "the padding is defensive, and
it is what keeps a truncated file an error from the cipher rather than a panic in it". Only the
absence of a panic is true; the padding converts an error into a silent success.

**Fairness note the refuter added, and it is right:** `SECURITY.md` scopes the "never hand back
unverified bytes" promise to the agile package HMAC, and `src/integrity.rs:226-228` says in as many
words that standard-encryption plaintext is unauthenticated. So this contradicts a code comment and a
reasonable reading of the headline API, not a formal security promise.

**Why it matters at publication.** Fixing it later turns an `Ok` into an `Err` for inputs that
currently succeed — a semantic break. The pre-release window is exactly where that is free.

---

## 11. The AES round-key schedule is never wiped, while RC4's deliberately is

**Severity: medium** · confidence: high · verdict: QUALIFIED (real; scoped) · re-verified by me at
`Cargo.toml:170-171`

**What is wrong.** `aes = { version = "0.8", optional = true }` and `cbc = { …, features =
["block-padding"] }` — neither enables the `zeroize` feature, so `aes` 0.8.4's `Drop` body is empty and
the expanded round keys are left in freed memory. Round 0 of an AES key schedule *is* the key verbatim,
so this is not a derived residue: it is the session key (one `cbc::Decryptor::<Aes256>::new` per
4096-byte segment — roughly 2,560 abandoned schedules for a 10 MB document), the three agile block
keys, the standard AES-128 key, and the session key on both `dataIntegrity` blobs.

What makes it a finding rather than a nitpick is that `Cargo.toml:180-183` makes exactly this argument
for RC4 — "the schedule is a function of the block key, so leaving it behind would leave the key
behind" — and enables the feature there. The same reasoning was not applied one dependency over. An
agent verified the remediation builds: adding `features = ["zeroize"]` to `aes` and `cbc` compiles
with no new crates in the graph (`zeroize` is already there via secure-gate).

**Why it matters at publication.** This is the crate's published differentiator. `README.md:115-122`
and `Cargo.toml:5` tell a reader key material zeroizes on drop; the honest statement today is that the
wrapped copy zeroizes and the expanded round keys derived from it do not. The residue is stack- and
heap-resident and outside the scope `SECURITY.md:63` declares, so it does not block publication — but
it is a one-line fix that is cheaper now than as an erratum against a version that can be yanked and
never unpublished.

---

## 12. The zeroization property has no test of any kind

**Severity: medium** · confidence: high · verdict: QUALIFIED (real) · mutation proof

**Where.** The claim at `src/lib.rs:492-493` and `src/rc4.rs:13-15`; the only mechanism at
`Cargo.toml:183`.

**What is wrong.** Deleting `rc4`'s `zeroize` feature leaves all 205 tests green, plus every
integration binary and all 25 doc-tests — identical to the unmutated baseline. `grep -rn -i
'zeroiz|wiped|scrub'` over the test modules returns nothing: the property the crate exists for has no
guard. The RC4 half is the worst case because it is not type-enforced — it is a single feature string
in `Cargo.toml`, so a routine `cargo add` that drops the features array silently deletes a documented
security property with green CI. (The refuter's addition, which I agree with: `README.md:118`'s other
mechanical claim — `[REDACTED]` in `Debug` — is equally untested, and unlike zeroization it is trivial
to assert.)

**Why it matters at publication.** The published rustdoc for `decrypt_binary_office` states the RC4
schedule is wiped. Once on crates.io that sentence is what a downstream auditor checks, and there is
no evidence behind it and no guard against its silent loss on the next dependency bump.

---

## 13. Three "measured" numbers in the evidence documents are wrong

**Severity: medium** · confidence: high · verdict: CONFIRMED

- `CHANGELOG.md:125` — the integration-test row reads `| integration | — | 9 | 12 |`. The real
  `legacy-binary` count is **19** (2 + 2 + 1 + 7 + 7 across the five integration binaries; the
  captured `test_legacy` log shows each). 12 is the sum omitting `real_office_fixtures.rs`. The
  `crypto-ops` column (9) is correct.
- `README.md:150` calls the acceptance-gate block in `CHANGELOG.md` "verbatim". It is not:
  `tools/acceptance_gate.py:94-96` prints exactly one line per reader via
  `f"{self.reader:<14} {state:<8} {self.detail}"`, with `' | '`-joined details carrying literal
  `RIGHT PASSWORD :` / `WRONG PASSWORD :` prefixes and, for msoffcrypto-tool,
  `(verify_integrity=True)`. `CHANGELOG.md:54-63` shows two lines per reader, no prefixes, no
  separators, no annotation — paraphrased prose laid out to look like console output. The column
  widths do match the format string, so the header was plausibly copied and the details rewritten.
- `docs/design/development-record.md:349` says CI has "ten jobs"; `ci.yml` defines eleven.

**Why it matters at publication.** `CHANGELOG.md:40` introduces the table with "Every figure below was
measured, not asserted", and `README.md` stakes the crate's pitch on claims being checkable rather
than assertable. These are checkable, and two of the three fail — discoverable by exactly the skeptical
reader the crate says it wants. The "verbatim" one is the sharpest, because a reader who opens
`acceptance_gate.py` (as CLAUDE.md invites reviewers to do) can see the discrepancy and reasonably
wonder what else was tidied after the fact.

---

## 14. The release runbook publishes before the repository exists publicly, and its truth-edit grep misses the one file that freezes

**Severity: medium** · confidence: high (both) · verdict: CONFIRMED (both)

**14a — ordering.** `docs/RELEASING.md` runs `cargo publish` at step 6, truth edits at step 7, and the
public flip plus `private-vulnerability-reporting` at step 8. `SECURITY.md:5-8` — which ships inside
the `.crate` — names GitHub's Report-a-vulnerability button as "the whole intake process … deliberately
the only one", with no fallback address by design. Between steps 6 and 8 the crate is live and
installable while the repository is still private, so the only documented reporting channel does not
exist and public issues are explicitly discouraged. The runbook already knows private vulnerability
reporting requires a public repo (it says so twice) without noticing that publish precedes the flip.

**14b — the truth-edit grep.** Step 7's own grep
(`git grep -n -iE 'unpublished|never been published|repo is (currently )?private|not published'`)
returns CLAUDE.md, README.md, the plan and three self-references. It misses `SECURITY.md:79` — "there
is no version to backport to yet" — and `CHANGELOG.md:1`'s status banner, and
`development-record.md:242`. `SECURITY.md` is the sharp one: it is in the `include` allowlist, so that
sentence is baked into the immutable `.crate` at the exact moment it stops being true, in the document
that tells a security reporter what is supported. Widening the grep costs one alternation; adding a
`SECURITY.md` row to the step-7 table costs one line.

---

## 15. `README.md` ships in the tarball and links twice to `CHANGELOG.md`, which does not

**Severity: medium** · confidence: high · verdict: CONFIRMED · re-verified by me

**Where.** `README.md:150` and `:232`; `CHANGELOG.md` appears nowhere in `Cargo.toml`'s `include`
allowlist or in `cargo package --list`. `README.md:16` likewise links to `docs/plans/…`, also not
shipped.

**What is wrong.** Both links are load-bearing: they are the citations backing "checkable in one
command each rather than taken on trust" and the security-posture claim. crates.io's *website* rewrites
relative README links against the `repository` field, so the hosted page will resolve them once the
repo is public — but `cargo vendor`, distro packagers, offline readers and SBOM tooling read the
tarball's own files, and for them the links resolve to nothing. That is precisely the audience
`build.rs`'s module doc says the packaging story was written to reassure.

**Fix.** Either add `CHANGELOG.md` to `include` (it is small, and it is the evidence document) or make
the two links absolute. The first is better: the claim is that the evidence travels with the artifact.

---

## 16. Nine more mediums, stated once each

| # | Finding | Where |
|---|---|---|
| 16a | GitHub's licensee resolves this repo to **Apache-2.0 alone** (confirmed live: `gh api … .license.spdx_id` → `Apache-2.0`), so the public sidebar, the API and every SBOM/policy scanner reading it will contradict `MIT OR Apache-2.0` — which crates.io will show correctly. Two public faces disagreeing on the licence, on a project whose CLAUDE.md calls licence discipline load-bearing. Fix: a root `LICENSE`/`COPYING` stating the dual grant. | repo metadata; `LICENSE-MIT`, `LICENSE-APACHE` |
| 16b | `secure-gate` — the dependency the "why this crate exists" pitch rests on — is the **same GitHub owner's** crate, pinned at a release candidate whose final has never shipped, and README presents it through a bare crates.io link inside a paragraph comparing four *independent* projects unfavourably. README discloses the `odf-crypto` sibling relationship explicitly; this one it does not. Undisclosed self-dealing in a comparison is what gets quoted rather than asked about. One clause fixes it, and the honest version is stronger. | `README.md:114-120`, `:242-245`; `Cargo.toml:252` |
| 16c | The documented reason for not zeroizing the spin-hash rounds is **cryptographically wrong**: it argues an abandoned `H_i` is an inversion away from `H_final`, but the recurrence uses a *public* counter, so continuation is forward — one SHA-512 call from the last-dropped buffer. The conclusion ("don't wrap 100 000 rounds") is still fine; the supporting sentence is not, and the skill's own suggested fix (one reused buffer) is what `standard.rs:434-447` already does. | `src/agile.rs:604-606`; skill `:158-165` |
| 16d | `CHANGELOG.md:25` already carries the `## v0.1.0-rc.1 — Unreleased` heading, added in the repo's **first** commit — while `CLAUDE.md:258-259` says "no version headings until release" and `RELEASING.md:209` lists adding it as a post-publish truth edit. Nothing instructs replacing "Unreleased" with the publish date the changelog's own intro promises. | `CHANGELOG.md:25` |
| 16e | The CI guard that exists to stop the shared-artifact-directory bug recurring loops over `README.md CLAUDE.md` only — omitting `docs/RELEASING.md`, which documents the same command and is the file actually executed by hand at release time. | `ci.yml:178-190` |
| 16f | `agile_encrypted.docx` (one of the two fixtures that **ship**) and `standard_encrypted.docx` have no generator in `tools/` and no recorded provenance, against CLAUDE.md's "generate fixtures, don't copy them" rule. The licence question is clean — an agent SHA-256'd the corpus against the clones and found no match — but a third party can regenerate 5 of 19 and must take the rest on faith. Two lines in NOTICE closes it. | `tests/fixtures/`; rule at `CLAUDE.md:194` |
| 16g | The panic-denial gap of finding 8, stated as an API guarantee: `classify()`'s doc promises it never panics, and the compiler-enforced backstop does not extend to `cfb_reader.rs`, which performs the first read `classify()` makes. `Cargo.toml:324-331` confirms there is no crate-wide lint backstop. | `src/cfb_reader.rs:1` |
| 16h | `pad_zero` copies the `dataIntegrity` HMAC key out of its wrapper into a bare `Vec<u8>` that drops unzeroized, on the encrypt path — `sensitive.rs` describes that key as "equivalent to being able to forge". Inside a minimal `with_secret`, so the boundary rule is met; the copy is not. | `src/integrity.rs:484-495` |
| 16i | `nineteen` fixtures, `two` shipped and `thirty` corpus tests all check out — but `CLAUDE.md`'s Layout block names two of five `tests/*.rs` files and silently omits three, including `fixture_identity.rs`, the guard that keeps author metadata out of the corpus. `audit_claims.py` check D only enforces `src/`. | `CLAUDE.md:228-230` |

---

## 17. Low severity — one line each

Reported because the brief asked for deltas regardless of how intentional they look.

- **`plain.docx`, one of the two shipped fixtures, is Microsoft Word output** (python-docx's bundled
  `default.docx`; its `app.xml` says `Microsoft Macintosh Word 14`), while `Cargo.toml:36-38` justifies
  shipping it as "python-docx output rather than Office's, so … carry no document metadata". The
  metadata conclusion is right; the reasoning is not.
- **`excelize` (BSD-3) is missing from CLAUDE.md's provenance table** though it is cited in
  `src/standard_encrypt.rs:34`, NOTICE, README and `deny.toml` — a sixth upstream absent from "the most
  consequential table in this file".
- **Four MPL-2.0 LibreOffice paths outside the sanctioned `oox/source/crypto/` scope** are cited in the
  source (`ww8par.cxx`, `xicontent.cxx`, `mscodec.hxx/cxx`), and a refuter found six more. All are
  behaviour-only citations, which is the permitted use — but the table's scope and the clone list do
  not cover them.
- **`agile.rs:1341-1343` self-reports quoting two sentences from LibreOffice comments.** Benign on
  inspection — those comments are themselves verbatim [MS-OFFCRYPTO] §2.3.4.10 text — but a crate whose
  rule is "never copy MPL expression" should not carry a public comment saying it did.
- **NOTICE's per-file derivation map omits three modules** whose own headers declare them as ports
  (`rc4.rs`, `rc4_office97.rs`, `binary_office.rs`), and **NOTICE is outside every `audit_claims.py`
  check** — the one attribution artifact nothing audits.
- **`python-docx` is credited nowhere**, though both shipped fixtures are its output.
- **`deny.toml:34`'s documented dev-advisory command does not parse** (`--exclude-dev` is a boolean),
  and `exclude-dev = true` silently removes dev-dependencies from the licence, bans and sources checks
  too, though it is justified on advisory grounds alone.
- **`LICENSE-APACHE:190` keeps the literal brackets** the appendix tells you to remove. Year and holder
  are real, so this is not the classic unfilled-placeholder miss.
- **`Cargo.toml:35` cites `src/classify.rs:340, :362` as the `include_bytes!` sites**; there are sixteen
  such sites and neither of those lines is one.
- **`docs/RELEASING.md:208` instructs editing `docs/handoffs/2026-09-05-cold-start.md`**, a path that has
  never existed in this repository — a second reference survives at `tools/audit_claims.py:29`.
- **83 `GH #N` citations resolve nowhere for a public reader.** Documented and deliberate
  (`src/lib.rs:117-129`), with a real index at `development-record.md:36-61`; reported because a
  reader's first instinct is to click.
- **The maintainer's `O:/` clone-drive layout is published in three files.** Adjudicated in `5de2ae7`;
  reported for completeness.
- **`tools/gen_plain_binary_fixtures.ps1:37-40` says the fixtures carry the operator's Office user name**
  — the committed corpus was scrubbed, so the header describes a state the tree contradicts, while the
  generator would still stamp it on a re-run.
- **`tests/fixture_identity.rs` documents four leak vectors and parses two** (`Author`/`LastAuthor`),
  not the BIFF `WriteAccess` or `SttbSavedBy` rows in its own table.
- **`#![forbid(unsafe_code)]` binds `src/` only**; `tests/legacy_allocation.rs` installs a
  `#[global_allocator]` with four `unsafe fn`s, so `grep -rn unsafe .` on a fresh clone contradicts the
  "no unsafe" claim in README, SECURITY.md and CHANGELOG.
- **Two stale `Cargo.toml` comments ship inside `Cargo.toml.orig`**: "0.42 over the 0.38" (the
  dependency is `quick-xml = "0.41"`) and secure-gate's "`rand` is NOT enabled yet".
- **`.gitattributes` claims to name every fixture extension and omits `.txt`**, so `plain_content.txt`
  falls through to `* text=auto eol=lf`. Harmless today; the file is an expected-output fixture.
- **`RELEASING.md` never tags the released commit** and no tags exist.
- **Nothing records that the crates.io name `msoffice-crypto` was confirmed free** — worth one check
  before step 6, since name squatting is permanent.
- **The `CryptoOffice` clone marked DO NOT OPEN is physically present** in the clone root that
  `audit_claims.py` walks recursively.
- **Residual bare copies of key material**, each real and each small: the UTF-16LE password is
  materialised into a bare `Vec<u8>` in all five KDF entry points (against `SECURITY.md:58-61`'s
  "everything derived from it is wrapped"); `derive_block_key` abandons an unzeroized digest beside the
  wrapper; Office-97 RC4 holds the password, `MD5(password)` and a 336-byte derivation buffer bare;
  `PAYLOAD_CEILING`'s "~2 GiB of peak" reasoning under-counts the legacy path, which holds four copies.
- **README overclaims that `==` on secrets is impossible "even by accident"** — true at wrapper level
  (`Dynamic` has no `PartialEq`), but the crate's mandated idiom hands out `&[u8]` inside nested
  `with_secret` closures, where `==` compiles; the crate's own tests do it.
- **`CHANGELOG.md:50-52`'s release-artifact SHA-256 is unreproducible** by anyone including this
  machine, because `encrypt_ooxml` draws salt/IV/session key from the OS CSPRNG. Correct as a record of
  one run; it just cannot be re-derived, and the surrounding prose does not say so.
- **README's comparison says `ms-offcrypto-writer` uses bare `Vec<u8>`**; it uses bare fixed-size
  arrays. The point stands, the type does not.

---

## What was covered and came back clean

One line each, as requested.

- **Secrets in git history other than finding 1** — no credentials, tokens, keys, internal hostnames or
  private URLs in any blob at any revision; `MS-OFFCRYPTO.pdf` is untracked in every commit; no
  `.claude/` session state, `settings.local.json` or scratch file was ever committed.
- **Fixture identity** — the OLE property sets of all seven CFB fixtures and the `docProps` of both
  shipped OOXML fixtures carry no personal name; the corpus was scrubbed and the guard test holds.
- **Commit trailers** — all six commits carry only `Co-Authored-By`; no session URLs.
- **Tarball behaviour** — green in all four configurations with the corpus absent, ignored counts
  reconciling exactly against this repository; both shipped fixtures arrive (the doc-tests would be a
  compile error otherwise).
- **Licence of the dependency graph** — `cargo deny check licenses advisories bans sources` exits 0;
  no Apache-2.0-only, MPL, GPL or unclear licence in the graph; no blanket allow and no ignored RUSTSEC.
- **No copied MPL expression** — spot-checks of the agile and standard KDFs, the verifier and the
  constant tables against the LibreOffice clone found citations of behaviour, not transliteration.
- **`unsafe`** — none in `src/`, enforced by `#![forbid(unsafe_code)]` (see the `tests/` caveat above).
- **`build.rs` supply-chain behaviour** — reads only inside the crate root, shells out to nothing, no
  network, no environment-dependent behaviour.
- **The dependency-graph vacuity guard** — CI really does fail if the `legacy-binary` graph lacks `rc4`
  and `md-5`, so the first two property checks are not vacuous.
- **CI as a public artifact** — no `pull_request_target`, no untrusted interpolation into a `run:`
  block, no third-party actions, no secret a fork could exfiltrate.
- **HMAC-before-plaintext on the agile path** — traced through `lib.rs` and `integrity.rs`; no policy
  setting, error branch or early return yields plaintext without verification under the fail-closed
  default.
- **secure-gate does not cross the public API** — no type, no re-export, no pub-in-private leak, so the
  consumer pinning a different version still resolves.
- **Feature additivity** — enabling `legacy-binary` only adds; no item changes signature by feature.
- **Fixture bytes on checkout** — every binary fixture extension carries a `binary` attribute (see the
  `.txt` note above).

## Method, and what this audit could not check

Nine independent finder lenses (packaging, git history, licence/provenance, cryptographic correctness,
hostile input, prose claims, API surface, CI/release, key material), each followed by a separate
refuter instructed to kill its findings, then a completeness critic looking for uncovered categories.
Four lenses ran in throwaway git worktrees with private target directories and used them for mutation
proofs — deleting a guard and observing whether anything failed — which is where findings 2, 3 and 12
come from. All `cargo` invocations were serialised or isolated per the working-directory rule in
CLAUDE.md; nothing in this repository was modified.

Not checked: the four-reader acceptance gate was not re-run (it needs Word, LibreOffice and this
machine, and the audit was read-only); `cargo publish --dry-run` was not run; crates.io name
availability was not queried; and no fuzzing was performed, so the panic-surface finding rests on
reading and targeted probes rather than coverage.
