Status: Planned

# `msoffice-crypto` CLI

A command-line front end over the published library, so the people who actually hit
encrypted Office files — forensics, DLP triage, archival ingest, mail-gateway
sandboxing, anyone holding a locked `.docx` with no Rust toolchain in the loop — can
use it without writing a program. `msoffcrypto-tool` ships one and is the reason most
people have ever decrypted an Office file from a shell; this crate does not, and that
is the single largest gap between the two for a non-Rust user.

Sibling arc: [`odf-crypto`](https://github.com/Slurp9187/odf-crypto) shipped exactly
this, plan `docs/plans/odf-crypto-cli-2026-09-04.md`, parent issue #31, landed as
`src/bin/odf-crypto.rs` with `tests/cli.rs` beside it. **That plan is the base text of
this one.** Where this plan repeats it, the repetition is deliberate — the two crates
are shaped alike on purpose. Where it diverges, § 10 says so in one place, so a
reviewer can check each divergence was forced by this crate rather than invented.

---

## 1. Shape

One binary, `msoffice-crypto`, three subcommands:

```
msoffice-crypto classify <FILE> [--json]                     # what is it, is it encrypted, how
msoffice-crypto decrypt  <IN> [-o OUT] [--integrity POLICY]  # -> the plain OOXML zip, or the plain .doc/.xls/.ppt
msoffice-crypto encrypt  <IN> [-o OUT] [--format FORMAT]     # -> the CFB container Office writes
```

`classify` needs no password and no cipher. `decrypt` and `encrypt` need
`crypto-ops`; `decrypt` of a `.doc`, `.xls` or `.ppt` additionally needs
`legacy-binary`, and says so rather than pretending the file is unreadable.

### 1.1 A `cli` feature, default off

A library consumer must not pay for an argument parser or a terminal crate to ask
whether a file is encrypted — that is the same argument the `default = []` detection
build already makes, applied one level out:

```toml
autobins = false          # see below; this one is load-bearing

[features]
cli = ["crypto-ops", "dep:clap", "dep:rpassword", "dep:serde_json"]

[[bin]]
name = "msoffice-crypto"
path = "src/bin/msoffice-crypto.rs"
required-features = ["cli"]
```

**`required-features` arrives with this arc.** The sibling's plan says it is "the same
mechanism `examples/` already uses"; that sentence does not transfer. This repository's
one example, `examples/office_crypto_check.rs`, deliberately touches none of this
crate's API — it is the `office-crypto` leg of the acceptance gate, and calling
`decrypt_ooxml` would be this crate agreeing with itself — so it compiles in every
feature configuration and needs no gate. The binary is the first target here that
cannot. Without `required-features`, `cargo test --locked --no-default-features` tries
to build a binary calling `decrypt_ooxml`, which does not exist in that configuration,
and the detection-only job fails on a binary nobody asked it to build.

**`autobins = false` is not optional either.** Every `src/bin/*.rs` is otherwise
auto-discovered as its own binary, which turns the CLI's `#[path]` test module into a
second bin target with no `main`. Declare the one binary explicitly.

`cargo install msoffice-crypto --features cli` is the install line, and
`--features cli,legacy-binary` is the one for someone who opens 97-2003 files. Neither
is default: `cargo install` on a library is not the common path, and making `cli`
default would put an argument parser in front of every library consumer.

### 1.2 What the three dependencies cost, and the licence finding

**`clap` 4, builder API, `default-features = false`,** features `std`, `help`, `usage`,
`error-context`, `suggestions`. No `derive`, no `wrap_help`. The sibling measured
`derive` at 21 crates, builder-plus-`suggestions` at 5, and `wrap_help` at 8 more (it
pulls `terminal_size` and `windows-sys`); its hand-rolled parser had shipped two real
defects first — `--output=x.odt`, the GNU `--flag=value` form, rejected outright, and a
near-miss like `--password-en` answered with "unrecognised option" and no suggestion.
Do not re-litigate that; **do re-measure it here**, because it is a claim about this
graph, and S1's close condition is the measurement.

**`serde_json` for `--json`.** 5 crates, and no `serde` derive (11 more) — the object
is built directly rather than derived from a struct. The sibling's hand-written escaper
was correct and tested and was replaced anyway, for a structural reason worth
repeating: with escaping done by hand, a field added later without remembering to
escape it silently emits broken JSON. `classify` gains fields as this crate learns
formats, so that is not hypothetical here.

**`rpassword` for the non-echoing prompt — and it is `Apache-2.0` only.** So is its
`rtoolbox`. That matters more in this repository than in the sibling's, because
`deny.toml`'s licences section is written about precisely this case: a dependency
licensed Apache-2.0-only does not relicense this crate, but it means the consumer who
took the MIT half still has to satisfy Apache-2.0 for that dependency, so the offer
stops being the clean either/or it reads as.

Measured 2026-09-11: the normal graph at `--all-features` contains **no
Apache-2.0-only crate today** — the one such crate in `Cargo.lock`, `zopfli`, is
dev-only, reaching the lockfile through the `office-crypto` oracle and appearing in no
`cargo tree -e normal` output. `rpassword` would be the first.

**Resolution: take it, and write it down.** It arrives only under `cli`, which is
opt-in and which no library consumer enables; `deny.toml` already allows `Apache-2.0`,
so `cargo deny` stays green with no `exceptions` entry. What changes is prose, and that
is S6's work: the README feature table and `deny.toml`'s licences comment each gain a
line saying the CLI's password prompt is Apache-2.0-only, so a consumer who took the
MIT half learns it here rather than in their own legal review. If that is judged
unacceptable, `console` (MIT) is the swap and the prompt is fifteen lines either way —
but do not hand-roll console-mode toggling to dodge a licence question a sentence
answers.

---

## 2. Passwords never come from `argv`

`argv` is world-readable in a process listing for the lifetime of the run — `ps aux` on
Linux, the command-line column in Task Manager on Windows. There is deliberately **no
`--password VALUE` flag**, and adding one later is a regression, not a feature.

This is not borrowed reasoning: this repository already made the call. The acceptance
gate's own leg takes `MSOFFICE_CRYPTO_PASSWORD` from the environment rather than an
argument, and `examples/office_crypto_check.rs` says why in its header. The CLI
generalizes it.

| Flag | Source | For |
|---|---|---|
| `--password-env NAME` | that environment variable | scripts, CI |
| `--password-file PATH` | first line of the file, one trailing CR-LF or LF stripped | secret managers, `--password-file /dev/stdin` |
| `--password-stdin` | one line from stdin | pipelines |
| *(none)* | non-echoing terminal prompt via `rpassword` | interactive use |

Exactly one may be given; two is a usage error rather than a silent precedence win.
With none of them and no terminal — stdin is not a TTY — the command fails naming the
flags that exist, rather than blocking forever on a prompt nobody can see.

`--password-env` takes the variable's *name*, so `MSOFFICE_CRYPTO_PASSWORD` is the
obvious argument and the help text names it. The CLI does **not** read it implicitly: a
password that applies without being asked for is how the wrong file gets decrypted in a
loop.

`--password` is registered as a hidden argument purely so that reaching for it produces
the reason it does not exist, rather than clap's generic "unexpected argument".
Removing the trap would make the tool less clear about a decision this section calls
load-bearing.

---

## 3. Exit codes

A CLI that returns 1 for everything cannot be scripted. Codes 0–7 carry the sibling's
meanings unchanged; 8 and 9 exist because this crate distinguishes facts the sibling's
error type does not.

| Code | Meaning | Maps from |
|---|---|---|
| 0 | success | — |
| 1 | usage error | bad flags, missing operand, two password sources, output exists without `--force` |
| 2 | I/O error | unreadable input, unwritable output, `Error::Io` |
| 3 | not a Microsoft Office file | `Error::NotACfbFile` on an input `classify` also calls `Container::Unknown` |
| 4 | wrong password | `Error::WrongPassword` |
| 5 | refused: nothing to do | decrypt of an unencrypted file, encrypt of an already-encrypted one, `Error::NotEncrypted` |
| 6 | malformed or hostile file | `MissingStream`, `XmlParse`, `BadParameters`, `CipherError` |
| 7 | internal invariant violated | `RandomSource` |
| 8 | **integrity** | `IntegrityCheckFailed`, `IntegrityElementMissing`, `IntegrityUnavailable` |
| 9 | **unsupported encryption** | `UnsupportedEncryptionVersion`, `UnsupportedAlgorithm`, `Family::Unsupported`, and a legacy family in a build without `legacy-binary` |

**Why 8 is not folded into 4 or 6.** `CLAUDE.md` § *Cryptographic Rules* requires that
"wrong password" and "file tampered" be different variants, because telling a user
their password is wrong when the file was modified is actively misleading. A CLI that
maps both to one number re-creates that bug at the process boundary, where it is worse:
the error text a human would have read is on stderr, and the number is all a script
gets. 6 is "this file is broken"; 8 is "this file was changed after it was written, or
the policy would not accept it unauthenticated". Those drive different next steps — one
is a support ticket, the other is an incident.

**Why 9 is not folded into 5.** 5 means the file needed nothing done to it. 9 means it
needed something this build cannot do, and the fix is often a flag away — a `.doc`
refused by a binary built without `legacy-binary` must say which feature to rebuild
with, and must not look like "your file is fine".

---

## 4. `classify` cannot fail, and that changes the table

The sibling's `classify` returns a `Result`, and its CLI maps "not a zip" to exit 3.
This crate's `classify` returns a `Classification` unconditionally — `CLAUDE.md`
§ *Design Values* 1 makes that a rule, not an implementation detail: it is the first
thing a caller runs on an unknown file, so it returns "unknown" and never fails loudly.

Consequences, both deliberate:

- **`classify` exits 0 on anything it can read**, including sixteen bytes of junk,
  which it reports as `container: unknown`. That is an answer, not a failure. Only an
  unreadable *file* is an error (exit 2). The alternative — inventing an exit 3 for
  "unknown" — would put a failure code on the one command whose contract is that it
  does not fail, and would be the first thing to diverge from the library the moment a
  new container became recognisable.
- **`decrypt` classifies before it decrypts**, so the interesting refusals are the
  CLI's rather than the library's. Handed a plain `.docx`, the library says
  `NotACfbFile`, which is true and unhelpful; the CLI says "not encrypted" and exits 5.
  Handed sixteen bytes of junk it exits 3. Same library error, two different answers,
  because the classification distinguishes them and the error cannot.

---

## 5. `classify` output

Human-readable by default, one field per line, stable key names, absent fields omitted:

```
container:    cfb
document:     ooxml-package
version:      4.4
family:       agile
encrypted:    yes
supported:    yes
integrity:    declared
key-cipher:   AES
key-hash:     SHA-512
key-bits:     256
key-block:    16
key-salt:     16
pw-cipher:    AES
pw-hash:      SHA-512
pw-bits:      256
pw-spin:      100000
```

Two parameter blocks, not one: a `Classification` carries `key_data` (the package
encryptor) and `password_key` (the verifier's) separately, and they differ in real
files. `encrypted:` and `supported:` are the two predicates the type already exposes,
printed rather than left for the reader to infer from `family:`.

Enum values are lower-kebab (`ooxml-package`, `rc4-cryptoapi`, `xor-obfuscation`) so
they are greppable and stable; numbers are numbers.

`--json` emits the same data as one object, built as a `serde_json::Value`, with
`key_data` and `password_key` as nested objects or `null`. Nested rather than
prefix-flattened, because `pw-spin` is a readable column heading and `"pw_spin"` is a
worse JSON key than `"password_key": {"spin_count": 100000}` — and a consumer of the
JSON is reading it with a program that can index one more level.

---

## 6. `decrypt`

**Dispatch on the classification, not on the extension.** A `.doc` that is really an
OOXML package, or the reverse, is exactly the kind of file this crate is built for:

| `Document` | Route | Feature |
|---|---|---|
| `OoxmlPackage` | `decrypt_ooxml_with_policy` | `crypto-ops` |
| `WordBinary`, `ExcelBinary`, `PowerPointBinary` | `decrypt_binary_office` | `legacy-binary` |
| a `Container::Zip` the family calls unencrypted | refuse, exit 5 | — |
| anything else | exit 3 or 9 per § 3 | — |

In a build without `legacy-binary`, the binary-format arm is `#[cfg]`-ed out and the
three binary documents exit 9 with a message naming the feature. One binary, two
capability levels, and the difference is a sentence the user can act on.

**`--integrity POLICY`** takes the four `IntegrityPolicy` variants by name: `require`,
`require-where-defined`, `verify-if-present`, `skip`.

The default is **not spelled as a literal**. It is `IntegrityPolicy::default()`,
rendered through the same name table clap parses, so `--help` shows whichever variant
the library currently defaults to. That flip has already happened once — GH #12 moved
the default from `VerifyIfPresent` to `RequireWhereDefined` because the old one was a
silent downgrade an attacker triggers by deleting ~200 bytes of XML — and a CLI with
the old name typed into its help text would have survived that change looking correct.
A unit test asserts the rendered default parses back to `IntegrityPolicy::default()`.

On success the outcome is reported on **stderr**, one line: `integrity: verified`,
`not-declared`, `not-applicable` or `skipped`. Stderr, so `-o -` into a pipe is
unaffected; and always, so a user who passed `--integrity skip` is told in the same run
that the bytes they now hold are unauthenticated.

`--integrity require` against a 97-2003 binary document is a **refusal**, exit 8, not a
silent `not-applicable`: those formats define no MAC, and `require` is the caller
saying unauthenticated plaintext is unacceptable whatever the file claims to be. That
is the same answer the library gives for ECMA-376 standard encryption, which has no
integrity element by spec — `IntegrityUnavailable`, exit 8.

---

## 7. `encrypt`

`--format agile` (default) or `--format standard`, over `encrypt_ooxml` and
`encrypt_ooxml_standard`. Agile is the default because it is what current Office writes
and the only one of the two carrying a `dataIntegrity` HMAC at all; `standard` exists
for someone who needs an Office 2007 reader to open the result, and the help text says
that rather than leaving the choice to folklore.

The input must be a plain OOXML package. An input `classify` calls `Container::Cfb` is
refused with exit 5 — the library has no `AlreadyEncrypted` variant, so this guard is
the CLI's, and without it a double-encrypted container is a plausible accident.

The artifact a CLI `encrypt` writes is subject to **the same local four-reader gate** as
the library's, per `CLAUDE.md` § *Build and verify* — including the private artifact
directory rule, which exists because a gate run once measured another build's file out
of the shared system temp directory and the verdict was very nearly recorded as
evidence for the wrong tree. S5 does not close on a round-trip through this crate; it
closes on `GATE: PASS` over a CLI-written file, recorded against its SHA-256.

---

## 8. Output paths

`-o/--output PATH` writes there. With no `-o`, write next to the input:
`report.docx` → `report.decrypted.docx` / `report.encrypted.docx`. Never overwrite an
existing file without `--force`; a decrypt that silently replaced the encrypted
original would be unrecoverable, and this crate's whole posture is that the user's data
outlives the tool.

Write to a temporary file in the destination directory and rename over the target, so
an interrupted run cannot leave a half-written `.docx` that looks complete. Same
directory, because a rename across filesystems is not atomic and degrades to a copy.
`-o -` writes to stdout for pipelines; the `wrote <path>` notice and the `integrity:`
line are on stderr either way.

---

## 9. Slices

| Slice | Work | Done when |
|---|---|---|
| **S1** | `cli` feature, `autobins = false`, `[[bin]]` with `required-features`, clap wiring, `--help`/`--version`, the § 3 exit codes as constants, and `classify` with human output. Update the `CLAUDE.md` Layout block in the same change. No passwords, no decrypt, no encrypt. | `cargo test --locked --no-default-features` green, and no binary built in that configuration. `--help`/`--version` exit 0 and name all three subcommands; `--integrit` exits 1 naming the flag and suggesting `--integrity`; `--output=x.docx` is accepted. `classify tests/fixtures/agile_encrypted.docx` prints `family: agile` and `integrity: declared`; `plain.docx` prints `encrypted: no` and exits 0; sixteen bytes of junk prints `container: unknown` and exits **0**. `python tools/audit_claims.py` passes — check D fails until the Layout block names the two new files, which is why that edit is this slice's work. Recorded in the PR: the measured crate delta of `--features cli` over `--features crypto-ops`, and that the detection graph still contains no `clap`, `rpassword` or `serde_json`. |
| **S2** | `--json` for `classify`, built as a `serde_json::Value`, with `key_data` / `password_key` nested. | `--json` output parses as one object for every fixture in `tests/fixtures/`, discovered at run time rather than hardcoded, and carries the same values the human form printed. A test round-trips the output back through `serde_json::from_str` for an encrypted, an unencrypted and a 97-2003 fixture, so a malformed field fails rather than merely looking plausible. An unencrypted file emits `null` for both parameter blocks, not an omitted key. |
| **S3** | Password sourcing: `--password-env`, `--password-file`, `--password-stdin`, the `rpassword` prompt fallback, and the hidden `--password` trap. | Each of the three non-interactive sources decrypts `agile_encrypted.docx` with `testpass`. Two sources together exits 1. No source with stdin redirected from `/dev/null` exits 1 and does **not hang**. `--password secret` exits 1 with the argv reason on stderr. A test greps the binary's own `--help` for the string `--password ` and fails if it appears. |
| **S4** | `decrypt`: classification dispatch, the `legacy-binary` arm, `--integrity`, output handling (`-o`, derived name, `--force`, atomic temp-then-rename, `-o -`), and the § 3 error mapping. | Every encrypted OOXML fixture decrypts to a package whose first four bytes are `PK\x03\x04` and which `classify` then calls unencrypted. `word97_password.doc`, `excel97_password.xls` and `powerpoint97_password.ppt` decrypt byte-identically to the SHA-256 constants `tests/legacy_binary_fixtures.rs` already asserts against `msoffcrypto-tool`'s output — the CLI is checked against the independent oracle, not against the library. Wrong password exits 4; `plain.docx` exits 5; junk exits 3; a `.doc` in a build without `legacy-binary` exits 9 naming the feature. **The integrity pair, both halves required:** an agile fixture with its `dataIntegrity` blobs blanked exits 8 under the default policy, and the *same file* exits 0 with `integrity: not-declared` under `--integrity verify-if-present` — the negative control `CLAUDE.md` § *Testing Rules* demands, without which the test cannot tell "policy wired" from "always fails". Tamper in the ciphertext body, not the header. `--integrity require` on a 97-2003 document exits 8. An existing output without `--force` exits 1 and leaves the existing file byte-identical. |
| **S5** | `encrypt`: `--format agile\|standard`, the already-encrypted refusal, and the gate run. | `encrypt` of `plain.docx` then `decrypt` is byte-identical to the input, in both formats; `classify` of each artifact reports the family asked for. Encrypting an already-CFB file exits 5. `tools/acceptance_gate.py` over a **CLI-written** artifact, from a private `MSOFFICE_CRYPTO_ARTIFACT_DIR`, prints four `PASS` lines and `GATE: PASS`, and those lines are recorded in `CHANGELOG.md` against the artifact's SHA-256. Both mutation runs (`--tamper --expect-fail`, `--corrupt-integrity --expect-fail`) fail as they should. |
| **S6** | CI, packaging and prose. Add `cli` and `cli,legacy-binary` to the clippy and test matrices; assert the detection graph carries no `clap`/`rpassword`/`serde_json`; assert `cargo package --list` ships `src/bin/`. README CLI section, install lines, the exit-code table, the never-in-argv rule, the `cli` row in the feature table, the Apache-2.0 sentence in the feature table and in `deny.toml`. Changelog entry per the `changelog-protocol` skill. | CI green on all five feature configurations. `cargo deny --all-features check licenses advisories bans sources` green with `rpassword` in the graph and **no `exceptions` entry**. `cargo package --locked --list` includes `src/bin/msoffice-crypto.rs`. `python tools/audit_claims.py --clones O:/projects-github-clones` passes. README's exit-code table matches § 3 exactly, and its install lines are the two in § 1.1. |

S2, S3 and S4 block on S1. S4 blocks on S3 — it needs a password. S5 blocks on S4. S6
blocks on S5.

### Where the tests live, and why it matters here

`tests/cli.rs` drives the built binary as a subprocess (`CARGO_BIN_EXE_msoffice-crypto`,
which Cargo sets for every binary target when building an integration test), because
what is under test is argument handling, exit codes and file side effects — none of
which a library call exercises.

**It needs no `fixture_corpus` gate, and the binary's own unit tests must need none
either.** `tests/*.rs` is outside the `include` allowlist and never reaches the tarball,
so an integration test may read all nineteen fixtures and fail loudly on a missing one,
exactly as `tests/real_office_fixtures.rs` already does. `src/**/*.rs` *does* ship, so
the binary's `#[path]`-included test module is published and must stay fixture-free:
exit-code mapping, the derived output name, the first-line rule, the policy round-trip.
Anything needing a withheld fixture belongs in `tests/cli.rs`. Get this backwards and
the count of corpus-dependent tests `CLAUDE.md` pins changes, and the published crate's
`cargo test` goes red over files it deliberately does not ship.

---

## 10. Divergences from the sibling, in one place

| # | `odf-crypto` | Here | Forced by |
|---|---|---|---|
| 1 | `classify` may fail; unknown input exits 3 | `classify` cannot fail; unknown input exits **0** | `classify` never fails loudly — `CLAUDE.md` Design Value 1 |
| 2 | exit codes 0–7 | 0–7 plus **8 integrity**, **9 unsupported** | this crate separates tamper from wrong password, and has families a given build cannot do |
| 3 | three error types | one `Error`, mapped variant by variant | the crate's single public error type |
| 4 | no integrity policy | `--integrity`, default rendered from `IntegrityPolicy::default()` | `IntegrityPolicy` exists, and its default has already moved once |
| 5 | one encrypt path | `--format agile\|standard` | two writers |
| 6 | one decrypt path | dispatch on `Document`, legacy arm behind `legacy-binary` | five encryption families across two container shapes |
| 7 | `required-features` already precedented by `examples/` | first `required-features` target in the repo | the one example needs no feature gate |
| 8 | `rpassword` unremarkable | first Apache-2.0-only crate in a non-dev graph; documented in the feature table and `deny.toml` | `deny.toml`'s licences section is written about exactly this |
| 9 | every golden present | corpus split: 2 of 19 fixtures ship | the `include` allowlist and `build.rs` |

## 11. Out of scope

- **No batch or recursive mode.** `find … -exec` composes better than a flag, and a
  half-finished directory walk is a worse failure than a shell loop.
- **No password-guessing, wordlist or brute-force affordance.** The foundation plan
  already puts password recovery permanently out of scope and names herumi's
  `attack.hpp` as the thing deliberately not ported; a CLI is not where it comes back.
- **No `--json` for `decrypt` or `encrypt`.** Three subcommands and eight flags. The
  facts a script needs from those two are the exit code and the `integrity:` line.
- **No refusal to write binary output to a terminal.** Considered; the sibling does
  not, a user who types `-o -` asked for bytes, and the divergence would cost more than
  it buys.
- **No config file, and no colour.** Ten lines of key-value text do not need a
  terminal-styling crate.

## 12. Borrow / do not copy

**Borrow:** `src/bin/odf-crypto.rs` wholesale in shape — the `ExitCode` mapping, the
hidden `--password` trap, the atomic write, the derived output name, the first-line
rule, the password-source enum, the `after_help` blocks. It is the sibling crate, the
licences match, and a second independent design of the same three subcommands would be
worse and would drift. The env-var-not-argv reasoning is already stated locally, in
`examples/office_crypto_check.rs`.

**Do not copy:** that example itself, or its two-positional-argument grammar. It stays a
throwaway shim for `tools/acceptance_gate.py`, and the gate keeps calling it, so the
four-reader evidence path does not start depending on the CLI's argument grammar — a
CLI flag rename must not be able to break the gate.

---

Protocol: [`../plan-workflow.md`](../plan-workflow.md). Arc context:
[`msoffice-crypto-foundation-2026-09-04.md`](msoffice-crypto-foundation-2026-09-04.md).
