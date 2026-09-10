Status: Durable record — compiled 2026-09-05 from the development repository's issues and pull requests, before that repository is archived

# The development record

This crate was built across 14 issues and 12 pull requests in a private repository that is
being archived. GitHub numbers issues and pull requests from one sequence, so **#1–#13 and
#24 are issues and #14–#23, #25, #26 are pull requests** — there is no pull request #1, and
`#N` in `CHANGELOG.md`, `docs/plans/` or a source comment may mean either.

Those threads carried a layer the code and the changelog do not: what was **decided and then
reversed**, what was **tried and did not work**, what was **closed without being finished**
and where it went. That layer is invisible in a diff and expensive to rediscover, and it dies
with the archive. This file is it.

**This is the primary history.** It was written alongside a 3,397-line changelog that
recorded every change and the mutation that proved it; that changelog stayed with the
archived repository when this one was rebuilt, and `CHANGELOG.md` here begins at the first
release. So where the two overlap, `CHANGELOG.md` carries the measurements a consumer can
check — reader verdicts, goldens, test counts — and this file carries the decisions behind
them: what was settled and then reversed, what was tried and failed, what was closed
unfinished. The day-by-day implementation narrative is in the archive and is not
reproduced here.

Dates are local (America/Los_Angeles), matching `git log` and `CHANGELOG.md`. Several threads
carry UTC timestamps a day ahead; they are the same day.

---

## 1. Index — what each number was

Keep this table. It is what makes a surviving `#N` reference resolvable once the repository
holding those numbers is gone.

| # | Kind | What it was | Outcome |
| --- | --- | --- | --- |
| 1 | issue | Parent plan: complete MS-OFFCRYPTO | **Open** — closes when every slice does |
| 2 | issue | S1: `classify`, feature split, secure-gate boundary | Closed; **its third part withdrawn**, see §2.1 |
| 3 | issue | S2: verify the package HMAC on decrypt (F18) | Closed |
| 4 | issue | S3: port RC4 CryptoAPI + doc97 decrypt | Closed by #19 |
| 5 | issue | S4: spike — does Office accept a `cfb`-built DataSpaces tree? | Closed, **answer: yes**, see §3.1 |
| 6 | issue | S5: agile encryption, six steps | Closed |
| 7 | issue | S6: standard encryption | Closed by #17 |
| 8 | issue | S7: four-reader acceptance gate | Closed by #18 |
| 9 | issue | S8: publish to crates.io | **Open** — its close condition was stale and is now met, see §7 |
| 10 | issue | S9: bound file-controlled parameters | Closed 4/5; the fifth moved to #6, see §6 |
| 11 | issue | S10: agile hardcodes SHA-512, misreports as `WrongPassword` | Closed; the keyBits half moved to #13, see §6 |
| 12 | issue | S11: missing `dataIntegrity` is a downgrade attack | Closed |
| 13 | issue | S12: agile is AES-256 only; 3 of 4 real tuples do not open | Closed by #15 |
| 14 | **PR** | Detection, verified decryption, agile encrypt steps 1–4 | Merged. Declared 7 known gaps — all now closed, §8 |
| 15 | **PR** | AES-128/192 agile: all four real-world tuples open | Merged |
| 16 | **PR** | README/description positioning | Merged |
| 17 | **PR** | `encrypt_ooxml_standard` — the Office 2007 writer | Merged |
| 18 | **PR** | The four-reader acceptance gate, LibreOffice's first verdict | Merged |
| 19 | **PR** | The 97-2003 binary formats, behind `legacy-binary` | Merged |
| 20 | **PR** | Fixture identity guard (landed red, then green) | Merged |
| 21 | **PR** | Cut the `include` allowlist to its floor | Merged — **a deliberate reversal**, §2.4 |
| 22 | **PR** | Trademark and non-affiliation posture | Merged |
| 23 | **PR** | Read against [MS-OFFCRYPTO] itself: five conformance deltas | Merged, closes #24 |
| 24 | issue | Cross-check the implementation against the specification | Closed by #23 |
| 25 | **PR** | Rustdoc read back against the code: 58 claims corrected | Merged |
| 26 | **PR** | Five `pub` items that were never public | Merged |

---

## 2. Decisions reversed or withdrawn

The most expensive category, because a reversal leaves no trace in the final code — only the
absence of something, which reads as an oversight to anyone who has not seen the argument.

### 2.1 The public API was going to take secure-gate types. It does not, and will not.

S1 originally had a third part: move `decrypt_ooxml`'s boundary onto secure-gate wrappers.
It was first *unblocked* by a plan to drop this crate to `secure-gate =0.8.0-rc.10` to match
the consumer's pin — and then, ten minutes later, **withdrawn entirely as a design
error**, which also cancelled the version drop.

Three reasons, in increasing order of how much they settle it:

1. This crate's own secure-gate skill already said so (§ *Scope: the public API stays plain*):
   the caller owns the password, and handing back the plaintext package *is* the function.
2. `odf-crypto`, the deliberately similarly-shaped sibling, exports a plain boundary and had
   already published twice on that basis. Two crates shaped alike should not disagree here.
3. The consumer does not want it. Its call site takes
   `user_password: Option<&str>` and dispatches PDF, OOXML, ODF and ZIP through *identically
   shaped* signatures. A wrapped boundary would force it to build a wrapper solely to satisfy
   this crate, then immediately unwrap it.

**The consequence is the part worth keeping:** because no secure-gate type crosses the
boundary, there is no version to match, so this crate's secure-gate version is invisible to
consumers. That is why `msoffice-crypto` on 0.9.x and the consumer pinned to `=0.8.0-rc.10` coexist
without conflict. Key material *inside* the crate stays wrapped throughout; only the boundary
is plain.

**Do not reopen this without new evidence.** It was decided twice on 2026-09-04, once in
each direction, and the second decision is the considered one.

### 2.2 The golden bar was lowered, deliberately

#6 originally required byte-diffing the encrypt output against **herumi's and
msoffcrypto's** bytes for identical inputs. That needs both tools driven with *our* salt, IV
and session key — a `SAME_KEY` rebuild of herumi and reaching into msoffcrypto's internals.

It was revised down to byte-exactness against **our own committed golden**, on the reasoning
that a bar nobody intends to meet is worse than a lower one, and that #8's four-reader gate
supplies stronger evidence more directly (it includes real Word recovering exact content).
The cheap half of the cross-implementation evidence was kept because it needs none of our
internals: `msoffcrypto-tool` and `office-crypto` each decrypting our output to byte-identical
plaintext.

### 2.3 LibreOffice's four-tuple allowlist was deliberately *not* adopted

#10 supplied LibreOffice's accepted-tuple table as a candidate validation rule and then
argued against copying it: **that list is what LibreOffice chooses to open, not what the
format permits.** Adopting it would trade a denial-of-service bug for a correctness bug —
rejecting files Word opens.

What landed instead is self-consistency validation: `hashSize` must match the named
`hashAlgorithm`, `keyBits ∈ {128,192,256}`, `blockSize` must match the named cipher, and
unknown algorithm *names* are refused. This is why the crate opens AES-256/SHA-256, which
LibreOffice does not.

### 2.4 The tarball stopped shipping the fixture corpus

Until 2026-09-05 the stated posture was that *"a crate whose fidelity claim cannot be re-run
by a distro packager or a `cargo vendor` audit is not worth the bytes saved"*. #21 reversed
it: 717 KB → 289 KB, 65 files → 42.

Both sides of the original argument had changed. The repository was going public, so a clone
re-runs everything the tarball would have — the evidence *moved* rather than vanished — while
a consumer who only wanted to use the crate was paying half a megabyte of Word documents for
the privilege. Three documents that had asserted the fixtures ship were corrected in the same
change.

**The two fixtures that remain are not arbitrary.** `plain.docx` and `agile_encrypted.docx`
are pulled in by `classify`'s doc examples with `include_bytes!`. Measured: without them the
unpacked crate does not compile. Both are python-docx output rather than Office's, so unlike
the other seventeen they never carried document metadata naming whoever generated them.

---

## 3. Negative results — recorded so nobody repeats the experiment

### 3.1 Office accepts a `cfb`-built container (#5) — the spike that unblocked encryption

herumi hardcodes an eleven-row red/black directory-entry table. The open question was whether
Office requires it.

**It does not.** The `cfb` crate builds the directory tree itself and exposes no colour or
sibling-pointer API at all; the tree it produces is nothing like herumi's — every entry Black,
different index assignment, different pointers, zero timestamps — and real Word 16 opens it
and recovers the content. So that table is a property of herumi's tree-builder, not of the
format.

The experiment isolated exactly one variable: `EncryptionInfo` and `EncryptedPackage` were
lifted **verbatim** from a working file and the container rebuilt around them, so the only
thing that changed was who wrote the container.

Its stated limits were: one file, one Office build, one tuple, an *open* rather than a
re-*save*; Excel and PowerPoint untested at that point.

### 3.2 Office 16 cannot be made to write the older agile tuples

To generate AES-128/SHA-1 fixtures, Office's encryption-tuple policy was set at
`HKCU:\Software\Microsoft\Office\16.0\Common\Security\OpenXMLEncryption` to
`Microsoft Enhanced RSA and AES Cryptographic Provider,AES 128,128,SHA-1`, and a document was
saved through Word COM.

**Word ignored the setting entirely** and wrote AES-256/SHA-512 as always. The registry key
was removed afterwards. This is consistent with those tuples being what Office 2010/2013
wrote — which is why LibreOffice still accepts them — and modern Office having settled on one.

Consequence: those fixtures come from `msoffcrypto-tool`'s writer, and the test module states
that provenance. **Cross-implementation evidence is not interop evidence and must not be
presented as such.**

### 3.3 Office 16 will not write the Office 97/2000 RC4 family either

It writes only 128-bit RC4 CryptoAPI whatever `SetPasswordEncryptionOptions` asks, and refuses
the Office 97/2000 provider outright. That family is therefore pinned by `msoffcrypto-tool`'s
known-answer vectors and a synthetic container, with no real fixture — stated in the README
row rather than left as a silent weakness.

Similarly, Excel 16's XOR route writes a BIFF5 `Book` stream the oracle cannot read, so the
XOR fixture is generated over `excel97_plain.xls` with the oracle's own key material.

### 3.4 LibreOffice could not be driven headless — until it could

Three separate threads (#6, #15, #17) recorded LibreOffice as *not run*, because it could not
be driven headless with a password on this machine. #18 solved it: a pipe, a fresh
`-env:UserInstallation` profile, and LibreOffice's own bundled Python. The recipe is in the
changelog. Any document still saying LibreOffice cannot be driven is superseded.

---

## 4. Findings *about the references* — bugs found in the sources we ported from

These are the reason "read the reference sceptically" is a rule here rather than a slogan.

- **herumi generates a weak session key.** `FillRand(secretKey, encryptedKey.saltSize)` draws
  the **salt** size (16) and then pads to `keyBits / 8` with the constant `0x36` — an AES-256
  key with **128 bits of entropy and a constant top half**. It reads like `saltSize` was
  written where `keyBits / 8` was meant. Nothing downstream notices, because the key is
  whatever the writer says it is: **no round-trip test in any implementation could find it.**
  `ms-offcrypto-writer` does not share the bug, which is what makes it herumi's rather than a
  reading of the format. This crate draws all 32, with a test asserting every byte position
  varies across 23 seeds.

- **`msoffcrypto-tool` omits the `hashSize` truncation** (`ecma376_agile.py:466`) and
  consequently rejects correct passwords on SHA-1 agile files. herumi and LibreOffice both
  truncate; so does this crate.

- **`msoffcrypto-tool` corrupts PowerPoint output.** It decrements `cPersist` and leaves a
  dangling `cPersist = 0` entry, which [MS-PPT] 2.3.5 forbids — and PowerPoint 16 **refuses
  its own output** (`0x80048242`). This crate leaves the directory alone. The differential
  test pins both digests, so the byte-for-byte agreement still holds everywhere else.

- **`msoffcrypto-tool` cannot read its own AES-192 output**, and its writer zero-pads HMAC
  blobs where its reader expects otherwise. Both surfaced as acceptance-gate control rows.

- **LibreOffice's flat parse struct crosses the two salts.** It compares `<keyData>`'s salt
  bytes against `<p:encryptedKey>`'s `saltSize`, which is correct only because every real
  writer emits 16 for both. This crate passes the pair in together so the crossing is not
  expressible.

- **The committed `standard_encrypted.docx` fixture is non-conforming** in three header
  fields (`Flags 0x36`, RC4's `AlgID 0x6801` over an AES-128 package, a zero `Flags` copy).
  Word, LibreOffice and `office-crypto` all refuse it; `msoffcrypto-tool` and this crate read
  it. The crate forgives it deliberately, and #17's correctly-labelled artifact passes all
  four readers.

- **Word compares more of the verifier blobs than any other reader.** #15 pinned it with
  thirteen same-length variants: Word keys the HMAC with the *whole* decrypted key blob and
  compares the whole value and verifier-hash blobs against zero-extended values. A `0x36` tail
  — LibreOffice's byte, and what this crate wrote — is a refusal; zero tails open. Readers
  that truncate to `hashSize` cannot see the pad. That was a latent bug in our writer,
  invisible to the SHA-512 golden because 64 needs no padding.

---

## 5. Cross-repository decisions (the downstream consumer)

The consumer is private and dormant here; its Office handler is switched off until this crate
publishes. These decisions were made in this repository's threads and must not be re-argued
when it is switched back on.

- **`NativeFormat::OfficeBinary`, flat.** Microsoft's own term — `[MS-DOC]` is titled *"Word
  (.doc) Binary File Format"*. Not `MsoLegacy` (a judgement about age, and these files still
  arrive daily), not one variant per file type, not a vendor sub-enum (it groups by
  capability, not vendor).

- **The trap, stated explicitly:** the consumer refuses `Ooxml | Odf` for native encryption. It is
  tempting to add `OfficeBinary` to that arm. **Those are two different facts.** `Ooxml`/`Odf`
  are refused because writing that encryption was unimplemented — *temporary*, and now closed
  by #6/#7 here. `OfficeBinary` is refused because agile encryption wraps an OOXML ZIP and
  therefore cannot wrap an OLE `.doc`; the only native alternative is RC4, which a vault must
  not write — **permanent**. Share the arm and native encryption silently switches back on for
  `.doc` the day the other reason expires.

- **Which entry point.** Call `encrypt_ooxml` (agile, authenticated). Expose
  `encrypt_ooxml_standard` only behind an explicit "Office 2007 compatible" choice, if at all
  — the vault's premise is that a stored file is not silently modifiable, which the standard
  format cannot promise (no integrity element, and ECB leaks equal blocks).

- **The re-enable list:** `features = ["crypto-ops"]`, or `["legacy-binary"]` for
  `.doc`/`.xls`/`.ppt` through `decrypt_binary_office`; the fail-closed `IntegrityPolicy`
  default; and the error variants the handler currently flattens. There is no `IntegrityPolicy`
  on the binary path — those formats define no integrity element.

- **Detection belongs to this crate.** The consumer should call `classify` rather than sniffing CFB
  streams itself, and must not offer "Upgrade Native" for binary formats.

`tests/encrypt_entry_points.rs` exists as the contract stated from *outside* the crate, and is
what the consumer can rely on.

---

## 6. Work closed without being finished, and where it went

Each of these was closed deliberately rather than left open, with the remainder re-homed.
Recorded because a closed issue reads as complete.

| Closed | What was left undone | Where it went |
| --- | --- | --- |
| **#10** (4 of 5 items) | The `/EncryptedPackage` read ceiling — no honest constant existed while the API was buffer-in/buffer-out, and a legitimate `.pptx` runs to hundreds of megabytes | **#6 step 2**, the segment iterator, which is what made a bounded working set exist. Landed as `PAYLOAD_CEILING = 1 << 30` |
| **#11** (hash dimension only) | Two close-when bullets were **unmet, not satisfied** — no AES-128 or AES-192 fixture decrypted, because the crate was AES-256 only. The two fixtures it added were AES-256/SHA-384 and AES-256/SHA-256, neither of which is one of the four real-world tuples | **#13**, closed by #15 |
| **#6** | The LibreOffice reader row | **#8**, closed by #18 |
| **#3** | Encrypt-side HMAC generation | **#6 step 5** |

**#10's stated reason for closing rather than re-scoping is worth keeping:** leaving it open
would advertise an available slice that is 4/5 done with a remainder blocked on unstarted
work, *"which is a worse signal than either closing or re-scoping."*

**#11 carried a warning forward that #13 then honoured:** the `keyBits / 8 > digest_len`
refusal was correct while AES-256 was the only path, but AES-128/SHA-1 is legitimate (16 ≤ 20),
so the guard had to stay expressed as the inequality and never as `hash == SHA-1`. #15's
mutation table shows the mis-shaped version being written deliberately and failing.

**#10 also absorbed a follow-up it had deferred.** It deferred standard encryption's own
`EncryptionHeader` validation to a future issue; most of it landed anyway alongside the agile
work. Anyone reaching for that follow-up should read `standard.rs` and `malformed_input.rs`
first and scope only the remainder — **do not file it fresh.**

---

## 7. #9's close condition contradicted a later decision — and is now satisfiable

**#9 (publish) requires a fresh `cargo test` inside the unpacked tarball to pass**, *"which is
what proves the vendored fixtures actually shipped"*. That was written 2026-09-04, before #21
cut the allowlist to two fixtures on 2026-09-05, and the two decisions then contradicted each
other.

Measured 2026-09-05, before the repair: **156 passed, 19 failed** under `crypto-ops` and 30
failed under `legacy-binary`, every failure reading `fixture ... must be present -- these
tests are not optional`. Nothing was broken — that is the fixtures-are-not-optional rule
working exactly as designed against a tarball that deliberately ships two of nineteen.

**The trap was that the obvious fix is the wrong one:** re-adding ~400 KB of Office documents
to make a suite green, reversing a considered decision to satisfy a sentence written before
it. The second-obvious fix is also wrong — an early `return` when the file is missing is
precisely the `let Ok(data) = … else { return }` anti-pattern this crate removed, where a
missing fixture produced a green suite that tested nothing.

What landed instead: `build.rs` sets `cfg(fixture_corpus)` when any withheld fixture is
present, and the 30 corpus-dependent tests carry
`#[cfg_attr(not(fixture_corpus), ignore = "…")]`. The tarball reports them as **ignored, with
a reason** — true, and visible in cargo's normal output — while the repository still runs all
30. A partially present corpus deliberately counts as *present*, so a deleted fixture still
fails loudly by name.

The ignored counts are now a two-way check: 0 ignored in a tarball means the corpus leaked
into the allowlist; anything but 0 ignored in a checkout means the corpus is incomplete.
`docs/RELEASING.md` § 3 carries the numbers. **#9's close condition can now be met as
written.**

---

## 8. PR #14's seven known gaps — audited 2026-09-05, all closed

#14 listed seven holes it was not fixing. **None was given a tracking issue**, so their status
existed nowhere. Verified against the tree today:

| # | Gap as declared | Status |
| --- | --- | --- |
| 1 | `binary_office.rs` — Excel's BIFF walk falls through to `encrypted: Some(false)` on any abnormal exit, so a malformed `/Workbook` classifies as unencrypted: *"a guess in the attacker's favour"* | **Closed.** `FilePassScan` is now three-state — `Unreadable` / `ProvenAbsent` / `Found`. Only `ProvenAbsent` yields `Some(false)`; an abnormal exit reports `Unreadable` |
| 2 | Agile is AES-256/SHA-512 only and standard is AES-128 only, while the README publishes unqualified "decrypt ✅" | **Closed.** #13/#15 opened all four agile tuples, and the README's Scope table now qualifies every row, including **"AES-128/SHA-1 only"** for standard |
| 3 | `keyData/@hashAlgorithm` gets no digest-length pairing check, though it drives every package IV and the HMAC | **Closed.** `key_data_hash_size` is checked against `key_data_hash` at parse time |
| 4 | The standard-decrypt test asserts only `starts_with(b"PK\x03\x04")` when byte-identity is free | **Closed.** Asserts the standard fixture decrypts to `plain.docx` byte for byte |
| 5 | `NOTICE` says the herumi derivations are *"PLANNED, not yet present"* while sixteen files cite herumi | **Closed.** No such wording remains |
| 6 | There is no CI; every number is a local measurement | **Closed.** `.github/workflows/ci.yml`, ten jobs |
| 7 | `CHANGELOG.md` contains a NUL and a literal `0x06`, so GitHub renders it as binary | **Closed.** Zero of each |

---

## 9. Practices that came out of specific failures

Not opinions — each was paid for.

- **One target directory per checkout.** #17 found `cargo test` on a feature branch being
  served the unit-test binary a checkout of `main` had built: 148 tests from a binary
  containing none of the branch's. Cargo names this package's artifacts by a path-independent
  hash and judges freshness from the *last* build's dep-info, which does not list the new
  file. The hazard lands on the checkout with the new tests.
- **Restore mutations with something that updates mtime.** The same PR was bitten again:
  `Copy-Item` preserves the backup's mtime, so a restored file identical to `HEAD` by SHA-256
  and `git diff` was *older* than the mutant's artifacts, and the next matrix re-ran the
  mutant's binary from a tree `git` called clean. **Cargo compares mtimes; git compares
  content.**
- **`--no-fail-fast` when a guard is expected to be red.** #20's guard landed red on purpose;
  cargo halts at the first failing test *binary*, so two stale-digest failures stayed hidden
  behind it for several commits.
- **Never run two `cargo` invocations against one working directory** — on Windows it produces
  a spurious `could not compile … example "office_crypto_check"`, observed 2026-09-05, green
  when run alone.
- **One closing keyword per issue.** #14's first draft wrote a sentence saying an issue was
  *not* being closed and linked it for closing anyway: GitHub matches keyword-then-number and
  ignores surrounding negation. Verify with `gh pr view <n> --json closingIssuesReferences`.
- **A test that greps for the leaked value writes it into the repository permanently.** #20's
  fixture guard asserts author fields hold a sentinel instead, so it catches *any* name and its
  failure output never echoes what it found.
- **Lints check shape, not truth.** #25 found 58 false documented claims under a fully clean
  rustdoc lint set — five of them regressions from #23, each a comment that PR did not touch,
  made false by a line it did. **A review of the diff alone catches none of those.**
