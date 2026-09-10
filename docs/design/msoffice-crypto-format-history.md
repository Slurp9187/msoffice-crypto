Status: Reference — external research, reviewed and annotated 2026-09-04; converter evaluation added 2026-09-05

# Detect + decrypt across the real Office matrix

> **How to read this file.** The survey below was written by another agent whose frame of
> reference was a **read-only ingestion tool** — something that opens documents a user was
> sent, reads the contents, and never writes a file back. Product-specific references from
> that context have been scrubbed; the framing that remains is generalised to this crate.
>
> Its format matrix is the most complete one we have and its detection tree is better than
> what issue #2 currently specifies. Its **priorities are inverted** for this crate: it defers
> encryption, which is slices #6/#7 here, and it treats decryption as the whole job.
>
> Reviewed 2026-09-04 against the local clones. Annotations are marked inline:
> **Verified** (checked against source), **Correction** (wrong or wrong for this crate),
> **Gap** (missing dimension). Beyond the scrub described above, the original text is
> otherwise unedited — it is a dated research record, and rewriting its technical claims in
> place would erase what was actually asserted. The scrub touched framing only: no format,
> algorithm, library assessment or recommendation was changed.
>
> One bug came out of this review: issue #11. See §*Coverage of the libraries that matter*.

Detect + decrypt across the real Office matrix, not “Word 97 RC4 and call it done.”

No Go package covers that. Excelize is OOXML-only. `TalentFormula/msdoc/crypto` is exactly the slice you do not want. For full detect+decrypt you borrow from **Python `msoffcrypto-tool`**, with the **TypeScript `office-crypto` port** as a cleaner second source, and existing Rust only as a partial head start.

## What “all versions” actually is

MS-OFFCRYPTO has four password-to-open families, plus pre-97 XOR that is not in that spec.

| Era | Apps | Container | Scheme | Marker |
|---|---|---|---|---|
| Word/Excel/PPT ≤95 | binary | OLE or raw | XOR obfuscation (pre-OFFCRYPTO) | app-specific |
| Office 97–2000 | .doc/.xls | OLE | 40-bit RC4 | DOC: table stream Fib; XLS: `FILEPASS` type `0x0001` subtype standard |
| Office XP–2003 (and binary saved from later) | .doc/.xls/.ppt | OLE | RC4 CryptoAPI | DOC: `0x01`/`0x02` encryption flags; XLS: `FILEPASS` subtype `0x0002`; PPT: Current User + encrypted streams |
| Excel XOR (XP–2003) | .xls | OLE | XOR Method 1 | `FILEPASS` type `0x0000` |
| Office 2007 OOXML | .docx/.xlsx/.pptx | CFB wrapper | Standard / CryptoAPI AES (or RC4) | `EncryptionInfo` minor=2 |
| Office 2010+ OOXML | same | CFB wrapper | Agile | `EncryptionInfo` 4.4 |
| Rare | OOXML | CFB | Extensible | minor=3 |
| Rare | any | DataSpaces | IRM / certificate key encryptors | not password |

Office 2007 can still emit Standard. Office 2010+ normally emits Agile. Binary `.doc/.xls/.ppt` from later Office still uses RC4/XOR if the user saved the old format.

Nobody serious implements Office 95 crypto or Extensible/IRM. Treat those as “detected, refuse.” That is still “all versions” in practice.

## Coverage of the libraries that matter

| Scheme | Excelize (Go) | Rust `office-crypto` | Anysphere formula | Python msoffcrypto-tool | TS `office-crypto` |
|---|---|---|---|---|---|
| Detect OLE vs ZIP | yes | yes | yes | yes (`-t`) | yes |
| OOXML Agile decrypt | yes | yes (SHA-512 path; other hashes stub) | yes | yes | yes |
| OOXML Standard AES decrypt | yes | yes | yes | yes | yes |
| OOXML Standard RC4 decrypt | no | no | yes | yes | yes |
| Word 97–2000 RC4 | no | no | no | yes | yes |
| Word 2002–2004 RC4 CryptoAPI | no | **yes** | no | yes | yes |
| Excel XOR / RC4 / RC4 CryptoAPI | no | **no** (explicit Unimplemented) | **yes** | yes (experimental) | yes |
| PPT RC4 CryptoAPI | no | no | no | partial | yes |

> **Verified 2026-09-04 against real Office-written files, and the table needs three
> corrections.** Six fixtures were saved by Microsoft 365 build 16.0.19127.20302 — Word,
> Excel and PowerPoint, `.doc`/`.xls`/`.ppt` and `.docx`/`.xlsx`/`.pptx` — and probed.
>
> **1. The legacy three are RC4 CryptoAPI, measured not assumed.** `EncryptionHeader`
> v4.2, `AlgID = 0x6801` (RC4), `AlgIDHash = 0x8004` (SHA-1), `KeySize = 128` bits, for
> both `.doc` (FIB `fEncrypted`, `1Table`) and `.xls` (`FILEPASS` at 0x14,
> `wEncryptionType = 1`). A 2026 build still writes the 2003 scheme when you pick
> "97-2003" — this format is not historical.
>
> **2. msoffcrypto-tool's PPT support is better than "partial".** It decrypted a real
> PowerPoint-written encrypted `.ppt` to plaintext carrying the expected marker (entropy
> 7.999 → 7.116). All three legacy fixtures decrypt. Treat the row as **yes** for
> RC4 CryptoAPI; "partial" presumably refers to the older schemes, which were not tested.
>
> **3. LibreOffice belongs in this table, and its PPT97 answer is the interesting one.**
> It opens *unencrypted* PPT97 fine but **refuses the encrypted file — reporting
> `"Version Incompatibility. Incorrect file version."`**
>
> That message is false, and the reason is structural. Grepping which modules use the
> legacy codec:
>
> | LibreOffice module | uses `msfilter/mscodec` |
> | --- | --- |
> | `sw/source/filter/ww8/` — Writer | ✅ |
> | `sc/source/filter/excel/` — Calc | ✅ |
> | `filter/source/msfilter/mscodec.cxx` — the codec itself | ✅ |
> | `oox/source/crypto/AgileEngine.cxx` — OOXML agile | ✅ |
> | **`sd/` — Impress** | ❌ **absent** |
>
> LibreOffice **has** RC4 CryptoAPI and simply never wires it into the PowerPoint filter.
> So Impress opens the file, parses ciphertext as PPT records, gets garbage headers, and
> concludes the version is wrong. It is not a missing algorithm — it is a missing
> *detection step in front of the parser*.
>
> **Why that matters to this crate.** It is the same failure class as GH #11, where we
> reported `WrongPassword` for an algorithm we did not implement: an unsupported-capability
> failure wearing another error's costume. It is the strongest available argument for
> `classify` running first and never guessing — a shipping product with an enormous user
> base gets this wrong precisely because its architecture lets a format filter reach
> encrypted bytes with no encryption check in front of it.
>
> **Consequence for the acceptance gate (#8):** PPT97 has two independent verifiers
> (PowerPoint COM, msoffcrypto-tool), not four. LibreOffice cannot serve as one.
| Word XOR | no | no | no | no | no |
| Office 95 | no | no | no | no | no |
| Extensible / IRM | detect+error | error | error | unimplemented | unimplemented |

Rust `office-crypto` dispatch is literally: EncryptionInfo → OOXML; `WordDocument` stream → doc97; `Workbook` → unimplemented; `Current User` → unimplemented.

> **Verified 2026-09-04.** Exact, at `office-crypto/src/lib.rs:78-88`. Both `Workbook` and
> `Current User` return `DecryptError::Unimplemented`.
>
> **Verified — and it exposed a bug in *this* crate.** The table row
> *"Rust `office-crypto` → OOXML Agile decrypt → yes (SHA-512 path; other hashes stub)"* is
> confirmed by its own doc comment (`src/lib.rs:29`): non-SHA512 agile yields `Unimplemented`.
>
> Checking ours against that: `src/agile.rs` **never read `hashAlgorithm`**
> (`grep -c hashAlgorithm src/agile.rs` → `0`) and hardcoded `Sha512` at six sites.
> LibreOffice accepts four agile tuples (`AgileEngine.cxx:574-612`); **three of them**
> — AES-128/SHA1, AES-128/SHA384, AES-192/SHA384 — derived a wrong `H_final` here, failed
> the verifier, and surfaced as **`WrongPassword`**. The password was right; we could not
> read the file.
>
> `office-crypto` *detects and refuses*; we *silently misdiagnosed*. Strictly worse than the
> crate we chose not to depend on. Tracked as **#11**.
>
> **Fixed 2026-09-04 (#11), with two corrections to the paragraph above** — recorded rather
> than edited away, because both are things the original filing got wrong:
>
> 1. **By the time #11 was worked the symptom was `BadParameters`, not `WrongPassword`.**
>    Issue #10's `keyBits` bound and verifier-length guard both fire before the comparison,
>    so those tuples already produced a loud error — a *misleading* one, naming SHA-512 for
>    a file that named SHA-384, but not a misdiagnosed password. After #10 the
>    `WrongPassword` shape was reachable only through a crafted file.
> 2. **Three of LibreOffice's four tuples are still unreadable here, for the other reason.**
>    AES-128/SHA1, AES-128/SHA384 and AES-192/SHA384 all fail on the *key length*:
>    `agile::aes256_cbc_decrypt` implements AES-256 only. The hash gap is closed; the cipher
>    gap is not, and it is separate work.
>
> What #11 landed: `p:encryptedKey/@hashAlgorithm` and `@cipherAlgorithm` are parsed and
> honoured at every site on the password path, kept apart from `<keyData>`'s identically
> named attributes, and an unimplemented name is `UnsupportedAlgorithm { what, name }` —
> which is what `office-crypto` had over us.

So if you only vendor that crate you get modern Word/Excel/PowerPoint files plus old `.doc`. The gap is passworded `.xls` — which, because Excel was where password-to-open saw heavy business use, is disproportionately what turns up in a real corpus of encrypted Office documents.

## Detection tree you want in Rust

Do this before any KDF. It is cheap and is the public `detect` API.

1. First 8 bytes
   - `50 4B 03 04` → plain OOXML ZIP. Not encrypted.
   - `D0 CF 11 E0 A1 B1 1A E1` → OLE/CFB. Continue.
   - else → not an Office compound file (or Office 95 / raw BIFF5 without OLE).
2. Inside CFB, look at stream names
   - `EncryptionInfo` + `EncryptedPackage` → OOXML encrypted. Parse version:
     - `4.4` Agile
     - minor `2` Standard/CryptoAPI
     - minor `3` Extensible → unsupported
   - `WordDocument` → MS-DOC. Read Fib encryption flags / table stream.
   - `Workbook` or `Book` → MS-XLS. Scan BIFF for `FILEPASS` (0x002F).
   - `Current User` + `PowerPoint Document` → MS-PPT.
3. XLS `FILEPASS`
   - `wEncryptionType == 0` → XOR
   - `== 1` and subtype standard → 40-bit RC4
   - `== 1` and subtype `2` → RC4 CryptoAPI (two payload layouts exist; formula documents both)

`msoffcrypto-tool -t` is the reference for this probe. Port that, not Excelize’s “OLE magic + password option.”

## What to borrow, by layer

**Do not start from Go.** There is no Go matrix. Steal structure from Python, types from the TS port, and Excel FILEPASS details from formula.

1. **Dispatcher + detect**  
   `msoffcrypto/__init__.py` + `format/ooxml.py`, `doc97.py`, `xls97.py`, `ppt97.py`  
   TS port: `OfficeFile(buf)` factory. Same idea, less Python-ism.

2. **OOXML Agile / Standard decrypt**  
   Best trio:
   - Python `method/ecma376_agile.py` + `ecma376_standard.py`
   - Rust `office-crypto` (already a port of the OOXML half)
   - Excelize `crypt.go` only as a compact Go reading of the same KDFs  

   Watch the Agile 4096-byte segment boundary and Standard AES-ECB + 8-byte size prefix. Both have bit people.

3. **Binary RC4 and RC4 CryptoAPI**  
   Python `method/rc4.py` and `method/rc4_cryptoapi.py`.  
   Rust already has the Word CryptoAPI path in `office-crypto` (`doc97`). Reuse that; do not re-derive from TalentFormula.

4. **Excel FILEPASS (XOR + RC4 + CryptoAPI)**  
   This is the gap in current Rust crates. Sources:
   - Python `format/xls97.py` + `method/xor_obfuscation.py`
   - Anysphere `formula-xls` `biff/encryption.rs` + `encryption/cryptoapi.rs` — best writeup of the two CryptoAPI layouts and “decrypt record payloads only, headers stay plaintext.”

> **Correction — licence unverified, do not read yet.** `formula-xls` is recommended twice in
> this file with no licence stated, and it is the only named source not already cleared. Under
> CLAUDE.md §*Licence discipline*, nothing is read until the licence is confirmed compatible
> with `MIT OR Apache-2.0`. Apache-2.0 would make it read-only-for-behaviour like LibreOffice;
> anything copyleft puts it in the CryptoOffice category (do not open).
>
> Every other source named in this file is MIT or BSD-3 and cleared: herumi (BSD-3),
> office-crypto (MIT), msoffcrypto-tool (MIT + herumi NOTICE), ms-offcrypto-writer (MIT/Apache),
> excelize (BSD-3), `cfb` (MIT).

5. **PPT**  
   Python `format/ppt97.py` (partial). TS port claims RC4 CryptoAPI decrypt. Lowest priority unless you ingest `.ppt`.

6. **CFB/OLE reader**
   Need stream listing and named-stream reads. Options: port olefile, use a CFB crate (`cfb`, `ole`), or lift `office-crypto`’s `ole` module. Excelize uses `richardlehane/mscfb` on the Go side; that is read-only and fine for detect/decrypt.

> **Correction — settled, and it is `cfb`.** This is design commitment **D2** in the plan, and
> "lift `office-crypto`'s `ole` module" is the one option to reject. `cfb` 0.14 (MIT) already
> implements FAT chains, DIFAT, the red-black directory tree, a validate pass and a fuzz
> target, and it is already this crate's dependency. `office-crypto` hand-rolls 789 lines of
> the same thing and herumi another 789 — taking either would make three hand-rolled OLE
> readers in one dependency tree, which is exactly what D2 exists to prevent.
>
> `cfb` also **writes**, which this file's read-only framing does not need but slices #5/#6 do.
> `ms-offcrypto-writer` 1.0.7 ships `cfb`-built containers at volume, so the container half of
> encryption is a solved problem here.

## Suggested Rust surface

Keep detect separate from decrypt so callers can prompt for a password.

```rust
enum OfficeKind { Ooxml, Doc97, Xls97, Ppt97, Unknown }
enum Encryption {
    None,
    Agile,
    Standard,
    Rc4,
    Rc4CryptoApi,
    Xor,
    Extensible,
    Unsupported(&'static str),
}

struct Probe {
    kind: OfficeKind,
    encryption: Encryption,
}

fn probe(bytes: &[u8]) -> Result<Probe, Error>;
fn decrypt(bytes: &[u8], password: &str) -> Result<Vec<u8>, Error>;
```

> **Adopting the shape, extending the payload.** The `OfficeKind` / `Encryption` split is
> better than one flat enum and issue #2 should take it. Two changes:
>
> - The function is `classify`, not `probe`, to match the sibling crate `odf-crypto` — two
>   crates in one family should not name the same operation differently.
> - `Probe` is too thin. `classify` must also carry the **algorithm tuple**
>   (cipherAlgorithm, hashAlgorithm, keyBits, blockSize, saltSize, spinCount) and **whether a
>   `dataIntegrity` element is present**. The tuple is what #11 needs to stop hardcoding
>   SHA-512; the integrity flag is what lets a caller choose a verification policy before
>   committing to a decrypt (plan design D1).
>
> **Correction — `classify` must never panic and never allocate unboundedly.** It is the
> first thing a caller runs on a hostile file. Return "unknown", never unwrap. See #10.

Decrypt output:

- OOXML → plaintext ZIP (then calamine / docx-rs / etc.)
- .doc/.xls/.ppt → plaintext OLE (same streams, records decrypted in place)

Verifier-first is worth doing for Agile/Standard and RC4 CryptoAPI. You can reject a bad password without decrypting a 20 MB package. msoffcrypto’s `verify_password` is the model.

> **Already done — and insufficient on its own.** `agile.rs` and `standard.rs` both verify the
> password before decrypting the package.
>
> **Gap:** verifier-first proves *the password is right*. It says nothing about whether the
> ciphertext was **modified by someone who never had the password**. That is the agile
> `dataIntegrity` HMAC, which this file does not mention anywhere — and which this crate did
> not implement either (finding F18, now issue #3). Without it a tampered package decrypts to
> garbage and returns `Ok`.
>
> Standard encryption has no integrity element by spec, so for that family "verifier-first"
> genuinely is the whole story.

## Honest “all versions” cut line

Ship as v1:

- detect for ZIP / OLE / EncryptionInfo / FILEPASS / WordDocument / PPT
- decrypt Agile, Standard AES, Word RC4 + RC4 CryptoAPI, Excel XOR + RC4 + RC4 CryptoAPI

Defer:

- PPT full fidelity
- Word XOR Method 2
- Office 95
- Extensible, certificate encryptors, IRM
- encrypt

That covers every password-to-open Office document a user is realistically sent. Encrypt can stay a later crate (`ms-offcrypto-writer` already does modern Agile write).

> **Correction — wrong for this crate, right for the one this was written for.** Encryption is
> not deferred here: slices #6 (agile) and #7 (standard) are first-class, and the whole
> justification for not simply depending on `office-crypto` is that no existing crate spans
> detect + decrypt + encrypt behind one API with wrapped key material.
>
> `ms-offcrypto-writer` is agile-only and encrypt-only, and holds its key material in bare
> containers like every other implementation here. It is the reference for `cfb` integration,
> not a substitute.
>
> The *decrypt* cut line above is still the right one, and #4 adopts it.

## Practical port order

1. Vendor or wrap `office-crypto` for OOXML + `.doc` CryptoAPI. That is already Rust.

> **Refinement — port the format logic, not the crate.** Issue #4 takes `office-crypto`'s
> `method/rc4.rs` and `format/doc97.rs` (MIT, notice retained in `NOTICE`) and deliberately
> leaves its `ole.rs` behind per D2 above. Wrapping the whole crate would import a second OLE
> implementation and a second key-handling posture — `office-crypto` holds keys in bare
> `Vec<u8>`, which is the one property this crate exists to not do.
>
> Its OOXML half is also **not** a safe drop-in as-is: see #11 on the SHA-512 hardcoding, which
> `office-crypto` handles better than we currently do but still does not *support*.
2. Port `xls97.py` FILEPASS detect + XOR/RC4/CryptoAPI decrypt. This is the missing piece.
3. Add `probe()` so a caller can say “encrypted .xls, need password” before committing to a decrypt — and, just as importantly, before allocating anything sized by a field the file controls.
4. Use msoffcrypto’s `tests/inputs/` as golden files. They are the only public corpus that spans the matrix.
5. Ignore Excelize except as a readable Standard/Agile KDF walkthrough.

# Modern Encryption on **re-save**

You can force modern encryption on **re-save**, not on the **same bytes**. Agile will not wrap a leftover `.doc` / `.xls` / `.ppt`.

## Crypto and format are coupled

Agile and Standard encryption wrap an **OOXML package** (a ZIP). After decrypt you must get `PK\x03\x04` plus `[Content_Types].xml`. That payload can be `.docx`, `.xlsx`, `.xlsm`, `.xlsb`, `.pptx`, etc. It cannot be a BIFF8 workbook or a Word 97 FIB.

Microsoft’s own guidance is the same rule: if you want AES, save as Open XML; binary Office 97–2003 files are RC4-only for compatibility.

So the pipeline is:

```
legacy encrypted .xls/.doc/.ppt
        → decrypt (RC4 / XOR / CryptoAPI)
        → convert to OOXML
        → Agile-encrypt the ZIP
```

There is no “upgrade the encryption header in place.”

## Can the formats themselves be upgraded?

Yes. That is a normal Save As / compatibility conversion, not a crypto op.

| From | To | Macros | Notes |
|---|---|---|---|
| `.doc` | `.docx` | none | turn off compatibility mode if you want modern layout |
| `.doc` with VBA | `.docm` | keep | `.docx` strips VBA |
| `.xls` | `.xlsx` | none | 65 536-row ceiling goes away |
| `.xls` with VBA | `.xlsm` | keep | `.xlsx` **deletes** VBA with no recovery |
| `.xls` with Excel 4.0 XLM | messy | often dies or needs Excel itself |
| `.ppt` | `.pptx` | — | animations / old OLE embeds are the usual casualties |
| `.ppt` with macros | `.pptm` | keep | same `.m` rule |

Office, LibreOffice, and several converters will do this. Fidelity is “good enough for ordinary documents,” not bit-identical.

What actually breaks:

- **VBA** if you pick the non-`m` extension.
- **Excel 4.0 / XLM** sheets, some defined names, old external-link formulas.
- **ActiveX / embedded OLE** (Visio, old EQN, packed Worksheet objects).
- Word: WordArt, some list/numbering, binary-only fields, custom XML parts.
- Files that only work in Compatibility Mode. Saving as “modern” can reflow layout and change colors.
- Digitally signed VBA: conversion invalidates the signature.
- Very old WordBasic macros (pre-97) often do not survive.

What usually survives a conversion: values, number formats, most formulas, named ranges, basic charts, shared strings.

`.xlsb` is already in the OOXML family. You can Agile-encrypt it without a format change. A decrypted `.xls` is not `.xlsb`; you still convert.

> **Verified and adopted.** This is the sharpest point in the file and it was not obvious.
> `.xlsb` is a ZIP/OPC package with binary parts, so it satisfies the `PK\x03\x04` +
> `[Content_Types].xml` precondition that agile encryption requires. Slice #6's `encrypt()`
> accepts it with no conversion path.

## What you should *not* do

Do not write Agile `EncryptionInfo` around a raw OLE `.xls`. Excel will see a CFB file, decrypt `EncryptedPackage`, fail the ZIP check, and call the file corrupt.

Do not re-encrypt a decrypted `.xls` with RC4 “because it was RC4.” That is the scheme Microsoft tells you not to use, and a 40-bit key is brute-forceable without the password.

Do not confuse **password to open** (real encryption) with **password to modify / sheet protect / workbook protect / VBA project password**. Those last ones are verifiers on plaintext. Converting the file does not automatically preserve them, and they are not a substitute for Agile.

## A sane re-encrypt policy

```
probe(file)
  if none → leave or optionally Agile-wrap if caller asked
  if agile/standard on OOXML → decrypt; re-encrypt Agile 256/SHA-512/100000
  if binary RC4/XOR → decrypt to OLE;
       convert to OOXML (xlsx/xlsm/docx/docm/pptx/pptm);
       if convert fails → return plaintext + "cannot modernize";
       else Agile-wrap the new package
```

Pick the `m` sibling whenever a VBA project stream exists (`_VBA_PROJECT_CUR` / `vbaProject.bin`). Never silently drop macros on a re-encrypt path.

Treat conversion as a **user-visible format change**: the output filename and content type both change.

Which makes it acceptable depends entirely on the consumer. A tool that only reads the contents does not care that the container changed. A tool that promises to give the user back *their file* — as a vault or an archival store does — cares a great deal, and must say so: “saved as .xlsx, encrypted with current Office defaults.” This is why `upgrade_to_ooxml()` belongs behind an explicit flag and outside this crate.

## Who can do the convert step

Crypto libraries will not. You need an application-level converter:

- **Excel/Word COM or Graph** — highest fidelity, Windows-only, needs Office installed.
- **LibreOffice headless** (`--convert-to xlsx`) — good for values and simple workbooks; weaker on VBA and exotic Excel.
- **Specialized converters** (office_oxide and friends claim `.xls → .xlsx` / `.doc → .docx`) — evaluate on *your* fixtures, especially files with FILEPASS history.

> **Evaluated 2026-09-05: `office_oxide` 0.1.9 is a text extractor, not a converter.** The
> claim in the bullet above was checked against the crate's own source — the
> `office_oxide-0.1.9.crate` tarball from crates.io (MIT OR Apache-2.0, first published
> 2026-04-28, one maintainer plus contributors, active). `save_as` on a legacy file is
> `to_ir()` followed by a fresh OOXML writer (`src/lib.rs:410-423`): nothing from the
> original container is carried across, and the IR was built for text and markdown output.
> The three legacy-to-IR converters are 62, 807 and 83 lines, and what they carry is:
>
> | Path | Survives | Lost |
> | --- | --- | --- |
> | `.xls → .xlsx` (`convert_xls.rs`, 62 lines) | Sheet names; cell values as display text, which the writer re-parses to a number when it looks like one (`create.rs:1115`) | **Every formula** — only the cached result is read (`xls/cell.rs:228`). Number formats, so a date becomes its raw serial. Styles, fonts, merged cells, column widths, hidden rows, charts, images, hyperlinks, comments, names, validation, conditional formatting, freeze panes. Row 1 is forced to a header (`convert_xls.rs:31`). |
> | `.doc → .docx` (`convert_doc.rs`, 807 lines) | Paragraphs; heuristic headings; tables with spans (nested ones flattened, with a visible notice); lists; tab stops | **All character formatting** — CHPX is never decoded, so no bold, italic, font, size or colour. Images, headers, footers, footnotes, fields, styles, sections, page setup, comments, revisions, embedded objects. |
> | `.ppt → .pptx` (`convert_ppt.rs`, 83 lines) | Title, body and notes text — one heading and flat paragraphs per slide | Images, shapes, positions, layouts, masters, tables, charts; everything visual. |
>
> Two losses bear directly on the re-encrypt policy above. **VBA is silently dropped**: the
> only mentions in the source are two comments that skip it (`xls/workbook.rs:293`,
> `xlsx/mod.rs:193`), so a macro workbook comes out as a macro-free `.xlsx` with no
> warning — exactly what "never silently drop macros" forbids. And **it cannot open an
> encrypted legacy file at all**: `FILEPASS` is an error (`xls/workbook.rs:97`) and
> `.doc`/`.ppt` have no encryption handling, so the RC4 CryptoAPI / doc97 decrypt (S3 in
> the foundation plan) runs first whichever converter follows. Its own docs never call the
> conversion lossy — "migrate legacy corpora in one line" is the phrasing — so read the
> bullet's `.xls → .xlsx` as *text export*.
>
> What it does well is what it was built for. The CFB, doc, xls and ppt parsers have no
> `unwrap` outside tests, there is a fuzz target, and 0.1.9 added overflow and DoS guards
> to the `.doc` walker. That is a plausible fit for preview or search indexing in the consumer, and
> no fit for "give the user back their file". If it is ever taken as a dependency for that
> narrower job: MSRV 1.88 on edition 2024 (this crate is 1.85, the consumer 1.81); 69 crates in the
> default build against this crate's 16 for detection and 34 for decrypt — `zip`,
> `quick-xml`, `serde_json`, `encoding_rs` and an unconditional `libc`; and a hand-rolled
> CFB reader rather than `cfb`.
>
> **So the ranking above stands, with one sharpening on each line.** Word/Excel COM is the
> reference importer — the code that wrote the file reads it back — so it is the only path
> that keeps formatting, formulas, charts, embedded objects and, as `.docm`/`.xlsm`,
> macros. Its costs are operational, not fidelity: Office installed and licensed,
> Windows/macOS only, Microsoft's own "Considerations for server-side Automation of
> Office" advises against unattended use, and a modal dialog (macro security, a repair
> prompt) hangs a run. For a desktop vault that is more workable than it sounds — the file
> is already on a machine that may have Office — but it cannot be a hard dependency.
> LibreOffice headless is the portable second: twenty-year-old binary import filters,
> formulas and formatting intact, VBA kept only as stored code and never run; shelling out
> to it raises no MPL question because no code is incorporated. **Graph, or any cloud
> converter, is off the table for a vault** — it sends the decrypted plaintext off the
> machine, which is the one thing a vault exists to prevent. When neither local converter
> is present, the policy above already says what to do: return the decrypted legacy bytes
> with "cannot modernize", not a text skeleton under the user's filename.

Do not bake LibreOffice into the crypto crate. Keep `decrypt()` format-preserving and put `upgrade_to_ooxml()` behind an explicit flag.

## Practical cut

- **Detect + decrypt all schemes:** yes, keep the original bytes.
- **Re-encrypt modern by default:** only after the payload is already OOXML, or after a successful convert.
- **Legacy stays legacy** if convert is off or fails. Offer plaintext export rather than writing RC4 again.
- **Never claim “same file, stronger crypto”** for `.doc`/`.xls`/`.ppt`. That statement is false.

Concrete rule for the crate: `encrypt()` accepts only ZIP/OOXML (and `.xlsb` packages). `encrypt_legacy()` does not exist. `upgrade_and_encrypt()` is a different module that can fail.

> **Adopted verbatim.** This rule now governs slice #6, and the reasoning behind it — wrapping
> agile `EncryptionInfo` around a raw OLE `.xls` makes Excel decrypt, fail the ZIP check, and
> report corruption — is the kind of thing that is expensive to rediscover. `upgrade_to_ooxml()`
> stays out of this crate entirely: it needs an application-level converter (Word/Excel COM or
> LibreOffice headless), and a crypto crate that shells out to an office suite is the wrong
> shape.

---

## What this file does not cover

Three dimensions are absent, and all three matter for a crate whose stated input is files
arriving by email from strangers.

**1. Authentication, not just decryption.** The coverage matrix has no row for integrity
verification. Agile encryption carries a `dataIntegrity` HMAC over the `EncryptedPackage`
stream; without checking it, a package tampered by someone who never knew the password
decrypts to garbage and returns `Ok`. That was finding F18 and is issue #3. Standard
encryption and the RC4 families have no integrity element by spec — worth stating explicitly
so a caller knows the guarantee differs by family rather than assuming it is uniform.

**2. Hostile input.** No mention of panics, bounds, or unbounded work — although every use this
file contemplates involves opening a document somebody else wrote and sent, which is
maximally untrusted. Concretely: `spinCount` is a
file-controlled iteration count with no ceiling in our code, so a file claiming four billion
rounds hangs the process with no allocation and no error. LibreOffice caps it at 10,000,000
(`AgileEngine.cxx:554`), along with `blockSize`, `saltSize` and a salt-length cross-check.
`/EncryptionInfo` is `read_to_end`-ed with no cap. Issue #10.

> **Closed 2026-09-04 (#10), in two passes.** `spinCount` is capped at `1 << 21` — tighter
> than LibreOffice's 10,000,000, with the measurement written into
> `limits::SPIN_COUNT_MAX`'s doc comment — and `blockSize`, `saltSize`, the salt-length
> cross-check, `hashSize`⇄`hashAlgorithm`, `cipherAlgorithm`, `cipherChaining` and
> `keyBits` are all checked, each asked of **each element against that element's own
> attributes**. `/EncryptionInfo` has a 1 MiB read cap.
>
> Two checks went beyond what this paragraph asked for, both found by reading the same
> LibreOffice function: the agile header's `Reserved` word must be `0x00000040` (`:522-530`
> — the one structural check LibreOffice has and msoffcrypto-tool does not), and the
> `EncryptedPackage`'s declared plaintext size is checked against the ciphertext length,
> its only prior use being `Vec::truncate`, which past the current length is a silent
> no-op — so an absurd claim was *accepted* and the caller received padding as content.
>
> One thing was deliberately **not** ported: the four-tuple allowlist at `:574-612`. It is
> LibreOffice's own writer-preset list plus one legacy row, it welds the hash to the key
> size in a format that declares them independently, and copying it would refuse
> legitimate files that Word opens — trading a denial-of-service bug for a correctness
> one. The per-element self-consistency form is herumi's (`crypto_util.hpp:126-167`) and
> is what landed.
>
> What remains open is the read cap on `/EncryptedPackage` itself, which waits on the
> streaming API (D4) and is recorded under *Known gaps* in CHANGELOG.md.

**3. Licence provenance.** Sources are recommended by capability alone — "vendor", "lift",
"steal structure from" — with no note of what each licence permits. For a crate published
`MIT OR Apache-2.0` that is the highest-consequence omission in the file: one pasted function
from an Apache-2.0 or MPL-2.0 source makes the MIT half undistributable. CLAUDE.md
§*Provenance* carries the cleared table; `formula-xls` above is the one outstanding item.
