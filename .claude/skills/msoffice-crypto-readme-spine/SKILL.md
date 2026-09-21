---
name: msoffice-crypto-readme
description: The README's agreed structure, the slots where it diverges from odf-crypto, and the four CI checks that read it. Use before editing README.md, when adding or moving a section, when cutting material from it, when adding a code example, or when CI fails on a job that is not obviously about the README. Also use when reconciling structure with the odf-crypto sibling.
---

# README structure, and what checks it

Local on purpose. **The spine below is an agreement between two sibling crates, not a
general rule** — READMEs vary enormously between projects and this shape has no business
being imposed on one that is not `msoffice-crypto` or `odf-crypto`.

The generic techniques it relies on live in global skills and are not restated here:
`readme-doctests` (compiling the examples), `publish-prep` (what the package ships, and
links into directories it does not), `changelog-protocol` (when concrete versions move).

## The spine

Same headings, same order, in both crates. A reader who has seen one should find the other
by muscle memory.

```
1  # msoffice-crypto              title + one-line pitch
2  badges                         five, fixed order
3  pitch paragraph + status blockquote
4  ## What it does                capability grid: ✅ / ❌ / n/a + Needs column
   [SLOT C]  ## Why this one
5  ## Install                     commented two-line toml + pre-release caveat
   [SLOT A]  (empty here)
6  ## Usage                       fn main() -> Result<…>, rust,no_run
7  ## Command line
8  ## Features                    table, measured crate counts
9  ## How it's verified
10 ## Security
11 ## MSRV
12 ## Sibling crate
   [SLOT B]  ## Trademarks
13 ## Acknowledgements
14 ## License
```

**Features sits after Command line, not before Install, and the reason is load-bearing.**
Install is self-sufficient *because* its toml block carries both lines with comments — the
detection-only one and the `crypto-ops` one — so a reader chooses a build without needing
the features table. Collapse that block to one line and the ordering silently becomes wrong.
The two-line block is a requirement, not a stylistic nicety.

**"Writable is not the same as externally accepted" is a sentence under the grid in §4, not
its own heading.** One sentence does not earn a section, and a heading around it makes a
caveat read as a feature. `CLAUDE.md` requires the distinction to appear; it does not require
a section.

## The three slots, and why each is empty where it is empty

Record the reason, always. Three unexplained asymmetries read as untidiness and invite
exactly the tidying that destroys the information — *empty because measured* and *empty
because not applicable* look identical once the reason is gone.

| Slot | Here | odf-crypto | Why |
| --- | --- | --- | --- |
| **A** — format-detail table after Install | **empty** | `## Supported algorithms` | Their cipher × KDF × start-key axes are genuinely independent, so they need a table. [MS-OFFCRYPTO]'s axes nest — hash × keyBits *within* a family — so the decomposition fits inside a grid cell (`AES-128/192/256 × SHA-1/256/384/512`). A table here would have one row. |
| **B** — crate-specific legal | `## Trademarks` | **empty** | This crate names Microsoft products. `odf-crypto` names no vendor's trademarks. |
| **C** — `## Why this one` | present | **empty** | Four existing implementations do some of what this crate does, so "why not use `office-crypto`" is a question readers arrive with. odf-crypto searched crates.io across `odf`, `opendocument`, `odt` and `libreoffice` — 80 crates, only theirs mentions encryption — so it is empty **on evidence**, not by assumption. |

## The four sibling signals

Order alone does not make two files read as siblings; plenty of unrelated crates share one.

1. **Identical badge row** — same five, same order, same shields.io style.
2. **Reciprocal `## Sibling crate`** with a parallel sentence, not a bare link.
3. **Parallel pitch cadence**: `<authority>-faithful <format> encryption: detect it, decrypt
   it, write it.` The *cadence* is shared; the filler is not, and must not be forced.
   odf-crypto is **LibreOffice**-faithful because for the profile it writes there is no OASIS
   specification to conform to. This crate is **[MS-OFFCRYPTO]**-faithful because the
   specification is the authority and Word is a vendor implementation that blocks a
   disagreement without settling it. Flattening those into one template makes one of the two
   files say something false in its first line.
   Also: **not "OOXML"** — three 97-2003 binary families are roughly half the read surface,
   and are why this crate is not called `ooxml-crypto`.
4. **`## How it's verified` as a shared heading over deliberately different apparatus** —
   four readers here, a UNO-driven LibreOffice golden there. Matching the *content* would be
   dishonest; matching the heading says both crates hold themselves to one standard.

## Mechanical rules — named, not restated

A restated rule is a second copy free to drift from the first. Each of these is owned by a
skill that already states it; this file points, and adds nothing.

- **README examples are compiled** via `#[cfg(all(doctest, feature = "legacy-binary"))]` at
  the end of `src/lib.rs` — `readme-doctests` (global).
- **Examples are `fn main() -> Result<…>` with `rust,no_run`.** No hidden `#` lines, no
  `unwrap` in example code — `readme-doctests`.
- **Links into a directory the `include` allowlist does not ship must be absolute.**
  `docs/`, `tools/`, `tests/` and `examples/` are repository-only — `publish-prep`.
- **Every concrete version moves at bump time** — `changelog-protocol` (global) and this
  repo's profile beside it.

Two checks live here rather than in a publishing flow, because both belong beside a
*structural* edit and not only before a release:

```sh
# 1. an untagged fence is a live Rust doctest -- run AFTER any reorder, not only at adoption
awk '/^```/ { if (!b) { b=1; t=substr($0,4);
       if (t=="") printf "%d: UNTAGGED\n", NR } else { b=0 } }' README.md

# 2. every relative link must be in the PACKAGE, not merely in the allowlist --
#    Cargo auto-includes README.md and the licence files without listing them
grep -oE '\]\([^)#][^)]*\)' README.md | grep -v http | tr -d '](' | sort -u
cargo package --locked --list
```

## What actually checks this README

Four things, and `audit_claims` is only one of them. **CI went red for three consecutive
commits on a job whose name does not mention the README**, while the prose auditor was green
throughout — so "audit green" is true and insufficient.

| Check | Where | What it enforces |
| --- | --- | --- |
| `prose` job → `tools/audit_claims.py` | CI + local | relative links resolve, `file.rs:NNN` citations in range, backticked `module::item` paths exist, MSRV and version figures agree with `Cargo.toml` |
| **`the documented local gate must name a private artifact directory`** | `ci.yml` | if the README names `acceptance_gate.py`, it **must** also name `MSOFFICE_CRYPTO_ARTIFACT_DIR`, and must not point the gate at shared system temp |
| cli graph vacuity guard | `ci.yml` | if `rpassword` stops pulling `rtoolbox`, the Apache-2.0 sentences in README.md **and** `deny.toml` move in the same commit |
| doctests | `cargo test --doc --features legacy-binary` | every ` ```rust ` block compiles |

**The second one is the one that bit.** The compaction cut the artifact-directory warning as
contributor material while keeping the sentence naming the script, so the file went on
documenting the gate and stopped documenting the thing that makes running it safe — exactly
the state the guard exists to prevent. The lesson is not about that paragraph:

> **Judge a cut by what depends on the text, not by whom it is for.** Consumer-versus-
> contributor is a sound editorial rule and a useless safety one. Every other deletion in
> that rewrite was justified by naming where the content already lived; that one was
> justified by naming an audience, and nothing checked whether anything pointed at it.

## This file is duplicated, and nothing detects the drift

`odf-crypto` carries the same spine in `.claude/skills/odf-crypto-readme-spine/SKILL.md`. A
global skill had the better drift story and was **not** chosen, deliberately: READMEs vary
enormously between projects and this shape has no business being applied to one that is not
these two crates, and each repo staying self-describing was judged worth the second copy.

**Nothing detects the two copies diverging.** So: if you change the spine, the slots, or the
sibling signals, say so to the other repo in the same piece of work. A duplicated file that
does not admit it is duplicated is how two copies silently become two standards.

One cross-check does exist, and it catches this file drifting from the README it describes —
not from the sibling, but it is the only automatic signal available:

```sh
grep -n '^## ' README.md          # must match the spine, minus the slots declared empty
```

## Two constraints invisible from the artifact they constrain

Recorded because a later well-meaning edit would take both out first.

**Features-after-Usage is licensed by the two-line commented Install block.** The argument
for Install-before-Features was that the block makes Install self-sufficient — and that
argument was then conceded, because self-sufficient means Features is *not* urgent and
belongs with the other cost material. The dependency survives the concession: it is what
makes the current order correct, and it is visible from neither section alone.

**The pitch shares a cadence, not its opening clause.** The proposed template was
`<reference-implementation>-faithful <format>`, generalised from odf-crypto's case on the
assumption that slot has an occupant everywhere. It does not. Recorded as a reversal with
the failed reasoning intact, per this repo's convention for plans, because the outcome alone
would not stop someone re-deriving the template.
