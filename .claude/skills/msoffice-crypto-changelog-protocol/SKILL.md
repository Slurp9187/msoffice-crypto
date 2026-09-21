---
name: msoffice-crypto-changelog-protocol
description: Keep CHANGELOG.md honest by making the release date a verifiable claim rather than a typed one. Use when adding a changelog entry, cutting a release, bumping the version in Cargo.toml, tagging, or when a version heading looks out of step with the manifest or the tags.
---

# Changelog protocol

A changelog is a set of claims about what shipped and when. This protocol keeps each claim
checkable, because the failure mode is silent: a section reading `## v0.1.0 — 2026-09-10`
when `v0.1.0` was never tagged looks released forever and nothing complains.

Adapted from the same protocol in a sibling project. The invariants are theirs; the examples
and the enforcement below are this repository's.

## The two invariants

**1. The top version heading matches `Cargo.toml`'s `version`.** Exact string, `-rc.N`
suffix included.

**2. A version heading carries a date if and only if that tag exists.**

```
## v0.1.0-rc.1 — unreleased      while the work is in flight
## v0.1.0-rc.1 — 2026-09-10      the moment v0.1.0-rc.1 is tagged
```

One separator, two possible values. **The date is the release marker.** It is not decoration,
and it is not the date the work happened.

## Why this repository in particular

Because it has already been bitten, twice, by hand-typed dates:

- Five entries were stamped `2026-09-06` while every commit they described was `2026-09-05`
  local. They had been dated in UTC on a UTC-7 machine. A changelog dated in the future is a
  defect, and nothing caught it but a person reading carefully.
- A later entry was written on one local date and committed after midnight on the next, so
  it had to be re-dated by hand to match its own commit.

Under invariant 2 neither is possible: entries carry no date at all, and the one date in the
file is written when the tag is cut.

## Dates in entries: bookkeeping versus evidence

**Do not date an entry as bookkeeping.** Git records when a change landed, precisely and
without drift. A typed date is a lossy copy that can go wrong, costs a decision per entry,
and answers a question no reader asks. They ask *"what changed between the version I have and
the one I am considering?"* — and a date between releases does not help.

**Do date an entry when the date is part of the claim.** The test:

> Does the reader need the date to know how **stale an observation** is?

If yes it belongs in the entry, because git dates the commit, not the measurement. This
matters more here than in most crates: the Evidence section is the backing for the README's
"checkable rather than assertable" argument, and every figure in it is a measurement taken
against particular versions of four external readers.

```markdown
<!-- KEEP — the date bounds the evidence -->
- Gate run against artifact SHA-256 `c279812c…de9c`: Word 16.0.19127, LibreOffice 26.2.1.2,
  msoffcrypto-tool 6.0.0, office-crypto 0.3 — all PASS, 2026-09-10.
- Tarball measured 2026-09-10: 20/156/175 passing, 10/19/30 ignored.

<!-- DROP — git already knows -->
- Renamed the error type (2026-09-10).
```

A reader six months from now needs to know the gate verdict was against *that* Word build. It
does not need to know which afternoon a rename happened.

## The release flow

1. **Open a line.** Bump `version` in `Cargo.toml`; add `## vX.Y.Z — unreleased` at the top
   of `CHANGELOG.md`.
2. **Accumulate.** Entries go under that heading. No dates unless the date is evidence.
3. **Cut.** Replace `— unreleased` with the ISO date, commit, then tag *that* commit.
4. **Repeat.** The next bump opens a new section. Never leave a standing empty one.

Pre-releases work identically: `## v0.1.0-rc.2 — unreleased` opens after `v0.1.0-rc.1` is
tagged and dated.

**No standing `## [Unreleased]` section.** The versioned-but-undated section *is* the
unreleased one. Keeping both leaves a reader unable to tell which section describes the code
they have — the exact ambiguity this protocol removes. This crate always knows its next
version, so it always names it.

## Tags

**This repository is tagged at every published version**, and also at `v0.1.0-rc.1`, which
was tagged before the decision not to publish it. `docs/RELEASING.md` gained its tagging
step at the same time as this skill. The reason a tag matters here is narrower than
convention: the crate argues its claims are checkable, and without a tag a consumer holding a
published version from crates.io has no ref to check out and re-run the suite against. The
`.crate` is immutable; the tag is what ties it to a tree.

Use an **annotated** tag, and push the branch and tag together:

```sh
git tag -a v0.1.0-rc.1 -m "v0.1.0-rc.1"
git push --follow-tags
```

`--follow-tags` pushes the branch plus annotated tags reachable from those commits that are
missing on the remote. It does not push lightweight tags, and it does not push unrelated
local ones.

### The trap: moving a tag

`--follow-tags` only pushes tags **missing** from the remote. It will not move one that
already exists — it reports `Everything up-to-date` while the remote silently keeps the old
commit. **A no-op reported as success is the worst shape a failure takes**, and it is the
same shape as the `build.rs` include defect the pre-publish audit found: correct operation and
total absence, indistinguishable from outside.

Moving a tag is always by name:

```sh
git push -f origin v0.1.0-rc.1
```

### Do not

- **`git push --tags`** without auditing first. It publishes *every* local tag, including
  scratch markers. Check what would go:

  ```sh
  comm -23 <(git tag -l | sort) \
           <(git ls-remote --tags origin | grep -v '\^{}' | sed 's|.*refs/tags/||' | sort)
  ```

- Assume `--tags` also pushes the branch. It does not.
- Reach for `gh release create` merely to push a tag, unless a GitHub Release is wanted.

## The archived record is exempt, and that is deliberate

This crate's pre-publication changelog was 3,397 lines of dated entries, newest first — the
opposite of what this protocol says. It stayed with the archived development repository when
this one was rebuilt, and `CHANGELOG.md` here starts at the first release.

That archive is **not** a violation to be tidied. It was the right artifact while the work was
happening and it is frozen where it sits; `docs/design/development-record.md` carries the
decisions forward. This protocol governs what is written from here on, not what was written
before.

## Enforcement

Both invariants are check **G** in `tools/audit_claims.py`, which the `prose` CI job runs on
every push. It is one tool rather than a second script on purpose: check E already parses
`Cargo.toml`'s version, and this repository's house style is one checker whose every check has
been proved by mutation.

It inspects **only the newest section**. Historical sections are frozen and old projects
accumulate legitimate oddities; failures nobody can act on get the whole check disabled. The
newest section is where the error actually happens, because it is the one being edited.

**Tags must be fetched in CI.** `actions/checkout` does not fetch them by default, and without
them every dated heading looks untagged:

```yaml
- uses: actions/checkout@v7
  with:
    fetch-depth: 0        # or: fetch-tags: true
```

There is a window, between dating a heading and pushing the tag, where the tree fails its own
check. `--follow-tags` sends both refs in one push and closes it. If you want certainty rather
than reasoning, push the tag first and the branch second.
