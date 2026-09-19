Status: Live procedure — followed and amended, not a dated snapshot (unlike `docs/handoffs/`)

# Releasing msoffice-crypto

The order below is not arbitrary. Two steps constrain everything around them:

- **The public repository must exist before `cargo publish`.** `repository =` in
  `Cargo.toml` is baked into the `.crate` and is what crates.io links to. Publishing first
  and moving the repository afterwards leaves the published version pointing at a dead URL,
  and a published version cannot be edited — only yanked.
- **The truth edits in step 7 must land after publish, not before.** README, `CLAUDE.md`
  and the plan all currently state that the crate is unpublished, and each is *correct*
  until the moment it is not. Editing them early makes the repository lie for the length of
  the release.

---

## 1. Preconditions

All five feature configurations, because a change can be clean in one and broken in
another:

```bash
cargo test   --locked --no-default-features
cargo test   --locked --no-default-features --features crypto-ops
cargo test   --locked --no-default-features --features legacy-binary
cargo test   --locked --no-default-features --features cli
cargo test   --locked --no-default-features --features cli,legacy-binary
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo clippy --locked --all-targets --no-default-features --features crypto-ops -- -D warnings
cargo clippy --locked --all-targets --no-default-features --features legacy-binary -- -D warnings
cargo clippy --locked --all-targets --no-default-features --features cli -- -D warnings
cargo clippy --locked --all-targets --no-default-features --features cli,legacy-binary -- -D warnings
cargo fmt --all --check
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --no-default-features
cargo deny --all-features check licenses advisories bans sources
python tools/audit_claims.py --clones O:/projects-github-clones
```

**`--clones` is the half CI cannot run.** `tools/audit_claims.py` reads the prose back
against the tree — relative links resolve, `file.rs:NNN` citations are in range, backticked
`module::item` paths exist, CLAUDE.md's Layout names every `src/*.rs` and only files that
exist, and the MSRV and version figures agree with `Cargo.toml`. CI runs all of that on
every push. The sixth check verifies every **upstream** `file.ext:NNN` citation against the
clones `CLAUDE.md` § *Provenance* names, and those live outside the repository, so it skips
on a runner and only ever runs here. It is the check worth caring about at release time:
GH #25 found that every `encode.hpp` line number in one module was wrong, and a release is
the last moment a citation into someone else's BSD-3 or MPL-2.0 source can be corrected
before it is published as this crate's justification for what it copied.

**Run them one at a time.** Two concurrent `cargo` invocations against this working
directory produce a spurious build failure on Windows — observed 2026-09-05, where a
background matrix run and a foreground `cargo package` collided and reported
`could not compile msoffice-crypto (example "office_crypto_check")`. The identical command
alone was green. A failure seen while something else was building is not evidence.

CI must be green on the commit being released, not on an ancestor of it.

## 2. The local acceptance gate

CI runs the two independent-implementation legs; Word and LibreOffice need this machine.
**Name a private artifact directory** — every session's `cargo test` writes
`msoffice_crypto_encrypt_ooxml.docx` into the shared system temp directory, so gating
without this can gate another build's file and record the verdict as evidence for yours.
That has actually happened: a gate run measured another build's artifact, and the
verdict was very nearly recorded as evidence for the wrong tree.

```bash
export MSOFFICE_CRYPTO_ARTIFACT_DIR="$(mktemp -d)"
cargo test --locked --no-default-features --features crypto-ops
python tools/acceptance_gate.py "$MSOFFICE_CRYPTO_ARTIFACT_DIR/msoffice_crypto_encrypt_ooxml.docx" \
  --expect-package tests/fixtures/plain.docx --expect-text-file tests/fixtures/plain_content.txt
```

A pass is four `PASS` lines and `GATE: PASS`. Record them in `CHANGELOG.md` against the
SHA-256 the script prints first. Then check `tasklist` for a leaked `WINWORD`, `EXCEL`,
`POWERPNT` or `soffice`: the drivers stop their own, but a hung run cannot.

## 3. Verify the tarball, which is not the repository

The `include` allowlist ships `src/**`, both licences, `NOTICE`, `SECURITY.md` and exactly
two fixtures. Everything else — `tests/*.rs`, `examples/`, the other seventeen fixtures,
`docs/`, `tools/` — is repository-only, on purpose.

```bash
cargo publish --locked --dry-run            # builds AND verifies; not --no-verify
cargo package --locked --list               # read it, do not skim it
```

Then unpack and test what a consumer would actually receive:

```bash
cd target/package/msoffice-crypto-<version>
cargo test --no-default-features
cargo test --no-default-features --features crypto-ops
cargo test --no-default-features --features legacy-binary
```

Measured 2026-09-19 for v0.1.0-rc.3, and **every one must be green**:

| Build | tarball | repository |
| --- | --- | --- |
| detection | 37 passed, 0 failed, **13 ignored** | 50 passed, **0 ignored** |
| `crypto-ops` | 184 passed, 0 failed, **22 ignored** | 215 passed, **0 ignored** |
| `legacy-binary` | 205 passed, 0 failed, **33 ignored** | 257 passed, **0 ignored** |

**Re-measure these at each release rather than trusting them.** They were the 2026-09-05
figures until rc.3 and every one of the six had drifted; nothing machine-checks them. The
totals are not expected to match across the two columns either: `detection` does
(37 + 13 = 50, the same tests with thirteen reported honestly as ignored), but the other two
lose tests outright, because the `tests/*.rs` integration files are not in the `include`
allowlist and so do not exist in the tarball at all.

**The ignored count is a check, not an accident.** `build.rs` sets `cfg(fixture_corpus)`
when it finds any of the seventeen withheld fixtures, and the corpus-dependent tests carry
`#[cfg_attr(not(fixture_corpus), ignore = "…")]`. So:

- **A tarball reporting 0 ignored** means the corpus leaked into the allowlist — check
  `cargo package --list`.
- **A repository run reporting anything but 0 ignored** means the corpus is incomplete, and
  the affected fixture has been deleted or never regenerated.

Read the counts in both directions; each is the other's control. Before this existed the
tarball reported 30 *failures* and the release notes had to explain them away.

The doc tests matter separately and are included above: the two shipped fixtures are pulled
in with `include_bytes!` (`src/classify.rs`), so an allowlist mistake that drops them is a
**compile error** rather than a skipped test — which is what makes this step catch something
that reading `cargo package --list` does not.

Confirm by eye that `LICENSE-MIT`, `LICENSE-APACHE` and `NOTICE` are present. Both licences
require the text to travel with the copy (MIT's notice clause, Apache-2.0 §4(a)), and
neither is auto-included, because that happens only for `license-file` and this crate uses
an SPDX expression.

## 4. Decide the version

`0.1.0-rc.1` is a pre-release, and **Cargo does not match a pre-release from an ordinary
requirement**: `msoffice-crypto = "0.1"` will not resolve to it, and `cargo add
msoffice-crypto` reports no matching version. A consumer must name the full string.

That is the right shape while the API is still free to move — the downstream consumer has
not yet re-enabled its Office handler against it, and until it has, nobody has used this API
in anger. Publishing `0.1.0` makes the API a promise on the day it lands.

Recommended: publish `0.1.0-rc.1` as the tree stands, let the consumer's re-enable exercise it,
then cut `0.1.0`. Both are cheap; only the second is irreversible.

## 5. The repository transition

Owned by the maintainer, not scripted here. Two facts from the 2026-09-05 survey that the
sequencing depends on:

- **The working tree is clean of identifying metadata; the history is not.**
  `tests/fixture_identity.rs` holds the invariant for the tree. History still carries the
  pre-scrub fixture blobs: six commits, ten Office-written fixtures. Verified by extracting
  `f5c2d6d:tests/fixtures/word97_plain.doc` and comparing it against `HEAD`'s.
- **A `--replace-text` scrub would not be sufficient, and `fixture_identity.rs` explains
  why.** In three of the ten the name sits in `docProps/core.xml`, deflated inside the
  encrypted package. Byte replacement cannot see compressed content any more than `grep -r`
  can — the same trap that makes a raw scan of `tests/fixtures/` report those three as
  clean. A scrub in place needs a per-path `--blob-callback` swapping each old blob for
  today's; a fresh history sidesteps it.

History also carries commit trailers and an author address that the working tree does not.

Whatever route is taken, the public repository must be at the URL in `Cargo.toml`'s
`repository` field before step 6, or that field must be updated first.

Three pieces of repository metadata are empty and are the first thing a visitor sees; the
crate's own `description` in `Cargo.toml` is already written and is the obvious source:

```bash
gh repo edit --description "Microsoft Office document encryption per MS-OFFCRYPTO: detect, decrypt and encrypt, with key material that zeroizes on drop"
gh repo edit --add-topic rust --add-topic cryptography --add-topic ooxml --add-topic ecma-376 --add-topic ms-offcrypto
```

**Private vulnerability reporting cannot be enabled yet, and that is not an oversight.** It
is a public-repository feature: on a private repo the API returns
`404 Not Found` for `PUT /repos/{owner}/{repo}/private-vulnerability-reporting`, and the
Settings toggle is absent. So it belongs to step 8, after the flip — but it is listed here
too because `SECURITY.md` names it as the **only** reporting channel, and between going
public and enabling it the policy points at a button that does not exist.

`gh repo view --json description,repositoryTopics,homepageUrl` reads the current state back.

## 5a. Date the heading and tag the commit

Until 2026-09-10 this runbook went from the tarball straight to `cargo publish` and never
mentioned a tag. That is a real gap for a crate arguing its claims are checkable: the
`.crate` on crates.io is immutable, but without a tag a consumer holding `0.1.0-rc.1` has no
ref to check out and re-run the suite against.

Per `.claude/skills/changelog-protocol/SKILL.md`, the date **is** the release marker:

```bash
# 1. substitute the ISO date for "unreleased" in CHANGELOG.md's top heading, and commit
# 2. tag that commit, annotated -- lightweight tags are not pushed by --follow-tags
git tag -a v0.1.0-rc.1 -m "v0.1.0-rc.1"
git push --follow-tags
```

Between dating the heading and pushing the tag the tree fails its own check G
(`dated heading with no tag`). `--follow-tags` sends both refs in one push and closes that
window; push the tag first if you want certainty rather than reasoning.

**Moving a tag is a separate command and the failure is silent.** `--follow-tags` pushes only
tags *missing* from the remote — it will not move one, and reports `Everything up-to-date`
while the remote quietly keeps the old commit. To move one: `git push -f origin vX.Y.Z`, by
name. Never `git push --tags`, which publishes every local tag including scratch markers.

## 6. Publish

```bash
cargo publish --locked
```

Then, from a scratch directory:

```bash
cargo new --bin mc-smoke && cd mc-smoke
cargo add msoffice-crypto@<exact version> --features crypto-ops
cargo build --locked
```

An exact version, because of the pre-release rule in step 4. This is what proves the crate
resolves from the registry rather than from this working copy.

## 7. Truth edits, after publish

Each of these is a true statement today that publishing falsifies. Grep before editing —
the list is what was there on 2026-09-05 and may have moved:

```bash
git grep -n -iE 'unpublished|never been published|repo is (currently )?private|not published|no version to backport|pre-release'
```

| File | What changes |
| --- | --- |
| `README.md` | `> **Status: early, unpublished.**`, and the version in the `[dependencies]` snippet. |
| `CLAUDE.md` | The whole *Project Status — pre-release, nothing published* section, which instructs its own revision at exactly this point. "Breaking API changes are free" stops being true; say what replaces it. |
| `docs/plans/msoffice-crypto-foundation-2026-09-04.md` | §S8's "Blocked on: the repo is currently private", §7's path-dependency paragraph, and the `Status:` line at the top → `Shipped (<date>)` with the landing commit. |
| `docs/handoffs/2026-09-05-cold-start.md` | The `⬜ #9` row. Handoffs are dated snapshots — if it reads as historical, leave it; if it reads as current state, it needs a superseding note rather than an edit. |
| `CHANGELOG.md` | A `v0.1.0-rc.1` version heading goes on top; the dated record stays beneath it **as written**. A release heading summarising the dated entries would lose the reasoning, which is the whole reason they are dated. |
| `Cargo.toml` | Bump `version` for the next cycle. |

Close GH #9 with the evidence from steps 3 and 6, then GH #1 once its last slice is closed.

## 8. Go public, and turn on private vulnerability reporting

The flip is its own step because something depends on it that cannot be done sooner.

```bash
gh repo edit --visibility public --accept-visibility-change-consequences
gh api --method PUT repos/<owner>/msoffice-crypto/private-vulnerability-reporting
gh api repos/<owner>/msoffice-crypto --jq .security_and_analysis   # read it back
```

**Enable reporting immediately after the flip, in the same sitting.** `SECURITY.md` names
GitHub's private advisory flow as the *only* channel — deliberately, so that no address has
to be published or kept working — and the feature exists only on public repositories. On a
private repo the API answers `404 Not Found` and the Settings toggle is absent, so the
window between going public and enabling it is a window in which the security policy points
at a button that is not there.

**Point CI back at hosted runners, and remove the self-hosted one.** *Done on
2026-09-11, at the flip; kept here because it is the one step whose omission is silent.*

```bash
gh variable delete CI_RUNNER
gh api repos/<owner>/msoffice-crypto/actions/runners --jq '.total_count'   # must be 0
```

`msoc-linux` was registered on 2026-09-11 only because a private repository consumes
Actions minutes and the account had hit its spending limit. Public repositories get
unlimited hosted minutes, so the reason ended there -- and GitHub advises against
self-hosted runners on public repositories, because a pull request from a fork can execute
arbitrary code on the runner host. That host is a workstation holding this repository and
others.

Deleting the variable was not treated as sufficient. `ci.yml` had `runs-on:
${{ vars.CI_RUNNER || 'ubuntu-latest' }}` in all twelve jobs, which on a *public*
repository is a latent hazard rather than a convenience: one settings change redirects
every job onto a self-hosted host, and nothing about it appears in a diff. All twelve are
now hard-coded to `ubuntu-latest`, so reintroducing the indirection is a workflow edit
somebody can review. The runner was also deregistered from the repository, not merely
stopped -- an offline runner is a registration waiting for a host to come back.

Also uninstall the service on that host; deregistering here does not stop it running
there.

**Re-enable the CI workflow.** It was disabled by hand on 2026-09-10
(`state: disabled_manually`) because a private repository consumes Actions minutes, the
account hit its spending limit, and every job began failing before it ran a single step --
sixteen red entries that said nothing about the code. A permanently red board trains people
to stop reading it, so switching it off was right; leaving it off after the flip would be a
silent loss of the entire gate.

```bash
gh workflow enable ci.yml
gh api repos/<owner>/msoffice-crypto/actions/workflows --jq '.workflows[] | "\(.name): \(.state)"'
```

Public repositories get unlimited standard-runner minutes, so the condition that forced the
disable disappears at the flip. Re-run the matrix once from the Actions tab and confirm all
sixteen jobs are green before trusting the board again.

Two more things that only make sense once the repository is public:

- **`homepage`** can point at the rendered documentation, which exists only after
  `cargo publish` has run: `gh repo edit --homepage https://docs.rs/msoffice-crypto`.
- **Branch protection on `main`**, if wanted. Everything in this repository was assembled
  by direct commits; from here on the CI matrix is the gate, and requiring it on a pull
  request is what makes that gate binding rather than advisory.

Check the flip did what you meant with `gh repo view --json visibility`. Going public is
not reversible in the way that matters: anything already pushed is public from that moment,
and un-publishing a repository does not un-publish what people already fetched.

## 9. If something is wrong after publishing

`cargo yank --version <v>` stops new dependants resolving it; it does **not** remove the
files, and anything with it already in a lockfile keeps building. There is no unpublish.
That is why step 3 unpacks and tests the tarball rather than trusting the allowlist, and
why step 6 resolves from the registry rather than from here.
