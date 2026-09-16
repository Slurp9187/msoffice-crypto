#!/usr/bin/env python3
"""Read the project's prose back against the tree.

GH #25 did this for the **rustdoc** and corrected 58 claims. Its scope stopped at `src/`,
so `README.md`, `CLAUDE.md`, `docs/**` and the comment blocks in `Cargo.toml`, `deny.toml`
and `ci.yml` had never been checked — which is where a dead link in the plan's *provenance*
section had been sitting since 2026-09-04, surviving that whole audit.

Lints check shape, not truth. This checks the truths a machine can reach:

  A  relative links in Markdown resolve to a file that exists
  B  `file.rs:NNN` citations name a real source file with at least NNN lines
  C  backticked `module::item` paths name something findable in `src/`
  D  CLAUDE.md's Layout block names every `src/*.rs`, and only files that exist
  E  version and MSRV figures in the live documents agree with `Cargo.toml`
  F  upstream `file.ext:NNN` citations resolve against the local clones  (local only)
  G  CHANGELOG.md's top version heading matches Cargo.toml, and is dated iff tagged

Exit status is 1 if anything is flagged, 0 otherwise.

    python tools/audit_claims.py                 # A-E, plus F if the clones are present
    python tools/audit_claims.py --clones DIR    # point F at a different clone root

**F is skipped, not failed, when the clones are absent**, so CI can run this unchanged.
The clones live outside the repository (`CLAUDE.md` § *Provenance* names the paths) and no
CI runner has them.

# What is deliberately NOT checked, and why

**Prose in dated snapshots is exempt from E.** `docs/handoffs/` is "a dated snapshot, not a
live document" by CLAUDE.md's own definition, and `docs/plans/` carries cross-crate
comparison tables — `aescrypt-rs` at MSRV 1.70, `office_oxide` at 1.88 — which are correct
statements about *other* crates and which a naive version check reports as disagreements.
Those two directories are still checked for dead links and bad citations, because a dead
link is dead whenever it was written.

**This cannot tell a stale claim from a differently worded one.** It is a floor, not a
substitute for reading. The 2026-09-05 run flagged 12 things of which 3 were real.
"""

import argparse
import collections
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Documents whose *factual* claims are live and must track the tree.
LIVE_DOCS = ["README.md", "CLAUDE.md", "SECURITY.md", "docs/RELEASING.md"]

# Everything the link and citation checks read. Dated snapshots are included here and
# excluded from the version check -- see the module docstring.
ALL_DOCS = LIVE_DOCS + [
    "Cargo.toml",
    "deny.toml",
    "build.rs",
    ".github/workflows/ci.yml",
    "docs/design/development-record.md",
    "docs/plan-workflow.md",
    "docs/design/msoffice-crypto-format-history.md",
]

DEFAULT_CLONES = pathlib.Path("O:/projects-github-clones")

UPSTREAM_EXTS = {".hpp", ".cpp", ".cxx", ".hxx", ".py", ".go", ".h"}

# Never walked: build output and version-control metadata, in this repository and in
# the clones alike. `target/` alone is hundreds of thousands of files.
PRUNE_DIRS = {"target", "target-msrv", ".git", "node_modules", ".venv", "__pycache__"}


def docs():
    seen = []
    for name in ALL_DOCS:
        p = ROOT / name
        if p.exists():
            seen.append(p)
    for p in sorted(ROOT.glob("docs/**/*.md")):
        if p not in seen:
            seen.append(p)
    return seen


def read(p):
    return p.read_text(encoding="utf-8", errors="replace")


def line_of(txt, pos):
    return txt[:pos].count("\n") + 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--clones", type=pathlib.Path, default=DEFAULT_CLONES, nargs="?",
                    help="root holding the upstream clones (check F); pass a nonexistent "
                         "path to skip it, as CI does")
    args = ap.parse_args()

    src = sorted(ROOT.glob("src/**/*.rs"))
    src_names = {p.name for p in src}
    src_text = {p.name: read(p) for p in src}
    all_src = "\n".join(src_text.values())
    found = collections.defaultdict(list)
    DOCS = docs()

    def flag(kind, msg):
        found[kind].append(msg)

    # ---- A: relative markdown links --------------------------------------------------
    link = re.compile(r"\[[^\]]*\]\(([^)#\s]+)(?:#[^)]*)?\)")
    for p in DOCS:
        if p.suffix != ".md":
            continue
        txt = read(p)
        for m in link.finditer(txt):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            if not (p.parent / target).exists():
                flag("A dead relative link",
                     f"{p.relative_to(ROOT).as_posix()}:{line_of(txt, m.start())} -> {target}")

    # ---- B: internal citations -------------------------------------------------------
    # Not only `.rs`. This repository's own tools get cited as `acceptance_gate.py:84` and
    # `audit_claims.py:59`, and until 2026-09-10 check F treated every `.py` citation as
    # upstream and reported both as missing from the clones -- a false positive the
    # pre-publish audit's own report triggered. A citation is INTERNAL when a file of that
    # name exists in the tree; only what is left goes to F.
    local_files = {}
    for d in ("src", "tools", "tests", "examples", "."):
        for q in pathlib.Path(d).glob("*"):
            if q.is_file():
                local_files.setdefault(q.name, q)

    cite = re.compile(r"\b([A-Za-z0-9_./-]+\.(?:rs|py|ps1)):(\d+)")
    for p in DOCS:
        txt = read(p)
        for m in cite.finditer(txt):
            base = pathlib.Path(m.group(1)).name
            if base not in local_files:
                continue
            n = read(local_files[base]).count("\n") + 1
            if int(m.group(2)) > n:
                flag("B citation past end of file",
                     f"{p.relative_to(ROOT).as_posix()}:{line_of(txt, m.start())} -> "
                     f"{m.group(1)}:{m.group(2)} but {base} has {n} lines")

    # ---- C: backticked module::item --------------------------------------------------
    item = re.compile(r"`([a-z_][a-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)`")
    external = {"std", "core", "alloc", "cargo", "rand", "cfb", "quick_xml", "secure_gate",
                "office_crypto", "msoffcrypto", "clippy", "rustdoc", "self", "crate", "super",
                "comphelper", "zip", "chacha20"}
    for p in DOCS:
        txt = read(p)
        for m in item.finditer(txt):
            mod, name = m.group(1), m.group(2)
            if mod in external:
                continue
            if f"{mod}.rs" not in src_names and f"{mod}_tests.rs" not in src_names:
                continue
            if re.search(r"\b" + re.escape(name) + r"\b", all_src):
                continue
            flag("C identifier not found in src/",
                 f"{p.relative_to(ROOT).as_posix()}:{line_of(txt, m.start())} -> {mod}::{name}")

    # ---- D: CLAUDE.md Layout block ---------------------------------------------------
    claude = read(ROOT / "CLAUDE.md")
    blocks = re.findall(r"```\n(.*?)```", claude, re.S)
    layout = next((b for b in blocks if "src/lib.rs" in b), None)
    if layout is None:
        flag("D layout block", "could not locate the Layout code block in CLAUDE.md")
    else:
        # Named anywhere in the block, including the "(+ foo_tests.rs)" sibling notation.
        named = set(re.findall(r"[A-Za-z0-9_./-]+\.(?:rs|toml|yml|md)", layout))
        named_bases = {pathlib.Path(n).name for n in named}
        for p in src:
            if p.name not in named_bases:
                flag("D src file missing from the Layout index", p.name)
        # Resolve by searching the repository rather than a fixed list of directories:
        # the Layout names files under `docs/plans/` and `.github/workflows/` as well as
        # the obvious three, and a hardcoded list is one more claim that can go stale.
        #
        # `os.walk` with pruning, not `rglob`: `target/` holds hundreds of thousands of
        # build artefacts and filtering them *after* the walk means paying for them anyway.
        present = set()
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS]
            present.update(filenames)
        for n in sorted(named):
            if pathlib.Path(n).name in present or (ROOT / n).exists():
                continue
            flag("D Layout names a file that does not exist", n)

    # ---- E: versions, live documents only --------------------------------------------
    cargo = read(ROOT / "Cargo.toml")
    msrv = re.search(r'^rust-version = "([^"]+)"', cargo, re.M).group(1)
    pkg = re.search(r'^version = "([^"]+)"', cargo, re.M).group(1)
    # `src/lib.rs` is checked here but is not a LIVE_DOCS member: that list also feeds
    # ALL_DOCS, whose link and citation checks expect Markdown. The crate-level docs carry
    # the same two `msoffice-crypto = { version = "..." }` snippets README.md does, they are
    # what renders on docs.rs, and they are what a reader copies. They drifted to rc.1 while
    # README was bumped to rc.2 -- invisible to this check until the version literal was
    # looked for by hand while cutting the tag.
    for name in LIVE_DOCS + ["src/lib.rs"]:
        p = ROOT / name
        if not p.exists():
            continue
        txt = read(p)
        for m in re.finditer(r"MSRV (\d+\.\d+)", txt):
            if m.group(1) != msrv:
                flag("E MSRV disagrees with Cargo.toml",
                     f"{name}:{line_of(txt, m.start())} says {m.group(1)}, Cargo.toml says {msrv}")
        for m in re.finditer(r'msoffice-crypto = \{ version = "([^"]+)"', txt):
            if m.group(1) != pkg:
                flag("E package version disagrees with Cargo.toml",
                     f"{name}:{line_of(txt, m.start())} says {m.group(1)}, Cargo.toml says {pkg}")

    # ---- F: upstream citations, only when the clones are here ------------------------
    clones = args.clones
    if clones is not None and clones.exists():
        up = re.compile(r"\b([A-Za-z0-9_]+\.(?:hpp|cpp|cxx|hxx|py|go|h)):(\d+)(?:-(\d+))?")

        # Collect the basenames actually cited *first*, then walk once looking only for
        # those. The clone root is ~260,000 files (LibreOffice core is most of it), and
        # indexing every source file in it to check a dozen citations is the difference
        # between one second and twenty.
        wanted = set()
        for p in DOCS:
            for m in up.finditer(read(p)):
                wanted.add(m.group(1))

        index = collections.defaultdict(list)
        for dirpath, dirnames, filenames in os.walk(clones):
            dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS]
            for fn in filenames:
                if fn in wanted:
                    index[fn].append(pathlib.Path(dirpath) / fn)
        checked = 0
        for p in DOCS:
            txt = read(p)
            for m in up.finditer(txt):
                name = m.group(1)
                if name in local_files:
                    continue  # this repository's own file; check B range-checked it
                hi = int(m.group(3) or m.group(2))
                cands = index.get(name, [])
                where = f"{p.relative_to(ROOT).as_posix()}:{line_of(txt, m.start())}"
                if not cands:
                    flag("F upstream file not found in the clones", f"{where} -> {name}")
                    continue
                checked += 1
                if not any(hi <= sum(1 for _ in c.open(encoding="utf-8", errors="replace"))
                           for c in cands):
                    flag("F upstream citation past end of file",
                         f"{where} -> {name}:{m.group(2)} (no candidate is that long)")
        print(f"check F: {checked} upstream citations verified against {clones}")
    else:
        print(f"check F: SKIPPED, no clones at {clones} "
              f"(expected on CI; CLAUDE.md § Provenance names the paths)")

    # ---- G: the changelog's top heading -----------------------------------------------
    # `.claude/skills/changelog-protocol/SKILL.md` is the rule; this is the enforcement.
    # Only the NEWEST section: historical ones are frozen, and failures nobody can act on
    # are how a whole check gets switched off.
    changelog = ROOT / "CHANGELOG.md"
    if changelog.exists():
        txt = read(changelog)
        head = re.search(r"^## +(\S+?) +[-\u2014] +(.+?)\s*$", txt, re.M)
        if head is None:
            flag("G changelog has no version heading",
                 "CHANGELOG.md: expected a top heading like '## vX.Y.Z - unreleased'")
        else:
            heading_ver, marker = head.group(1), head.group(2).strip()
            want = "v" + pkg

            # Invariant 1: the top heading names the manifest version.
            if heading_ver != want:
                flag("G top heading disagrees with Cargo.toml",
                     f"CHANGELOG.md:{line_of(txt, head.start())} says {heading_ver}, "
                     f"Cargo.toml says {pkg} (expected {want})")

            # Invariant 2: dated if and only if the tag exists.
            tags = set()
            try:
                import subprocess
                tags = set(subprocess.run(["git", "tag", "-l"], cwd=ROOT, capture_output=True,
                                          text=True, timeout=30).stdout.split())
            except Exception as exc:  # noqa: BLE001 - a missing git is not a claim failure
                print(f"check G: could not list tags ({exc}); tag half skipped")
                tags = None

            dated = bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", marker))
            if tags is not None:
                tagged = heading_ver in tags
                if dated and not tagged:
                    flag("G dated heading with no tag",
                         f"CHANGELOG.md:{line_of(txt, head.start())} is dated {marker} but "
                         f"tag {heading_ver} does not exist -- the date IS the release marker")
                if tagged and not dated:
                    flag("G tagged version still marked unreleased",
                         f"CHANGELOG.md:{line_of(txt, head.start())} says '{marker}' but "
                         f"tag {heading_ver} exists; date it")
            if not dated and marker != "unreleased":
                flag("G heading marker is neither a date nor 'unreleased'",
                     f"CHANGELOG.md:{line_of(txt, head.start())} -> {marker!r}")

    # ---- report ----------------------------------------------------------------------
    print(f"audited {len(DOCS)} documents against {len(src)} source files")
    total = 0
    for kind in sorted(found):
        print(f"\n== {kind}  ({len(found[kind])})")
        for msg in found[kind]:
            print(f"   {msg}")
            total += 1
    if total:
        print(f"\nFAIL: {total} claim(s) do not match the tree")
        return 1
    print("\nOK: every checked claim matches the tree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
