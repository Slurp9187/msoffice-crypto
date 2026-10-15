#!/usr/bin/env python3
"""Measure the test counts the docs state, and fail if the docs are wrong (GH #21).

`docs/RELEASING.md` § 3 carries a table of how many tests pass and how many are ignored in
each feature configuration, in the repository and in the published tarball, and `CLAUDE.md`
names the number of corpus-dependent tests. They are prose that looks like data: during the
rc.3 cut all six figures in that table had drifted, and by rc.7 they had drifted again,
because nothing read them back. `tools/audit_claims.py` reads files; this one runs the
suite, which is why it is a script and a CI job of its own rather than a check in there.

What it does, in the runbook's order (§ 3 documents each step and the cycle each one cost):

  1. run `cargo test --locked --no-default-features [--features F]` in the repository for
     every configuration the table names;
  2. `cargo package --locked --no-verify` -- not `--dry-run`, which leaves no `.crate` --
     and find the artifact under `CARGO_TARGET_DIR`, not an assumed `target/`;
  3. extract it into a fresh short directory (Windows build scripts fail `LNK1104` past
     `MAX_PATH`), with the tarball's own short `CARGO_TARGET_DIR`, and **assert it is the
     tarball** -- no `docs/`, no `tools/` -- before believing a single number from it;
  4. run the same configurations there;
  5. compare every figure with the table, and the table's all-features `ignored` count with
     every place `CLAUDE.md` states it.

On a mismatch it prints the table as measured, ready to paste, and exits 1.

    python tools/check_test_counts.py            # measure and compare
    python tools/check_test_counts.py --keep     # leave the extracted tarball for a look

**The table is Linux's**, because CI is: a few tests are platform-gated (the CLI's kill test
runs on Linux and Windows, its interrupt fallback only off Windows), so `passed` differs by
platform. Off Linux this compares the `ignored` figures and the invariants, and says that it
skipped the `passed` ones -- an announced skip, never a silent pass.

**The counts are moving figures; the two-way read is the invariant.** 0 ignored in the
repository and the corpus count ignored in the tarball is what actually guards the
`include` allowlist (`CLAUDE.md` § *Testing Rules*), and this script asserts that shape as
well as the numbers, so that "update the table" can never be the answer to a leaked corpus.
"""
import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
RELEASING = ROOT / "docs" / "RELEASING.md"
CLAUDE = ROOT / "CLAUDE.md"

# The table's row labels, mapped to the features each one tests. The row label is what the
# table prints; the features are what cargo is given. `detection` is no features at all.
CONFIGS = {
    "detection": None,
    "`crypto-ops`": "crypto-ops",
    "`legacy-binary`": "legacy-binary",
    "`cli,legacy-binary`": "cli,legacy-binary",
}

# The row whose tarball `ignored` figure is the corpus count CLAUDE.md states: every
# feature on, so every corpus-dependent test is compiled and reported.
CORPUS_ROW = "`cli,legacy-binary`"

ROW = re.compile(
    r"^\|\s*(?P<build>[^|]+?)\s*\|"
    r"\s*(?P<tp>\d+) passed, (?P<tf>\d+) failed, \*\*(?P<ti>\d+) ignored\*\*\s*\|"
    r"\s*(?P<rp>\d+) passed, \*\*(?P<ri>\d+) ignored\*\*\s*\|\s*$",
    re.M,
)
RESULT = re.compile(r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored")

# Every place CLAUDE.md states the corpus count. All of them must agree with the table.
CLAUDE_CORPUS = [
    re.compile(r"the (\d+) corpus-dependent tests"),
    re.compile(r"this repository runs all (\d+)"),
    re.compile(r"unpacked `\.crate` as (\d+) ignored"),
]


def run_tests(cwd, features, env):
    """(passed, failed, ignored) summed over every test binary and the doctests."""
    cmd = ["cargo", "test", "--locked", "--no-default-features"]
    if features:
        cmd += ["--features", features]
    cmd += ["--", "--test-threads", "2"]
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    totals = [0, 0, 0]
    for m in RESULT.finditer(out):
        for i in range(3):
            totals[i] += int(m.group(i + 1))
    if proc.returncode != 0 or not RESULT.search(out):
        tail = "\n".join(out.splitlines()[-30:])
        sys.exit(f"cargo test failed in {cwd} with features {features!r}:\n{tail}")
    return tuple(totals)


def claimed_table():
    txt = RELEASING.read_text(encoding="utf-8")
    rows = {m.group("build"): m for m in ROW.finditer(txt)}
    missing = [label for label in CONFIGS if label not in rows]
    if missing:
        sys.exit(f"docs/RELEASING.md § 3: no table row for {', '.join(missing)}")
    return {
        label: {
            "tarball": tuple(int(rows[label].group(k)) for k in ("tp", "tf", "ti")),
            "repo": (int(rows[label].group("rp")), 0, int(rows[label].group("ri"))),
        }
        for label in CONFIGS
    }


def claimed_corpus():
    txt = CLAUDE.read_text(encoding="utf-8")
    found = []
    for pat in CLAUDE_CORPUS:
        m = pat.search(txt)
        if not m:
            sys.exit(f"CLAUDE.md no longer states the corpus count as {pat.pattern!r}; "
                     "update CLAUDE_CORPUS in this script with the new wording")
        found.append(int(m.group(1)))
    return found


def build_tarball(env):
    """Package, find the `.crate`, extract it fresh, and prove it is the tarball."""
    version = re.search(r'^version = "([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M).group(1)
    subprocess.run(["cargo", "package", "--locked", "--no-verify", "--allow-dirty"],
                   cwd=ROOT, env=env, check=True, capture_output=True)
    target = pathlib.Path(env.get("CARGO_TARGET_DIR") or ROOT / "target")
    crate = target / "package" / f"msoffice-crypto-{version}.crate"
    if not crate.is_file():
        sys.exit(f"cargo package wrote no {crate}")
    # Short on purpose: Windows build scripts inside the tarball fail LNK1104 past MAX_PATH.
    base = pathlib.Path(tempfile.mkdtemp(prefix="mct"))
    with tarfile.open(crate) as tar:
        tar.extractall(base, filter="data")
    tree = base / f"msoffice-crypto-{version}"
    if not (tree / "Cargo.toml").is_file() or (tree / "docs").exists() or (tree / "tools").exists():
        sys.exit(f"{tree} is not the tarball: refusing to believe numbers measured there")
    return base, tree


def table(measured):
    lines = ["| Build | tarball | repository |", "| --- | --- | --- |"]
    for label in CONFIGS:
        tp, tf, ti = measured[label]["tarball"]
        rp, _, ri = measured[label]["repo"]
        lines.append(f"| {label} | {tp} passed, {tf} failed, **{ti} ignored** "
                     f"| {rp} passed, **{ri} ignored** |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keep", action="store_true", help="keep the extracted tarball")
    args = ap.parse_args()

    claims = claimed_table()
    corpus_claims = claimed_corpus()

    env = dict(os.environ)
    # Every test that writes an encrypt artifact writes it here, not into shared temp,
    # where another build's run could overwrite it (CLAUDE.md § Build and verify).
    artifacts = tempfile.mkdtemp(prefix="mca")
    env["MSOFFICE_CRYPTO_ARTIFACT_DIR"] = artifacts

    measured = {label: {} for label in CONFIGS}
    for label, features in CONFIGS.items():
        measured[label]["repo"] = run_tests(ROOT, features, env)
        print(f"repository {label}: {measured[label]['repo']}", flush=True)

    base, tree = build_tarball(env)
    tar_env = dict(env)
    tar_env["CARGO_TARGET_DIR"] = str(base / "t")
    try:
        for label, features in CONFIGS.items():
            measured[label]["tarball"] = run_tests(tree, features, tar_env)
            print(f"tarball    {label}: {measured[label]['tarball']}", flush=True)
    finally:
        if not args.keep:
            shutil.rmtree(base, ignore_errors=True)
        shutil.rmtree(artifacts, ignore_errors=True)

    problems = []
    on_linux = sys.platform.startswith("linux")
    if not on_linux:
        print(f"\nNOTE: on {sys.platform}, so `passed` is not compared -- the table is Linux's "
              "(CI's) and a few tests are platform-gated. `ignored`, `failed` and the "
              "invariants are compared as usual.")
    for label in CONFIGS:
        for where in ("repo", "tarball"):
            got, want = measured[label][where], claims[label][where]
            fields = "(passed, failed, ignored)"
            if not on_linux:
                got, want, fields = got[1:], want[1:], "(failed, ignored)"
            if got != want:
                problems.append(f"{label} {where}: the table says {want}, measured {got} "
                                f"{fields}")
        # The invariant, whatever the numbers: nothing ignored here, nothing failed there.
        if measured[label]["repo"][2] != 0:
            problems.append(f"{label} repository: {measured[label]['repo'][2]} ignored -- a "
                            "corpus fixture is missing; this is not a figure to update")
        if measured[label]["tarball"][1] != 0:
            problems.append(f"{label} tarball: {measured[label]['tarball'][1]} failed")
    corpus = measured[CORPUS_ROW]["tarball"][2]
    if corpus == 0:
        problems.append("the tarball ignores nothing: the corpus leaked into the `include` "
                        "allowlist -- this is not a figure to update")
    for pat, n in zip(CLAUDE_CORPUS, corpus_claims):
        if n != corpus:
            stated = pat.pattern.replace(r"(\d+)", str(n))
            problems.append(f"CLAUDE.md says {stated!r}; the tarball's {CORPUS_ROW} run "
                            f"ignores {corpus}")

    if problems:
        print("\nFAIL: the documented test counts do not match the tree")
        for p in problems:
            print(f"   {p}")
        print("\nThe table as measured, for docs/RELEASING.md § 3:\n")
        print(table(measured))
        return 1
    print(f"\nOK: every documented count matches; corpus = {corpus}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
