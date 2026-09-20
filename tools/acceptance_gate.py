#!/usr/bin/env python3
"""The four-reader acceptance gate (GH #8): does everything this crate encrypts open in
every reader that matters?

No upstream has this. herumi's test_all.py is decrypt -> encrypt -> decrypt, which proves
only self-consistency; odf-crypto's validate_encrypt.py adds one external reader. This
runs four, and one line per reader is the verdict:

    reader          driver                                   independent of us?   gives bytes?
    Microsoft Office COM, tools/office_com_check.ps1         shipping product     no
    LibreOffice     UNO, tools/libreoffice_uno_check.py      shipping product     no
    msoffcrypto-tool CLI, `python -m msoffcrypto -p`         independent impl     yes
    office-crypto   examples/office_crypto_check.rs          independent impl     yes

The two applications parse the package into a document and never hand the ZIP back, so
their bar is: opens, the recovered text contains the expected text, and a wrong password
is refused FOR THE PASSWORD REASON (each driver says what that looks like for its
reader). The two implementations write bytes, so their bar is byte-identity with the
expected plaintext package -- or with its SHA-256, for the Office-written controls whose
plaintext is not committed -- and a wrong password must not yield it.

The msoffcrypto leg carries one more bar, and it is the only one that covers the agile
`dataIntegrity` HMAC: after the CLI comparison it calls the library with
`decrypt(..., verify_integrity=True)`. Nothing else here reads that field -- the CLI
leaves the keyword at its default (`file.decrypt(outfile)`, msoffcrypto `__main__.py:105`;
`verify_integrity=False`, `format/ooxml.py:247`), office-crypto checks neither the
verifier nor the HMAC, and the two applications are not on CI. Without it, the CI half of
this gate passes an artifact whose HMAC blobs are garbage; `--corrupt-integrity` is the
run that proves it does not.

Every reader is run, here, by this script. Nothing is inferred from the test suite having
passed, because a gate that assumes a leg is not a gate.

Usage (from the repository root; the crypto-ops suite writes the artifact). Name a private
directory: every session's `cargo test` writes the same file name, so gating the shared
system temp directory can gate another build's artifact, and has --

    MSOFFICE_CRYPTO_ARTIFACT_DIR=/tmp/gate-$$ cargo test --no-default-features --features crypto-ops
    python tools/acceptance_gate.py "$MSOFFICE_CRYPTO_ARTIFACT_DIR/msoffice_crypto_encrypt_ooxml.docx" \
        --expect-package tests/fixtures/plain.docx --expect-text-file tests/fixtures/plain_content.txt

    # a control -- Office's own file, plaintext known only by digest (tests/real_office_fixtures.rs)
    python tools/acceptance_gate.py tests/fixtures/word16_agile.docx \
        --expect-sha256 90c3c1a8d3785597c0e7b1b1d24050e900bfb0ba6d1f4b272885b6a79f7461f0 \
        --expect-text "msoffice-crypto fixture: word16 docx, agile encryption, password testpass"

    # prove the gate fails when it should. --expect-fail inverts the exit code, so each of
    # these is an ordinary passing step in CI: it exits 0 only if the gate said FAIL.
    python tools/acceptance_gate.py <artifact> ... --tamper --expect-fail
    python tools/acceptance_gate.py <artifact> ... --corrupt-integrity --expect-fail
    python tools/acceptance_gate.py <artifact> ... --password not-the-password --expect-fail

`--corrupt-integrity` is **agile-only**: Office 2007 standard encryption defines no
`dataIntegrity` element and its `EncryptionInfo` is a binary header rather than XML, so the
mutation cannot be built for it. Asked for anyway it prints `GATE: NOT RUN` and exits 2 --
neither 0 nor 1, because the run proved nothing either way. `--tamper` applies to both
families. Both flags report the same way for an artifact that is not a CFB container at all,
which is what a run against a non-ECMA-376 look-alike hits.

`--readers` names which legs MUST run and pass (default: all four). A leg not selected is
reported NOT RUN and does not fail the gate; a leg selected but unable to run does. CI
runs `--readers msoffcrypto,office-crypto` on Linux, where the two applications do not
exist, plus the two mutation runs above; those two readers are the local gate, run on
Windows before a change to the encrypt path is merged, and their verdicts are recorded in
CHANGELOG.md against the exact artifact.

A pass looks like four lines ending in PASS and a final `GATE: PASS`. Exit 0 then, 1
otherwise -- and the other way round under `--expect-fail`. Exit 2 is neither: it is
`GATE: NOT RUN`, a mutation flag asked for on an artifact it cannot describe.

Environment: MSOFFICE_CRYPTO_LO_PYTHON (LibreOffice's python.exe; default the standard
install path), MSOFFICE_CRYPTO_PWSH (default `pwsh`), CARGO_TARGET_DIR passes through
to the office-crypto leg.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
ALL_READERS = ("office", "libreoffice", "msoffcrypto", "office-crypto")
LO_PYTHON = Path(os.environ.get("MSOFFICE_CRYPTO_LO_PYTHON", r"C:\Program Files\LibreOffice\program\python.exe"))
PWSH = os.environ.get("MSOFFICE_CRYPTO_PWSH", "pwsh")


@dataclass
class Verdict:
    reader: str
    passed: bool | None  # None = not run
    detail: str

    def line(self) -> str:
        state = {True: "PASS", False: "FAIL", None: "NOT RUN"}[self.passed]
        return f"{self.reader:<14} {state:<8} {self.detail}"


@dataclass
class Expectation:
    package: Path | None
    sha256: str | None
    length: int | None
    text: str | None
    text_file: Path | None

    def describe_bytes(self) -> str:
        if self.package is not None:
            return f"{self.package.name} ({self.package.stat().st_size} bytes)"
        return f"SHA-256 {self.sha256[:12]}…" + (f" ({self.length} bytes)" if self.length else "")

    def bytes_match(self, out: Path) -> tuple[bool, str]:
        """Byte-identity with the expected package, or digest identity when that is all we have."""
        if not out.exists():
            return False, "no output file"
        data = out.read_bytes()
        if self.package is not None:
            want = self.package.read_bytes()
            if data == want:
                return True, f"byte-identical to {self.describe_bytes()}"
            return False, f"{len(data)} bytes, NOT {self.package.name} ({len(want)} bytes)"
        got = hashlib.sha256(data).hexdigest()
        if got == self.sha256 and (self.length is None or len(data) == self.length):
            return True, f"SHA-256 matches the expected plaintext ({len(data)} bytes)"
        return False, f"{len(data)} bytes, SHA-256 {got[:12]}…, NOT the expected plaintext"


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, **kw)


def _last_line(s: str) -> str:
    lines = [l.strip() for l in s.splitlines() if l.strip()]
    return lines[-1] if lines else "(no output)"


# ---- the two applications -----------------------------------------------------------------


def leg_office(artifact: Path, pw: str, wrong: str, exp: Expectation) -> Verdict:
    if platform.system() != "Windows":
        return Verdict("office", False, "cannot run here: needs Windows with Microsoft Office (the local gate)")
    if shutil.which(PWSH) is None:
        return Verdict("office", False, f"cannot run: {PWSH} not found")
    cmd = [PWSH, "-NoProfile", "-File", str(HERE / "office_com_check.ps1"), "-Path", str(artifact), "-Password", pw, "-WrongPassword", wrong]
    cmd += ["-ExpectedText", exp.text] if exp.text is not None else ["-ExpectedTextFile", str(exp.text_file)]
    r = _run(cmd, cwd=REPO, timeout=600)
    lines = [l.strip() for l in (r.stdout + r.stderr).splitlines() if l.strip()]
    app = next((l for l in lines if l.startswith(("Word ", "Excel ", "PowerPoint "))), "Office")
    verdicts = [l for l in lines if l.startswith(("RIGHT PASSWORD", "WRONG PASSWORD", "NO APPLICATION"))]
    dialogs = [l for l in lines if l.startswith("DIALOG")]
    detail = f"{app}: " + " | ".join(verdicts + dialogs) if verdicts else f"{app}: exit {r.returncode}: {_last_line(r.stdout + r.stderr)}"
    return Verdict("office", r.returncode == 0, detail)


def leg_libreoffice(artifact: Path, pw: str, wrong: str, exp: Expectation) -> Verdict:
    if not LO_PYTHON.exists():
        return Verdict("libreoffice", False, f"cannot run: LibreOffice's python not at {LO_PYTHON} (the local gate)")
    cmd = [str(LO_PYTHON), str(HERE / "libreoffice_uno_check.py"), str(artifact), "--password", pw, "--wrong-password", wrong]
    cmd += ["--expected-text", exp.text] if exp.text is not None else ["--expected-text-file", str(exp.text_file)]
    r = _run(cmd, cwd=REPO, timeout=900, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    lines = [l.strip() for l in (r.stdout + r.stderr).splitlines() if l.strip()]
    version = next((l.split(": ", 1)[1] for l in lines if l.startswith("LibreOffice (UNO): ")), "LibreOffice")
    verdicts = [l for l in lines if l.startswith(("RIGHT PASSWORD", "WRONG PASSWORD", "COULD NOT DRIVE"))]
    detail = f"{version}: " + " | ".join(verdicts) if verdicts else f"exit {r.returncode}: {_last_line(r.stdout + r.stderr)}"
    return Verdict("libreoffice", r.returncode == 0, detail)


# ---- the two independent implementations ---------------------------------------------------


def declares_data_integrity(artifact: Path) -> bool:
    """Does this artifact carry a `<dataIntegrity>` element for anything to verify?

    Same technique as `corrupt_integrity`, and for the same reason: the version pair
    ([MS-OFFCRYPTO] 2.3.4.10, the first two LE u16s of `EncryptionInfo`) names the family
    without guessing, and only agile (4.4) has an XML `EncryptionInfo` that can carry the
    element. Anything else -- a standard 2007 binary header, a stream too short to hold a
    version, a file that is not a CFB at all -- declares none.

    Deliberately total rather than raising: this answers a question about what a verdict
    is allowed to claim, and a gate leg must not fail because the question was hard.
    """
    import olefile  # a dependency of the leg, not of the gate

    try:
        if not olefile.isOleFile(str(artifact)):
            return False
        ole = olefile.OleFileIO(str(artifact))
        try:
            if not ole.exists("EncryptionInfo"):
                return False
            info = ole.openstream("EncryptionInfo").read()
            if len(info) < 8:
                return False
            version = (int.from_bytes(info[0:2], "little"), int.from_bytes(info[2:4], "little"))
            return version == (4, 4) and b"dataIntegrity" in info
        finally:
            ole.close()
    except Exception:  # noqa: BLE001 -- unreadable means undeclarable, for this purpose
        return False


def msoffcrypto_integrity(artifact: Path, pw: str) -> tuple[bool, str]:
    """Does the agile `dataIntegrity` HMAC verify, according to an implementation that is
    not this crate?

    `msoffcrypto-tool` is the only reader here that checks it, and only through the
    library: its CLI calls `file.decrypt(outfile)` (`__main__.py:105`) and the keyword
    defaults to off (`format/ooxml.py:247`). The check is HMAC-over-ciphertext with the
    two `dataIntegrity` block keys, so it is independent of everything the byte
    comparison covers -- a package that decrypts to the right bytes under blobs that are
    meaningless is exactly what this catches, and what `--corrupt-integrity` builds.

    **A file with no `dataIntegrity` says so, and this used to be a live defect in the
    gate.** ECMA-376 standard defines no such element, msoffcrypto silently ignores the
    keyword for it, and this function nevertheless returned "dataIntegrity HMAC verifies
    (verify_integrity=True)" -- byte-identical to the line a real agile verification
    produces. The docstring claimed the distinction the code did not make, so a 2007
    artifact's PASS line asserted a check nobody had run. Reported by a downstream
    consumer measuring its own artifacts, 2026-09-19. `declares_data_integrity` is now
    consulted and the two cases read differently, so the string is evidence of exactly
    what happened.
    """
    import io

    import msoffcrypto  # a dependency of the leg, not of the gate

    declared = declares_data_integrity(artifact)
    try:
        with artifact.open("rb") as fh:
            of = msoffcrypto.OfficeFile(fh)
            of.load_key(password=pw)
            of.decrypt(io.BytesIO(), verify_integrity=True)
    except Exception as e:  # noqa: BLE001 -- any refusal is a failed verification
        return False, f"{type(e).__module__}.{type(e).__name__}: {e}"
    if not declared:
        return True, "decrypted; NO dataIntegrity element to verify (verify_integrity is inert here)"
    return True, "dataIntegrity HMAC verifies (verify_integrity=True)"


def leg_msoffcrypto(artifact: Path, pw: str, wrong: str, exp: Expectation, work: Path) -> Verdict:
    try:
        import importlib.metadata as md

        version = md.version("msoffcrypto-tool")
    except Exception:  # noqa: BLE001
        return Verdict("msoffcrypto", False, "cannot run: msoffcrypto-tool is not installed for this python (pip install msoffcrypto-tool)")
    out = work / "msoffcrypto_out.bin"
    r = _run([sys.executable, "-m", "msoffcrypto", "-p", pw, str(artifact), str(out)], cwd=REPO, timeout=600)
    if r.returncode != 0:
        return Verdict("msoffcrypto", False, f"msoffcrypto-tool {version}: right password REFUSED (exit {r.returncode}): {_last_line(r.stderr)}")
    ok, why = exp.bytes_match(out)
    if not ok:
        return Verdict("msoffcrypto", False, f"msoffcrypto-tool {version}: decrypted, but {why}")
    integrity_ok, integrity = msoffcrypto_integrity(artifact, pw)
    if not integrity_ok:
        return Verdict("msoffcrypto", False, f"msoffcrypto-tool {version}: {why}, but dataIntegrity does NOT verify: {integrity}")
    out2 = work / "msoffcrypto_wrong.bin"
    r2 = _run([sys.executable, "-m", "msoffcrypto", "-p", wrong, str(artifact), str(out2)], cwd=REPO, timeout=600)
    if r2.returncode == 0:
        ok2, why2 = exp.bytes_match(out2)
        if ok2:
            return Verdict("msoffcrypto", False, f"msoffcrypto-tool {version}: {why} | wrong password DECRYPTED TO THE PLAINTEXT -- failure")
        neg = f"wrong password: exit 0 but {why2}"
    else:
        neg = f"wrong password refused (exit {r2.returncode}): {_last_line(r2.stderr)}"
    return Verdict("msoffcrypto", True, f"msoffcrypto-tool {version}: {why} | {integrity} | {neg}")


def leg_office_crypto(artifact: Path, pw: str, wrong: str, exp: Expectation, work: Path) -> Verdict:
    if shutil.which("cargo") is None:
        return Verdict("office-crypto", False, "cannot run: cargo not found")
    common = ["--locked", "--quiet", "--no-default-features", "--features", "crypto-ops", "--example", "office_crypto_check"]

    # BUILD FIRST, AND SEPARATELY, because this leg measures a third party through a
    # binary that happens to live in this repository.
    #
    # `examples/office_crypto_check.rs:13` exists so the leg is not this crate marking its
    # own homework -- it calls `office_crypto::decrypt_from_bytes`, never
    # `msoffice_crypto::decrypt_ooxml`. But an example links the lib, so `cargo run`
    # compiles this crate on the way to running someone else's. Folded into one
    # invocation, a compile error in an unrelated, uncommitted edit came back as a
    # non-zero exit and was rendered "right password REFUSED" -- a sentence about a reader
    # and an artifact, asserted on the strength of `cargo` failing.
    #
    # Found by the downstream consumer, 2026-09-20: two runs minutes apart on one artifact
    # disagreed, because the variable was a `git status` in a different repository and
    # nothing in the output named it. They recorded no verdict for that run, which was the
    # right call and is the outcome this split makes unnecessary.
    build = _run(["cargo", "build", *common], cwd=REPO, timeout=1800)
    if build.returncode != 0:
        # NOT a Verdict: a selected reader that could not be *attempted* has proven
        # nothing, and both PASS and FAIL would be claims about bytes nobody read. Same
        # reasoning as MutationNotApplicable, and the same exit 2.
        raise LegCannotRun(
            f"office-crypto: the example did not build, so the reader was never run "
            f"(cargo exit {build.returncode}): {_last_line(build.stderr)}"
        )

    base = ["cargo", "run", *common, "--"]

    def run(password: str, out: Path) -> subprocess.CompletedProcess:
        return _run(base + [str(artifact), str(out)], cwd=REPO, timeout=1800, env={**os.environ, "MSOFFICE_CRYPTO_PASSWORD": password})

    out = work / "office_crypto_out.bin"
    r = run(pw, out)
    if r.returncode != 0:
        # The build already succeeded, so a non-zero exit here is the example's own: it
        # exits 1 when office-crypto refuses. Anything else is the harness failing, not a
        # reader refusing, and must not be worded as a refusal.
        if r.returncode == 1:
            return Verdict("office-crypto", False, f"office-crypto 0.3: right password REFUSED: {_last_line(r.stderr)}")
        raise LegCannotRun(
            f"office-crypto: the example exited {r.returncode}, which is neither success "
            f"nor its refusal code, so nothing was measured: {_last_line(r.stderr)}"
        )
    ok, why = exp.bytes_match(out)
    if not ok:
        return Verdict("office-crypto", False, f"office-crypto 0.3: decrypted, but {why}")
    out2 = work / "office_crypto_wrong.bin"
    r2 = run(wrong, out2)
    if r2.returncode == 0:
        ok2, why2 = exp.bytes_match(out2)
        if ok2:
            return Verdict("office-crypto", False, f"office-crypto 0.3: {why} | wrong password DECRYPTED TO THE PLAINTEXT -- failure")
        # office-crypto 0.3 checks neither the password verifier nor dataIntegrity (its
        # crypto.rs:17 says so), so a wrong key silently yields the wrong bytes. The
        # comparison is the whole check for this leg, and this line says so.
        neg = f"wrong password: {why2} (office-crypto verifies neither the verifier nor dataIntegrity; the byte comparison is the check)"
    else:
        neg = f"wrong password refused (exit {r2.returncode}): {_last_line(r2.stderr)}"
    return Verdict("office-crypto", True, f"office-crypto 0.3: {why} | {neg}")


# ---- the two mutations, each of which the gate must fail ------------------------------------


def tree_state() -> str:
    """This repository's HEAD and whether it is dirty, printed beside the reader versions.

    A verdict names the artifact by SHA-256 and each reader by version, and until now said
    nothing about the tree the run happened in. That mattered twice, in two directions:
    the office-crypto leg builds from this working directory, so an uncommitted edit can
    decide whether it runs at all; and `CHANGELOG.md`'s evidence sections cite an artifact
    hash, which pins the bytes measured but not the commit that produced them -- and
    `0.1.0-rc.4` currently spans many commits. Both were reported by the downstream
    consumer, who hit the first and then recognised the second from its shape.

    Best-effort by design: a `.crate` extraction has no git metadata, and a gate that
    refused to run outside a checkout would be worse than one that says "unknown".
    """
    try:
        head = _run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO, timeout=30)
        if head.returncode != 0:
            return "not a git checkout"
        status = _run(["git", "status", "--porcelain"], cwd=REPO, timeout=30)
        dirty = bool(status.stdout.strip()) if status.returncode == 0 else None
        sha = head.stdout.strip()
        if dirty is None:
            return f"{sha} (cleanliness unknown)"
        return f"{sha}{' DIRTY -- uncommitted changes are in this measurement' if dirty else ' clean'}"
    except Exception:  # noqa: BLE001 -- provenance is a courtesy; never fail a gate over it
        return "unknown"


class LegCannotRun(Exception):
    """A selected reader could not be attempted, so this run proves nothing about it.

    Distinct from a `Verdict` of either polarity, and for the reason MutationNotApplicable
    gives: PASS and FAIL are both claims about what a reader did with an artifact, and a
    reader that never executed did nothing with it. Rendering "could not build" as FAIL
    puts a falsehood in a line a consumer copies into an evidence section.

    The direction of the error is what makes this worth an exception rather than a softer
    verdict. A spurious FAIL is loud and gets investigated; the same conflation could in
    principle produce a spurious PASS, and a PASS is what gets written down as durable
    evidence. Exit 2, so a caller testing only `exit == 0` reads it as neither.
    """


class MutationNotApplicable(Exception):
    """The requested mutation has no meaning for this artifact, so this run proves nothing.

    Distinct from a failed gate on purpose. `--corrupt-integrity --expect-fail` is a proof
    that the gate notices blanked `dataIntegrity` blobs; run against a file that has none,
    it is not a proof that failed, it is a proof that could not be attempted. Reporting it
    as `GATE: FAIL` would let a green CI step stand for evidence nobody produced.

    Before this existed the same case was an uncaught `UnicodeDecodeError` from decoding an
    Office 2007 `EncryptionInfo` binary header as XML: exit 1, no `GATE:` line, and
    `--expect-fail` never reached its inversion, so the run failed while looking like the
    gate had held.
    """


def tamper(src: Path, dest: Path) -> str:
    """Copy `src` to `dest` and flip one bit in the EncryptedPackage ciphertext BODY.

    Not the header, not the container: a byte in the second 4096-byte segment, past the
    8-byte size prefix, so every reader parses the file, passes the verifier, and fails
    only where a tampered file should fail -- on the dataIntegrity check, or by decrypting
    to the wrong bytes if it does not check. Rewritten in place with olefile, which keeps
    the stream the same length and the container otherwise untouched.
    """
    import olefile  # only the --tamper path needs it

    shutil.copyfile(src, dest)
    if not olefile.isOleFile(str(dest)):
        raise MutationNotApplicable(
            "--tamper flips a bit in the EncryptedPackage stream, and this artifact is not a "
            "CFB container at all, so there is no such stream to reach"
        )
    ole = olefile.OleFileIO(str(dest), write_mode=True)
    try:
        if not ole.exists("EncryptedPackage"):
            raise MutationNotApplicable(
                "the artifact is a CFB container but carries no EncryptedPackage stream"
            )
        data = bytearray(ole.openstream("EncryptedPackage").read())
        offset = 8 + 4096 + 100
        if offset >= len(data):
            offset = 8 + (len(data) - 8) // 2
        data[offset] ^= 0x01
        ole.write_stream("EncryptedPackage", bytes(data))
    finally:
        ole.close()
    return f"flipped one bit at EncryptedPackage[{offset}] (ciphertext body, segment {(offset - 8) // 4096})"


HMAC_ATTRS = ("encryptedHmacKey", "encryptedHmacValue")


def corrupt_integrity(src: Path, dest: Path) -> str:
    """Copy `src` to `dest` and replace the two `dataIntegrity` blobs with base64 'A's.

    Nothing else moves: same attribute lengths (padding `=` kept, so the decoded blobs
    keep their length too), same `EncryptionInfo` stream length, same ciphertext, same
    file size. Password verification, the KDF, the container and the package are all
    untouched, so every reader that does not check the HMAC decrypts this file to the
    right bytes and reports PASS -- which is the point. Only a reader that checks
    `dataIntegrity` can tell this file from the real one, and the gate must fail on it.

    This is the mutation the review found the CI half of the gate could not catch
    ([MS-OFFCRYPTO] 2.3.4.14 is the field; CHANGELOG 2026-09-05 § *Review* the finding).

    **ECMA-376 agile (4.4) only**, and it says so rather than assuming it. Office 2007
    standard encryption defines no `dataIntegrity` element, and its `EncryptionInfo` is a
    binary header rather than XML, so this mutation cannot be built for it -- use
    `--tamper`, which reaches the same `EncryptedPackage` in either family.
    """
    import re

    import olefile

    shutil.copyfile(src, dest)
    if not olefile.isOleFile(str(dest)):
        raise MutationNotApplicable(
            "--corrupt-integrity blanks the dataIntegrity blobs inside an agile "
            "EncryptionInfo, and this artifact is not a CFB container at all"
        )
    ole = olefile.OleFileIO(str(dest), write_mode=True)
    try:
        if not ole.exists("EncryptionInfo"):
            raise MutationNotApplicable(
                "the artifact is a CFB container but carries no EncryptionInfo stream"
            )
        info = ole.openstream("EncryptionInfo").read()
        # [MS-OFFCRYPTO] 2.3.4.10: vMajor and vMinor are the first two LE u16s. Checked
        # before the decode below, because that decode is what used to raise
        # UnicodeDecodeError on a standard artifact -- the version pair names the family
        # without guessing, and the message can then name it back.
        if len(info) < 8:
            raise MutationNotApplicable(
                f"the EncryptionInfo stream is {len(info)} bytes, too short to carry a version pair"
            )
        version = (int.from_bytes(info[0:2], "little"), int.from_bytes(info[2:4], "little"))
        if version != (4, 4):
            detail = (
                " -- Office 2007 standard encryption defines no dataIntegrity element to blank; "
                "use --tamper for this artifact"
                if version[1] == 2
                else ""
            )
            raise MutationNotApplicable(
                f"--corrupt-integrity applies only to ECMA-376 agile encryption (4.4), and "
                f"this artifact declares {version[0]}.{version[1]}{detail}"
            )
        try:
            head, xml = info[:8], info[8:].decode("utf-8")  # 8 = version + flags, 2.3.4.10
        except UnicodeDecodeError as e:
            raise MutationNotApplicable(
                f"the artifact declares agile encryption (4.4) but its EncryptionInfo is not "
                f"UTF-8 XML, so there is nothing to blank: {e}"
            ) from e
        for attr in HMAC_ATTRS:
            blanked, n = re.subn(rf'({attr}=")([^"]*)(")', _blank_base64, xml)
            if n != 1:
                raise SystemExit(f"--corrupt-integrity: {attr} appears {n} times in EncryptionInfo, expected 1")
            xml = blanked
        out = head + xml.encode("utf-8")
        if len(out) != len(info):
            raise SystemExit(f"--corrupt-integrity: rewrote {len(info)} bytes as {len(out)}; the mutation must not resize the stream")
        ole.write_stream("EncryptionInfo", out)
    finally:
        ole.close()
    return f"blanked {' and '.join(HMAC_ATTRS)} in EncryptionInfo, every length unchanged"


def _blank_base64(m) -> str:
    value = m.group(2)
    pad = len(value) - len(value.rstrip("="))
    return m.group(1) + "A" * (len(value) - pad) + "=" * pad + m.group(3)


# ---- main ----------------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description="The four-reader acceptance gate for a file this crate encrypted.")
    ap.add_argument("artifact", type=Path)
    ap.add_argument("--password", default="testpass")
    ap.add_argument("--wrong-password", default="definitely-not-the-password")
    b = ap.add_mutually_exclusive_group(required=True)
    b.add_argument("--expect-package", type=Path, help="the plaintext OOXML the bytes must equal")
    b.add_argument("--expect-sha256", help="its SHA-256, when the plaintext is not committed")
    ap.add_argument("--expect-len", type=int, help="with --expect-sha256: the plaintext length")
    t = ap.add_mutually_exclusive_group()
    t.add_argument("--expect-text-file", type=Path, default=REPO / "tests" / "fixtures" / "plain_content.txt")
    t.add_argument("--expect-text")
    ap.add_argument("--readers", default="all", help="comma list of " + ",".join(ALL_READERS) + " (default all)")
    m = ap.add_mutually_exclusive_group()
    m.add_argument("--tamper", action="store_true", help="run on a copy with one ciphertext bit flipped; the gate must then FAIL")
    m.add_argument("--corrupt-integrity", action="store_true", help="run on a copy whose dataIntegrity blobs are blanked; the gate must then FAIL")
    ap.add_argument("--expect-fail", action="store_true", help="invert the exit code: this run is a proof that the gate fails, so GATE: FAIL exits 0")
    args = ap.parse_args()

    readers = ALL_READERS if args.readers == "all" else tuple(r.strip() for r in args.readers.split(","))
    unknown = [r for r in readers if r not in ALL_READERS]
    if unknown:
        ap.error(f"unknown reader(s) {unknown}; choose from {ALL_READERS}")
    if not args.artifact.exists():
        print(f"artifact not found: {args.artifact} -- run the crypto-ops test suite first")
        return 1
    exp = Expectation(
        package=args.expect_package.resolve() if args.expect_package else None,
        sha256=args.expect_sha256.lower() if args.expect_sha256 else None,
        length=args.expect_len,
        text=args.expect_text,
        text_file=args.expect_text_file.resolve() if args.expect_text is None else None,
    )

    work = Path(tempfile.mkdtemp(prefix="msoffice-crypto-gate-"))
    try:
        artifact = args.artifact.resolve()
        raw = artifact.read_bytes()
        print(f"artifact : {artifact} ({len(raw)} bytes, SHA-256 {hashlib.sha256(raw).hexdigest()})")
        if args.tamper or args.corrupt_integrity:
            mutant = work / artifact.name
            try:
                how = (
                    tamper(artifact, mutant) if args.tamper else corrupt_integrity(artifact, mutant)
                )
            except MutationNotApplicable as why:
                # Exit 2, distinct from both 0 and 1: this run neither passed nor failed,
                # so a caller that only tests `exit == 0` must not read it as either. The
                # flag was asked for on an artifact it cannot describe, and saying so is
                # the honest verdict -- see MutationNotApplicable.
                flag = "--tamper" if args.tamper else "--corrupt-integrity"
                print(f"mutation : NOT APPLICABLE -- {why}")
                print()
                print(f"GATE: NOT RUN ({flag} does not apply to this artifact; nothing was proven)")
                return 2
            artifact = mutant
            what = (
                "every reader must now refuse or produce the wrong bytes"
                if args.tamper
                else "only the dataIntegrity check can object, and the gate must now fail on it"
            )
            print(f"mutated  : {how} -> {what}")
        print(f"expected : bytes = {exp.describe_bytes()}; text from {'--expect-text' if exp.text is not None else exp.text_file.name}")
        print(f"readers  : {', '.join(readers)}")
        print(f"tree     : {tree_state()}")
        print()

        verdicts: list[Verdict] = []
        for reader in ALL_READERS:
            if reader not in readers:
                verdicts.append(Verdict(reader, None, "not selected"))
                continue
            try:
                if reader == "office":
                    v = leg_office(artifact, args.password, args.wrong_password, exp)
                elif reader == "libreoffice":
                    v = leg_libreoffice(artifact, args.password, args.wrong_password, exp)
                elif reader == "msoffcrypto":
                    v = leg_msoffcrypto(artifact, args.password, args.wrong_password, exp, work)
                else:
                    v = leg_office_crypto(artifact, args.password, args.wrong_password, exp, work)
            except LegCannotRun as why:
                # Exit 2 for the same reason MutationNotApplicable takes it: neither 0 nor
                # 1, because this run is not a pass and not a failure. Stopping here rather
                # than continuing is deliberate -- a partial gate printed under a GATE:
                # line reads as a complete one, and the missing leg is the interesting part.
                print(f"{reader:<14} NOT RUN  {why}")
                print()
                print(f"GATE: NOT RUN ({why}); nothing was proven")
                return 2
            verdicts.append(v)
            print(v.line(), flush=True)

        ran = [v for v in verdicts if v.passed is not None]
        failed = [v for v in ran if not v.passed]
        print()
        if failed:
            print(f"GATE: FAIL ({len(failed)} of {len(ran)} selected readers failed: {', '.join(v.reader for v in failed)})")
        else:
            print(f"GATE: PASS ({len(ran)} of {len(ALL_READERS)} readers ran; {4 - len(ran)} not selected)")
        if args.expect_fail:
            # The negative control, and the only way a mutation run can be an ordinary
            # green CI step: a gate that cannot fail is not a gate, so here PASS is the
            # failure.
            if failed:
                print("EXPECTED FAIL: the gate failed, which is what this run required")
                return 0
            print("UNEXPECTED PASS: --expect-fail required at least one selected reader to fail, and none did")
            return 1
        return 1 if failed else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
