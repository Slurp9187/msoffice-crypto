"""Open a password-protected Office file in real LibreOffice, and say whether it read it.

The LibreOffice leg of the four-reader acceptance gate (GH #8): the counterpart of
tools/office_com_check.ps1 for the second shipping product, driven over UNO. Run by
tools/acceptance_gate.py, or directly with LibreOffice's OWN python (the system one has
no `uno`):

    "C:\\Program Files\\LibreOffice\\program\\python.exe" tools/libreoffice_uno_check.py \
        <artifact> [--password testpass] [--expected-text-file tests/fixtures/plain_content.txt]

Two opens, and both matter, exactly as in the Word script:

  1. the right password -> LibreOffice must open the document AND the text it recovers
                           must contain the expected text. Writer, Calc and Impress
                           documents are read through their own models (body text,
                           every used cell, every shape on every page), so the same
                           check runs on a .docx, an .xlsx and a .pptx.
  2. a wrong password   -> LibreOffice must REFUSE, and refuse for the password reason.

The second needs care, because LibreOffice reports every abandoned load the same way.
With a wrong `Password` the OOXML filter asks the interaction handler for another one
(oox/source/core/filterdetect.cxx:435-438 -- behaviour cited, nothing copied: a
`DocumentMSPasswordRequest2`, comphelper/source/misc/docpasswordrequest.cxx:125); with
no handler, or one that aborts, it marks the load aborted, and the frame loader turns that
into `IllegalArgumentException: Unsupported URL <...>: "type detection aborted"`
(framework/source/loadenv/loadenv.cxx:799-800). A file whose verifier PASSES but whose
package fails to decrypt or fails its dataIntegrity check takes the very same exit
(filterdetect.cxx:448-451; oox/source/crypto/DocumentDecryption.cxx:216 folds
`checkDataIntegrity` into `decrypt`'s result). So "type detection aborted" alone cannot
tell "wrong password" from "tampered file".

This script installs its own interaction handler and records every request LibreOffice
raises. A wrong password is refused for the right reason when, and only when, a password
request was raised -- LibreOffice walked the container, parsed EncryptionInfo, ran the
KDF, compared the verifier, and asked for a different password
(comphelper/source/misc/docpasswordhelper.cxx:603-609: the request is made only on
`WrongPassword`, and only when a handler is present). That is the analogue of Word's
0x800A1520, and it is what makes the first open mean something. The handler selects
Abort, so the load ends in the exception above rather than a prompt nothing is there to
answer.

The request is recognised by its continuations, not by its type name: pyuno on this
build (LibreOffice 26.2, Python 3.12) cannot convert the `DocumentMSPasswordRequest2`
struct that `getRequest()` returns (`uno.py:513`, `AttributeError: args`), and a handler
that raises is a handler LibreOffice treats as absent. A `DocPasswordRequest` offers
exactly two continuations, Abort and an `XInteractionPassword2`
(comphelper/source/misc/docpasswordrequest.cxx:44, :50, :167), and nothing else on this
path offers a password continuation, so "a continuation that takes a password" is the request.

What LibreOffice cannot give: bytes. It parses the decrypted package into a document
model and never hands the ZIP back, so its bar is the same as Word's -- opens, content
matches, wrong password refused -- and NOT byte-identity. `msoffcrypto-tool` and
`office-crypto` are the two byte-identical legs.

Exit status (the harness reads these, and so can a human):
  0  both opens gave the right answer
  2  the right password opened the file but the content differs
  3  the wrong password OPENED the file
  4  the wrong password was refused, but NOT via a password request -- LibreOffice
     rejected the file before or after its verifier, which is a different fact
  5  the right password did not open the file (the reason is printed: a password
     request means LibreOffice's verifier rejected it; an abort with no request means
     the verifier passed and decrypt or the integrity check failed)
  6  LibreOffice could not be driven at all (the command and error are printed)

Always terminates the soffice it started, by the unique pipe name on its command line,
in a finally: a leaked instance blocks the next run, and killing by name would take a
user's own LibreOffice down with it.
"""

from __future__ import annotations

import argparse
import os
import random
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import uno
import unohelper
from com.sun.star.beans import PropertyValue
from com.sun.star.connection import NoConnectException
from com.sun.star.task import XInteractionHandler

SOFFICE = Path(os.environ.get("MSOFFICE_CRYPTO_SOFFICE", r"C:\Program Files\LibreOffice\program\soffice.exe"))
WRONG_PASSWORD = "definitely-not-the-password"


def _prop(name: str, value) -> PropertyValue:
    p = PropertyValue()
    p.Name = name
    p.Value = value
    return p


PASSWORD_REQUEST = "password request"


class RecordingHandler(unohelper.Base, XInteractionHandler):
    """Records what every request offered -- a password continuation or not -- and aborts it.

    LibreOffice raises a `DocumentMSPasswordRequest2` when the supplied password fails the
    verifier of an MS-OFFCRYPTO file. Recording rather than answering keeps the run
    headless and makes the refusal reason observable. See the module docstring for why
    the request is classified by its continuations rather than by `getRequest()`.
    """

    def __init__(self) -> None:
        self.requests: list[str] = []

    def handle(self, request) -> None:  # noqa: N802 -- UNO interface method name
        abort_t = uno.getTypeByName("com.sun.star.task.XInteractionAbort")
        pw_t = uno.getTypeByName("com.sun.star.task.XInteractionPassword")
        pw2_t = uno.getTypeByName("com.sun.star.task.XInteractionPassword2")
        abort = None
        takes_password = False
        for cont in request.getContinuations():
            if cont.queryInterface(pw2_t) is not None or cont.queryInterface(pw_t) is not None:
                takes_password = True
            if abort is None and cont.queryInterface(abort_t) is not None:
                abort = cont
        if takes_password:
            self.requests.append(PASSWORD_REQUEST)
        else:
            # Name any other request when pyuno can convert it (an ErrorCodeRequest for a
            # file LibreOffice cannot parse, say); the password request is the one it
            # cannot, and it is classified above without touching getRequest().
            try:
                exc = request.getRequest()
                name = getattr(exc, "typeName", None) or type(exc).__name__
                message = getattr(exc, "Message", "")
                code = getattr(exc, "ErrCode", None)
                self.requests.append(f"{name}" + (f" ErrCode={code:#x}" if isinstance(code, int) else "") + (f" {message!r}" if message else ""))
            except Exception:  # noqa: BLE001 -- pyuno conversion failure; the type is unknown, the fact remains
                self.requests.append("other request (type not convertible by pyuno)")
        if abort is not None:
            abort.select()


def _bootstrap(profile: Path):
    """Start a private soffice on a unique pipe with a fresh profile and connect to it."""
    pipe = "msofficecrypto" + str(random.random())[2:10]
    connect = f"pipe,name={pipe};urp;"
    cmd = [
        str(SOFFICE),
        "--headless",
        "--invisible",
        "--nologo",
        "--nodefault",
        "--norestore",
        "--nolockcheck",
        "--nofirststartwizard",
        f"--accept={connect}",
        f"-env:UserInstallation={profile.resolve().as_uri()}",
    ]
    print("starting", " ".join(cmd), flush=True)
    proc = subprocess.Popen(cmd)
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext("com.sun.star.bridge.UnoUrlResolver", local)
    url = f"uno:{connect}StarOffice.ComponentContext"
    last: Exception | None = None
    t0 = time.monotonic()
    for _ in range(120):  # a cold profile takes ~10-40 s on this machine
        try:
            ctx = resolver.resolve(url)
            print(f"connected after {time.monotonic() - t0:.1f}s", flush=True)
            return ctx, proc, pipe
        except NoConnectException as err:
            last = err
            time.sleep(1)
    _kill_by_pipe(pipe)
    raise RuntimeError(f"could not connect to {url}: {last}")


def _kill_by_pipe(pipe: str) -> None:
    """Kill every soffice whose command line carries OUR pipe name -- and nothing else.

    `Popen.terminate` is not enough: soffice.exe hands off to a second process, and the
    one Popen holds is not always the one still running. Matching the unique pipe name
    means a user's own LibreOffice is never touched.
    """
    ps = (
        "Get-CimInstance Win32_Process -Filter \"Name LIKE 'soffice%'\" | "
        f"Where-Object {{ $_.CommandLine -like '*{pipe}*' }} | "
        "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; $_.ProcessId }"
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, check=False)


def _lo_version(ctx) -> str:
    try:
        config = ctx.ServiceManager.createInstanceWithContext("com.sun.star.configuration.ConfigurationProvider", ctx)
        access = config.createInstanceWithArguments(
            "com.sun.star.configuration.ConfigurationAccess",
            (_prop("nodepath", "/org.openoffice.Setup/Product"),),
        )
        return f"{access.getPropertyValue('ooName')} {access.getPropertyValue('ooSetupVersionAboutBox')}"
    except Exception as e:  # noqa: BLE001 -- evidence, not load-bearing
        return f"<version query failed: {e}>"


def _document_text(doc) -> str:
    """Every piece of text the document model holds, joined with single spaces."""
    parts: list[str] = []
    if doc.supportsService("com.sun.star.text.TextDocument"):
        parts.append(doc.getText().getString())
    elif doc.supportsService("com.sun.star.sheet.SpreadsheetDocument"):
        sheets = doc.getSheets()
        for i in range(sheets.getCount()):
            sheet = sheets.getByIndex(i)
            cursor = sheet.createCursor()
            cursor.gotoEndOfUsedArea(False)
            end = cursor.getRangeAddress()
            rng = sheet.getCellRangeByPosition(0, 0, end.EndColumn, end.EndRow)
            for row in rng.getDataArray():
                parts.extend(str(v) for v in row if v not in ("", None))
    elif doc.supportsService("com.sun.star.presentation.PresentationDocument") or doc.supportsService(
        "com.sun.star.drawing.DrawingDocument"
    ):
        pages = doc.getDrawPages()
        for i in range(pages.getCount()):
            page = pages.getByIndex(i)
            for j in range(page.getCount()):
                shape = page.getByIndex(j)
                if hasattr(shape, "getString"):
                    parts.append(shape.getString())
    else:
        raise RuntimeError("opened, but the document is neither Writer, Calc nor Impress")
    return " ".join(parts)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _load(desktop, url: str, password: str):
    """One open. Returns (doc_or_None, handler, exception_text_or_None)."""
    handler = RecordingHandler()
    props = (
        _prop("Hidden", True),
        _prop("ReadOnly", True),
        _prop("Password", password),
        _prop("InteractionHandler", handler),
    )
    try:
        doc = desktop.loadComponentFromURL(url, "_blank", 0, props)
    except Exception as e:  # noqa: BLE001 -- the exception text IS the verdict
        return None, handler, f"{type(e).__name__}: {getattr(e, 'Message', str(e))}"
    return doc, handler, None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("artifact", type=Path)
    ap.add_argument("--password", default="testpass")
    ap.add_argument("--wrong-password", default=WRONG_PASSWORD)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--expected-text-file", type=Path, default=Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "plain_content.txt")
    g.add_argument("--expected-text")
    args = ap.parse_args()

    if not args.artifact.exists():
        print(f"artifact not found: {args.artifact} -- run the crypto-ops test suite first", flush=True)
        return 6
    if args.expected_text is not None:
        expected, source = args.expected_text, "--expected-text"
    else:
        expected, source = args.expected_text_file.read_text(encoding="utf-8"), args.expected_text_file.name
    expected = _norm(expected)
    url = args.artifact.resolve().as_uri()

    profile = Path(os.environ.get("TEMP", ".")) / f"msoffice-crypto-lo-{os.getpid()}"
    profile.mkdir(parents=True, exist_ok=True)
    try:
        ctx, proc, pipe = _bootstrap(profile)
    except Exception as e:  # noqa: BLE001
        print(f"COULD NOT DRIVE LIBREOFFICE: {e}", flush=True)
        shutil.rmtree(profile, ignore_errors=True)
        return 6

    rc = 0
    desktop = None
    try:
        desktop = ctx.ServiceManager.createInstanceWithContext("com.sun.star.frame.Desktop", ctx)
        print(f"LibreOffice (UNO): {_lo_version(ctx)}", flush=True)

        # 1. the right password
        doc, handler, err = _load(desktop, url, args.password)
        if doc is None:
            if PASSWORD_REQUEST in handler.requests:
                why = "LibreOffice's verifier REJECTED the password (it asked for another one)"
            elif err is not None:
                why = f"no password request, so the verifier passed and decrypt or the integrity check failed; load threw {err}"
            else:
                why = "loadComponentFromURL returned no document"
            print(f"RIGHT PASSWORD : DID NOT OPEN -- {why}; requests={handler.requests}", flush=True)
            return 5
        try:
            got = _norm(_document_text(doc))
        finally:
            doc.close(True)
        if expected in got:
            print(f"RIGHT PASSWORD : OPENED, content matches {source}", flush=True)
        else:
            print(f"RIGHT PASSWORD : OPENED, BUT CONTENT DIFFERS -- got: {got[:200]!r}", flush=True)
            return 2

        # 2. a wrong password -- must be refused, and refused for the right reason
        doc, handler, err = _load(desktop, url, args.wrong_password)
        if doc is not None:
            doc.close(True)
            print("WRONG PASSWORD : OPENED -- THIS IS A FAILURE", flush=True)
            return 3
        if PASSWORD_REQUEST in handler.requests:
            print(
                "WRONG PASSWORD : REFUSED -- verifier rejected it and LibreOffice asked for another "
                f"(a password request with an XInteractionPassword2 continuation, aborted); load then threw {err}",
                flush=True,
            )
        else:
            print(
                f"WRONG PASSWORD : REFUSED, BUT NOT BY THE VERIFIER -- no password request; requests={handler.requests}; load threw {err}",
                flush=True,
            )
            return 4
        return 0
    finally:
        try:
            if desktop is not None:
                desktop.terminate()
        except Exception:  # noqa: BLE001 -- terminate() commonly throws DisposedException on the way out
            pass
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        _kill_by_pipe(pipe)
        shutil.rmtree(profile, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
