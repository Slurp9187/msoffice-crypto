#!/usr/bin/env python3
"""Generate tests/fixtures/excel97_xor.xls: excel97_plain.xls under XOR obfuscation.

Why a generator and not Excel.  Excel 16 will still write XOR obfuscation, but only
into the Excel 5.0/95 format (`SaveAs FileFormat:=39`): a BIFF5 `Book` stream whose
FILEPASS record is the bare 4-byte key + verifier, with no `wEncryptionType` word.
msoffcrypto-tool, the differential oracle this slice's close-when is stated against,
reads only the BIFF8 `Workbook` layout ("Unrecognized file format" on the BIFF5 file,
measured 2026-09-05), and [MS-XLS] documents only BIFF8.  So the fixture is the
BIFF8 plain twin obfuscated by this script -- program output, which carries no
upstream licence (CLAUDE.md § Testing Rules, "Generate fixtures, don't copy them").

What is the oracle's and what is the spec's.  The 16-byte XOR array and the 16-bit
XorKey come from msoffcrypto-tool's `DocumentXOR` (MIT), so the key material is the
oracle's own; the password verifier and the byte transformation are written here
from the pseudocode in [MS-OFFCRYPTO] 2.3.7.1 and 2.3.7.3 (`CreatePasswordVerifier_
Method1`, `EncryptData_Method1`) because msoffcrypto has no encrypt side for XOR.
Excel's own reading of the same derivations is what makes that safe: for the
password `testpass`, Excel 16's BIFF5 FILEPASS carries key 0xA6CE and verifier
0x9727, and those are the two words this script computes.

Which bytes are obfuscated ([MS-XLS] 2.2.10): every record body except BOF,
FILEPASS, UsrExcl, FileLock, InterfaceHdr, RRDInfo and RRDHead, and except the
`lbPlyPos` field of BoundSheet8; record headers never.  The XOR array index for the
byte at offset k of a record body ending at stream offset `end` is `(end + k) % 16`
-- msoffcrypto `format/xls97.py` (`(data_index + count) % 16`) and LibreOffice
`sc/source/filter/excel/xistream.cxx:189-193` (behaviour only) agree on it, and the
spec leaves the initial index to the application.  FILEPASS goes directly after the
first BOF ([MS-XLS] 2.1.7.20), so every later record -- and every `lbPlyPos` -- moves
by the 10 bytes it occupies.

Byte-reproducible: XOR obfuscation draws no randomness and the container is edited
in place (the stream grows by 10 bytes inside the slack of its last sector; the
directory entry's size field is the only other change), so a rerun writes the
identical file.

    py -3 tools/gen_xor_fixture.py

Verify with the oracle afterwards:

    py -3 -m msoffcrypto -p testpass tests/fixtures/excel97_xor.xls out.xls

Written against msoffcrypto-tool 6.0.0 and olefile 0.47.
"""

import hashlib
import io
import pathlib
import struct
import sys

import msoffcrypto
import olefile
from msoffcrypto.method.xor_obfuscation import DocumentXOR

HERE = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = HERE / "tests" / "fixtures"
SRC = FIXTURES / "excel97_plain.xls"
DST = FIXTURES / "excel97_xor.xls"
PASSWORD = "testpass"

BOF, FILEPASS, BOUNDSHEET8 = 0x0809, 0x002F, 0x0085
# [MS-XLS] 2.2.10: BOF, FilePass, UsrExcl, FileLock, InterfaceHdr, RRDInfo, RRDHead.
NEVER_OBFUSCATED = {BOF, FILEPASS, 0x0194, 0x0195, 0x00E1, 0x0196, 0x0138}
OLE_END_OF_CHAIN = 0xFFFFFFFE


def password_verifier(password: bytes) -> int:
    """[MS-OFFCRYPTO] 2.3.7.1 CreatePasswordVerifier_Method1."""
    verifier = 0
    for byte in reversed(bytes([len(password)]) + password):
        intermediate1 = 1 if verifier & 0x4000 else 0
        intermediate2 = (verifier * 2) & 0x7FFF
        verifier = (intermediate1 | intermediate2) ^ byte
    return verifier ^ 0xCE4B


def rol8(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (8 - bits))) & 0xFF


def records(stream: bytes):
    pos = 0
    while pos + 4 <= len(stream):
        rec, length = struct.unpack_from("<HH", stream, pos)
        yield rec, stream[pos + 4 : pos + 4 + length]
        pos += 4 + length
    if pos != len(stream):
        sys.exit(f"{SRC}: {len(stream) - pos} trailing bytes after the last record")


def obfuscate(workbook: bytes, password: str) -> bytes:
    pw = password.encode("ascii")
    if not 1 <= len(pw) <= 15:
        sys.exit("XOR passwords are 1 to 15 ASCII characters ([MS-OFFCRYPTO] 2.3.7.2)")
    xor_array = DocumentXOR.create_xor_array_method1(password)
    key = DocumentXOR.create_xor_key_method1(password)
    filepass = struct.pack("<HHHHH", FILEPASS, 6, 0x0000, key, password_verifier(pw))
    shift = len(filepass)

    recs = list(records(workbook))
    if recs[0][0] != BOF:
        sys.exit("the Workbook stream must open with BOF")

    out = bytearray()
    for i, (rec, body) in enumerate(recs):
        if i == 1:
            out += filepass
        body = bytearray(body)
        if rec == BOUNDSHEET8:
            (lb_ply_pos,) = struct.unpack_from("<I", body, 0)
            struct.pack_into("<I", body, 0, lb_ply_pos + shift)
        out += struct.pack("<HH", rec, len(body))
        end = len(out) + len(body)
        clear = len(body) if rec in NEVER_OBFUSCATED else (4 if rec == BOUNDSHEET8 else 0)
        for k, byte in enumerate(body):
            if k < clear:
                out.append(byte)
            else:
                # EncryptData_Method1: rotate left 5, then XOR.
                out.append(rol8(byte, 5) ^ xor_array[(end + k) % 16])
    return bytes(out)


def chain(ole: olefile.OleFileIO, start: int) -> list[int]:
    sectors = []
    sect = start
    while sect != OLE_END_OF_CHAIN:
        if sect >= len(ole.fat):
            sys.exit(f"FAT chain runs off the table at sector {sect}")
        sectors.append(sect)
        sect = ole.fat[sect]
    return sectors


def replace_stream_in_place(src: pathlib.Path, name: str, new: bytes) -> bytes:
    """The container bytes with stream `name` replaced by `new`, which may be up to one
    sector's slack longer than the original.  Nothing else in the file moves."""
    data = bytearray(src.read_bytes())
    ole = olefile.OleFileIO(str(src))
    ss = ole.sectorsize
    sid = ole._find(name)
    entry = ole.direntries[sid]
    if entry.size < ole.minisectorcutoff:
        sys.exit(f"{name} lives in the mini stream; this script edits FAT streams only")
    sectors = chain(ole, entry.isectStart)
    if len(new) > len(sectors) * ss:
        sys.exit(f"{name}: {len(new)} bytes do not fit in the {len(sectors)} allocated sectors")
    for i, sect in enumerate(sectors):
        piece = new[i * ss : (i + 1) * ss]
        off = (sect + 1) * ss
        data[off : off + len(piece)] = piece

    per_sector = ss // 128
    dir_sectors = chain(ole, ole.first_dir_sector)
    dir_off = (dir_sectors[sid // per_sector] + 1) * ss + (sid % per_sector) * 128
    (old_size,) = struct.unpack_from("<I", data, dir_off + 0x78)
    if old_size != entry.size:
        sys.exit("directory entry not where expected")
    struct.pack_into("<I", data, dir_off + 0x78, len(new))
    return bytes(data)


def main() -> None:
    src_ole = olefile.OleFileIO(str(SRC))
    workbook = src_ole.openstream("Workbook").read()
    obfuscated = obfuscate(workbook, PASSWORD)
    if len(obfuscated) != len(workbook) + 10:
        sys.exit("the obfuscated stream should be exactly one FILEPASS record longer")

    out = replace_stream_in_place(SRC, "Workbook", obfuscated)
    DST.write_bytes(out)

    # Read back through olefile, then through the oracle.
    check = olefile.OleFileIO(str(DST))
    if check.openstream("Workbook").read() != obfuscated:
        sys.exit("the rewritten container does not read back")
    with open(DST, "rb") as f:
        office = msoffcrypto.OfficeFile(f)
        office.load_key(password=PASSWORD)
        dec = io.BytesIO()
        office.decrypt(dec)
    print(f"{DST.name}: {len(out)} bytes, sha256 {hashlib.sha256(out).hexdigest()}")
    print(f"msoffcrypto -d: {len(dec.getvalue())} bytes, sha256 {hashlib.sha256(dec.getvalue()).hexdigest()}")


if __name__ == "__main__":
    main()
