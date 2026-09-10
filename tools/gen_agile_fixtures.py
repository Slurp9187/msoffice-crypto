#!/usr/bin/env python3
"""Generate the non-SHA-512 agile fixtures in tests/fixtures/.

Why a foreign writer rather than this crate's own encrypt path: the crate has no
encrypt path yet (plan slice S5), and a round trip against a writer we also wrote
proves only that we agree with ourselves.  msoffcrypto-tool is an independent MIT
implementation with its own reading of [MS-OFFCRYPTO], so a fixture it writes and
this crate reads back to a byte-identical known plaintext is cross-implementation
evidence.  See CLAUDE.md § Testing Rules, "Generate fixtures, don't copy them".

What it does NOT prove: agreement with Microsoft's writer.  No AES-256/SHA-384 or
AES-256/SHA-256 file produced by real Office exists in any local corpus, and none
can be produced on this machine.  Say that, do not imply interop with Office.

The one modification to the oracle: msoffcrypto's agile writer hardcodes its
parameter tuple in `ECMA376AgileCipherParams.__init__` (the class comment says
"Hardcoded to AES256 + SHA512 for OOXML") and exposes no way to pass another one
through `encrypt()`.  This replaces that `__init__`; everything downstream --
the KDF, the verifier blobs, the payload segmentation, the dataIntegrity HMAC,
the XML, the CFB container -- is stock msoffcrypto.

`_random_buffer` is replaced with a deterministic SHAKE-256 stream so a rerun
produces cryptographically identical files.  The container is still not
byte-reproducible: the CFB directory entries carry creation/modification
FILETIMEs, which differ between runs.

    py -3 tools/gen_agile_fixtures.py

Validate with the oracle's own independent read path (no --verify flag exists, so
`verify_integrity` defaults off; run it from Python for the SHA-1 file, whose
zero-padded blobs it verifies -- HMAC zero-extends a short key, and the value
comparison is what actually gates it, see the CHANGELOG for 2026-09-05):

    py -3 -m msoffcrypto -p testpass tests/fixtures/agile_aes256_sha384.docx out.docx
    cmp out.docx tests/fixtures/plain.docx

Written against msoffcrypto-tool 6.x, ecma376_agile.py as of 2026-09-04.
"""

import hashlib
import io
import pathlib
import sys

import msoffcrypto.method.ecma376_agile as A

HERE = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = HERE / "tests" / "fixtures"
PASSWORD = "testpass"
SPIN_COUNT = 100000

# Every random draw in the writer -- both salts, the verifier input, the secret
# key, the HMAC key -- comes off this stream, so the seed below is the whole
# provenance of the fixture's key material.
SEED = b"msoffice-crypto agile fixture seed 2026-09-04"

_orig_init = A.ECMA376AgileCipherParams.__init__
_orig_random = A._random_buffer
_orig_get_salt = A._get_salt
_orig_encrypt_cbc = A._encrypt_aes_cbc


def _padded_encrypt_aes_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    """msoffcrypto's writer hands AES-CBC whatever length it has, and for SHA-1 the
    dataIntegrity HMAC key and value are 20 bytes -- not a block multiple -- so its
    generate_integrity_parameter crashes with "not a multiple of the block length" and
    it cannot write a SHA-1 file at all (ecma376_agile.py:413). Pad to a block multiple
    with ZEROS, the byte msoffcrypto itself uses for the verifier hash (_resize_buffer's
    default, :51, :339) and the only one real Word accepts: a 0x36 pad here -- LibreOffice's
    choice (AgileEngine.cxx:654-656, behaviour only) and this generator's first attempt --
    passes Word's verifier and then fails its integrity check with 0x800A1066, because
    Word keys the HMAC with the whole decrypted blob and compares the whole decrypted
    value. Measured 2026-09-05, thirteen variants; recorded in CHANGELOG.md. A no-op for
    every input that is already a block multiple, i.e. everything else."""
    rem = len(data) % 16
    if rem:
        data = data + b"\x00" * (16 - rem)
    return _orig_encrypt_cbc(data, key, iv)


def _seeded_random(seed: bytes):
    stream = hashlib.shake_256(seed)
    state = {"n": 0}

    def draw(size: int) -> bytes:
        # SHAKE is an XOF: take a fresh, longer squeeze each call and hand back
        # the tail, so successive draws never overlap.
        state["n"] += size
        return stream.digest(state["n"])[-size:]

    return draw


def generate(key_bits: int, hash_name: str, hash_size: int, out_name: str) -> None:
    def patched_init(self):
        _orig_init(self)
        self.keyBits = key_bits
        self.hashName = hash_name
        self.hashSize = hash_size

    A.ECMA376AgileCipherParams.__init__ = patched_init
    draw = _seeded_random(SEED + out_name.encode())
    A._random_buffer = draw
    # keyData.saltValue is drawn through _get_salt, not _random_buffer, so until this
    # hook the docstring's "every random draw comes off this stream" was false: the
    # package salt came from os.urandom, and regenerating a fixture changed its bytes.
    # Measured 2026-09-05 -- both committed fixtures differed from a rerun.
    A._get_salt = lambda salt_value=None, salt_size=16: salt_value if salt_value is not None else draw(salt_size)
    A._encrypt_aes_cbc = _padded_encrypt_aes_cbc
    try:
        plain = (FIXTURES / "plain.docx").read_bytes()
        encrypted = A.ECMA376Agile.encrypt(
            PASSWORD, io.BytesIO(plain), spin_count=SPIN_COUNT
        )
    finally:
        A.ECMA376AgileCipherParams.__init__ = _orig_init
        A._random_buffer = _orig_random
        A._get_salt = _orig_get_salt
        A._encrypt_aes_cbc = _orig_encrypt_cbc

    (FIXTURES / out_name).write_bytes(encrypted)
    print(f"wrote {out_name}: {len(encrypted)} bytes  ({hash_name}, keyBits={key_bits})")


def main() -> int:
    if not (FIXTURES / "plain.docx").exists():
        print("tests/fixtures/plain.docx is missing", file=sys.stderr)
        return 1
    # Issue #11 -- the hash dimension, at the key size the crate already read.
    generate(256, "SHA384", 48, "agile_aes256_sha384.docx")
    generate(256, "SHA256", 32, "agile_aes256_sha256.docx")
    # Issue #13 -- the keyBits dimension: the three tuples LibreOffice accepts besides
    # Office 16's own (AgileEngine.cxx:574-612), with AES-128/SHA-1 being Word 2010's
    # default. msoffcrypto's writer sizes the session key from keyBits and its AES from
    # the key it is handed, so the same __init__ hook that varied the hash varies these.
    generate(128, "SHA1", 20, "agile_aes128_sha1.docx")
    generate(128, "SHA384", 48, "agile_aes128_sha384.docx")
    generate(192, "SHA384", 48, "agile_aes192_sha384.docx")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
