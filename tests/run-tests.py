#!/usr/bin/env python3
# sting -- self-test.
#
# Copyright (C) 2026 Uladzislau Bolbas
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Self-test for sting.

The pure steganographic layer (carrier + stego + keystream) is always
exercised and needs nothing but Pillow and NumPy.  When a gisp executable can
be found, a full command-line round-trip is added on top.
"""

import io
import os
import sys
import tempfile

# Run against the in-tree package regardless of the working directory.
_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, _ROOT)

import numpy as np
from PIL import Image

from stinglib import backend, cli
from stinglib.carrier import load_carrier
from stinglib.constants import MAX_RATIO
from stinglib.errors import StingError
from stinglib.stego import embed, extract

_failures = 0


def check(name, ok):
    global _failures
    sys.stdout.write("%-52s %s\n" % (name, "ok" if ok else "FAIL"))
    if not ok:
        _failures += 1


def _png_bytes(mode="RGB", size=(256, 256), seed=1):
    rng = np.random.default_rng(seed)
    if mode in ("L",):
        arr = rng.integers(0, 256, size[::-1], dtype=np.uint8)
    else:
        ch = len(mode)
        arr = rng.integers(0, 256, (size[1], size[0], ch), dtype=np.uint8)
        if mode == "RGBA":
            arr[..., 3] = 255
    buf = io.BytesIO()
    Image.frombytes(mode, size, arr.tobytes()).save(buf, format="PNG")
    return buf.getvalue()


def test_roundtrip_modes():
    for mode in ("L", "LA", "RGB", "RGBA"):
        carrier = load_carrier(_png_bytes(mode))
        secret = os.urandom(120)
        stego = embed(carrier, secret, MAX_RATIO)
        got = extract(load_carrier(stego))
        check("stego round-trip (%s)" % mode, got == secret)


def test_lsb_matching_and_density():
    raw = _png_bytes("RGB")
    cover = np.asarray(Image.open(io.BytesIO(raw))).astype(int)
    carrier = load_carrier(raw)
    stego_png = embed(carrier, os.urandom(300), MAX_RATIO)
    stego = np.asarray(Image.open(io.BytesIO(stego_png))).astype(int)
    delta = set(np.unique(stego - cover).tolist())
    check("modifications are +/-1 only (LSB matching)",
          delta.issubset({-1, 0, 1}))
    changed = int(np.count_nonzero(stego - cover))
    check("change density within 3% cap",
          changed <= MAX_RATIO * cover.size)


def test_no_payload_and_tamper():
    clean = load_carrier(_png_bytes("RGB", seed=7))
    try:
        extract(clean)
        check("clean image reports no payload", False)
    except StingError:
        check("clean image reports no payload", True)

    carrier = load_carrier(_png_bytes("RGB", seed=9))
    stego_png = embed(carrier, os.urandom(100), MAX_RATIO)
    arr = np.asarray(Image.open(io.BytesIO(stego_png))).copy()
    arr[0:32, 0:32, :] ^= 0x0F                      # corrupt a block
    buf = io.BytesIO()
    Image.fromarray(arr, "RGB").save(buf, format="PNG")
    try:
        extract(load_carrier(buf.getvalue()))
        check("tampered image is rejected", False)
    except StingError:
        check("tampered image is rejected", True)


def test_capacity_exceeded():
    carrier = load_carrier(_png_bytes("RGB", size=(64, 64)))
    try:
        embed(carrier, os.urandom(100000), MAX_RATIO)
        check("oversize payload is rejected", False)
    except StingError:
        check("oversize payload is rejected", True)


def test_palette_promotion():
    rng = np.random.default_rng(3)
    idx = rng.integers(0, 256, (160, 160), dtype=np.uint8)
    pal = Image.fromarray(idx, "P")
    pal.putpalette(list(rng.integers(0, 256, 768, dtype=np.uint8)))
    buf = io.BytesIO()
    pal.save(buf, format="PNG")
    carrier = load_carrier(buf.getvalue(), quiet=True)
    secret = os.urandom(50)
    stego = embed(carrier, secret, MAX_RATIO)
    check("palette carrier is promoted and round-trips",
          extract(load_carrier(stego)) == secret)


def test_full_cli_with_gisp():
    try:
        gisp = backend.locate_gisp(None)
    except StingError:
        sys.stdout.write("%-52s %s\n" % ("full gisp CLI round-trip",
                                         "skipped (gisp not found)"))
        return
    with tempfile.TemporaryDirectory() as d:
        cover = os.path.join(d, "cover.png")
        stego = os.path.join(d, "stego.png")
        secret = os.path.join(d, "secret.bin")
        out = os.path.join(d, "out.bin")
        passf = os.path.join(d, "pass.txt")
        data = os.urandom(256)
        open(cover, "wb").write(_png_bytes("RGB", size=(256, 256)))
        open(secret, "wb").write(data)
        open(passf, "w").write("a strong passphrase here")

        rc = cli.main(["-H", "-c", cover, "-i", secret, "-o", stego,
                       "--passphrase-file", passf, "-q", "--gisp", gisp])
        rc |= cli.main(["-X", "-i", stego, "-o", out,
                        "--passphrase-file", passf, "-q", "--gisp", gisp])
        ok = (rc == 0) and os.path.exists(out) and open(out, "rb").read() == data
        check("full gisp CLI round-trip", ok)


def main():
    test_roundtrip_modes()
    test_lsb_matching_and_density()
    test_no_payload_and_tamper()
    test_capacity_exceeded()
    test_palette_promotion()
    test_full_cli_with_gisp()
    sys.stdout.write("\n%s\n" % ("all tests passed" if _failures == 0
                                 else "%d test(s) FAILED" % _failures))
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
