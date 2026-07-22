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
import stat
import sys
import tempfile
import tracemalloc
import zlib

# Run against the in-tree package regardless of the working directory.
_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, _ROOT)

import numpy as np
from PIL import Image

from stinglib import backend, cli, streams
from stinglib.carrier import load_carrier
from stinglib.constants import HDR_LEN, KEY_HEADER_DIR, MAGIC, MAX_RATIO
from stinglib.errors import StingError
from stinglib.keystream import bytes_to_bits, directions, permutation_prefix
from stinglib.stego import (_header_slots, embed, extract, header_bits,
                            stego_material)

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


def test_crafted_length_is_bounded():
    """A header may not claim more than the MAX_RATIO capacity.

    The bound must be the capacity ceiling, not the raw sample count: a
    crafted header claiming a payload that fills the whole image would
    otherwise make extract() materialise slot arrays for it, turning a stego
    PNG into a memory and CPU exhaustion vector.
    """
    raw = _png_bytes("RGB", size=(400, 400))
    carrier = load_carrier(raw)
    n = carrier.n_usable
    hbits = HDR_LEN * 8

    # Forge an open-mode header (MAGIC + valid CRC) declaring a payload that
    # occupies nearly every usable sample -- ~33x what embed() would ever emit.
    length = (n - hbits) // 8
    hdr = MAGIC + bytes([0, 0]) + os.urandom(16) + length.to_bytes(8, "big")
    hdr += (zlib.crc32(hdr) & 0xFFFFFFFF).to_bytes(4, "big")
    carrier.write(_header_slots(n, None), bytes_to_bits(hdr),
                  directions(KEY_HEADER_DIR, hbits))
    try:
        extract(load_carrier(carrier.to_png_bytes()))
        check("crafted oversize length is rejected", False)
    except StingError:
        check("crafted oversize length is rejected", True)

    # ...while a legitimately maximal payload must still round-trip, in both
    # modes, so the new bound cannot be off by a byte.
    ok = True
    for key in (None, b"a-stego-key"):
        hb = header_bits(stego_material(key))
        cap = load_carrier(raw).capacity_bytes(MAX_RATIO, hb)
        secret = os.urandom(cap)
        stego = embed(load_carrier(raw), secret, MAX_RATIO, stego_key=key)
        if extract(load_carrier(stego), stego_key=key) != secret:
            ok = False
    check("payload at exactly capacity still round-trips", ok)


def test_output_permissions():
    """Stego images blend in; recovered secrets stay private.

    A 0600 picture sitting among 0644 neighbours is exactly the anomaly the
    metadata stripping works to avoid, so --hide output takes the umask
    default.  A recovered secret keeps mkstemp's 0600, matching gisp.
    """
    with tempfile.TemporaryDirectory() as d:
        mask = os.umask(0o022)
        os.umask(mask)
        expected = 0o666 & ~mask

        public = os.path.join(d, "stego.png")
        private = os.path.join(d, "secret.bin")
        streams.write_bytes(public, b"image", private=False)
        streams.write_bytes(private, b"secret")
        check("stego output follows the umask",
              stat.S_IMODE(os.stat(public).st_mode) == expected)
        check("recovered secret stays 0600",
              stat.S_IMODE(os.stat(private).st_mode) == 0o600)

        # An existing file keeps whatever mode it already had.
        kept = os.path.join(d, "kept.png")
        open(kept, "wb").close()
        os.chmod(kept, 0o640)
        streams.write_bytes(kept, b"image", private=False)
        check("existing output keeps its mode",
              stat.S_IMODE(os.stat(kept).st_mode) == 0o640)


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


def _png_chunk_types(png):
    """Return the list of chunk type tags present in a PNG byte string."""
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    types = []
    i = 8
    while i + 12 <= len(png):
        length = int.from_bytes(png[i:i + 4], "big")
        types.append(png[i + 4:i + 8])
        i += 12 + length
    return types


def test_png_fingerprint():
    # Build a cover that deliberately carries ancillary metadata chunks, then
    # confirm the stego output has stripped every one of them and still decodes
    # and extracts.
    from PIL import PngImagePlugin
    rng = np.random.default_rng(4)
    arr = rng.integers(0, 256, (128, 128, 3), dtype=np.uint8)
    info = PngImagePlugin.PngInfo()
    info.add_text("Software", "definitely-not-sting 9.9")
    info.add_text("Comment", "hello")
    buf = io.BytesIO()
    Image.fromarray(arr, "RGB").save(buf, format="PNG", pnginfo=info,
                                     dpi=(72, 72))
    cover = buf.getvalue()
    check("cover fixture actually has metadata",
          any(t in _png_chunk_types(cover)
              for t in (b"tEXt", b"iTXt", b"zTXt", b"pHYs", b"tIME")))

    secret = os.urandom(40)
    stego = embed(load_carrier(cover), secret, MAX_RATIO)
    types = set(_png_chunk_types(stego))
    telltale = {b"tEXt", b"iTXt", b"zTXt", b"tIME", b"gAMA", b"cHRM",
                b"sRGB", b"iCCP", b"pHYs"}
    check("stego output carries no ancillary/metadata chunks",
          not (types & telltale))
    check("stego output keeps only decode-essential chunks",
          types.issubset({b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS"}))
    check("stripped stego still extracts",
          extract(load_carrier(stego)) == secret)

    # Colour type and bit depth are preserved across the modes.
    depth_ok = True
    for mode in ("L", "LA", "RGB", "RGBA"):
        stego = embed(load_carrier(_png_bytes(mode, seed=5)), os.urandom(20),
                      MAX_RATIO)
        if load_carrier(stego).mode != mode:
            depth_ok = False
    check("stego preserves 8-bit colour type across modes", depth_ok)


def test_stego_key():
    key = b"correct-stego-key"
    secret = os.urandom(120)
    stego = embed(load_carrier(_png_bytes("RGB", seed=21)), secret, MAX_RATIO,
                  stego_key=key)

    # Same stego-key round-trips.
    check("keyed stego round-trips",
          extract(load_carrier(stego), stego_key=key) == secret)

    # A keyed image carries no locatable open header (no MAGIC): open-mode
    # extraction must report nothing found.
    try:
        extract(load_carrier(stego))
        check("keyed image exposes no open header", False)
    except StingError:
        check("keyed image exposes no open header", True)

    # A wrong stego-key is rejected exactly like a clean image + a key: same
    # error text, so the two are indistinguishable.
    msg_wrong = msg_clean = None
    try:
        extract(load_carrier(stego), stego_key=b"the-wrong-key")
    except StingError as exc:
        msg_wrong = str(exc)
    try:
        extract(load_carrier(_png_bytes("RGB", seed=99)), stego_key=key)
    except StingError as exc:
        msg_clean = str(exc)
    check("wrong stego-key finds nothing",
          msg_wrong is not None and msg_clean is not None)
    check("wrong key and clean image are indistinguishable",
          msg_wrong == msg_clean)

    # An open-mode image is not readable with a stego-key, and vice versa.
    open_stego = embed(load_carrier(_png_bytes("RGB", seed=21)), secret,
                       MAX_RATIO)
    try:
        extract(load_carrier(open_stego), stego_key=key)
        check("open image not readable with a key", False)
    except StingError:
        check("open image not readable with a key", True)

    # Placement is genuinely key-dependent: header slots differ between two
    # keys and between keyed and open modes.
    n = load_carrier(_png_bytes("RGB", seed=21)).n_usable
    ha = _header_slots(n, stego_material(b"A"))
    hb = _header_slots(n, stego_material(b"B"))
    ho = _header_slots(n, None)
    check("stego-key changes header placement", not np.array_equal(ha, hb))
    check("keyed placement differs from open", not np.array_equal(ha, ho))


def test_feistel_permutation():
    # A full-length prefix must be an exact permutation of range(n), for a
    # spread of sizes including odd and power-of-two-adjacent edge cases.
    bijection = True
    for n in (1, 2, 3, 5, 8, 17, 256, 257, 4096, 10007):
        p = permutation_prefix(b"k", n, n)
        if sorted(p.tolist()) != list(range(n)):
            bijection = False
    check("keyed permutation is a bijection (many n)", bijection)

    # Determinism across runs: same key + n + count -> identical output.
    a = permutation_prefix(b"key", 1_000_000, 4000)
    b = permutation_prefix(b"key", 1_000_000, 4000)
    check("permutation is deterministic", np.array_equal(a, b))

    # A short prefix equals the head of the full permutation.
    full = permutation_prefix(b"key2", 5000, 5000)
    pref = permutation_prefix(b"key2", 5000, 137)
    check("prefix equals head of full permutation",
          np.array_equal(pref, full[:137]))

    # First k slots of a large carrier are unique and in range.
    n, k = 60_000_000, 100_000
    slots = permutation_prefix(b"payload", n, k)
    check("first k slots unique and within [0, n)",
          len(np.unique(slots)) == k
          and int(slots.min()) >= 0 and int(slots.max()) < n)

    # Distinct keys give distinct orders.
    check("placement is key-dependent",
          not np.array_equal(permutation_prefix(b"a", 100_000, 500),
                             permutation_prefix(b"b", 100_000, 500)))

    # Peak memory is O(slots), not O(n): reading 200k slots from a 100M-sample
    # carrier must stay far below the ~800 MB the old full argsort needed.
    tracemalloc.start()
    permutation_prefix(b"mem", 100_000_000, 200_000)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    check("peak memory is O(slots) not O(n)", peak < 100_000_000)


def test_highlight_payload_parser():
    """Malformed options must die with a message, not a traceback."""
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader(
        "highlight_payload", os.path.join(_ROOT, "tools", "highlight-payload"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    hp = importlib.util.module_from_spec(spec)
    loader.exec_module(hp)

    bad = [
        ["a.png", "b.png", "--radius"],        # trailing flag, no value
        ["a.png", "b.png", "--stego-key"],
        ["a.png", "b.png", "--radius", "x"],   # non-numeric value
        ["a.png", "b.png", "--dim", "wide"],
    ]
    ok = True
    stderr, sys.stderr = sys.stderr, io.StringIO()
    try:
        for argv in bad:
            try:
                hp.parse_args(argv)
                ok = False
            except SystemExit as exc:
                ok = ok and exc.code == 1
        good = hp.parse_args(["a.png", "b.png", "--radius", "2", "--dim", ".5"])
    finally:
        sys.stderr = stderr
    check("highlight-payload rejects malformed options", ok)
    check("highlight-payload still accepts valid options",
          good.radius == 2 and good.dim == 0.5 and good.src == "a.png")


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

        # The same round-trip in keyed (stealth) mode; the stego-key is a
        # separate secret from the gisp passphrase.
        kstego = os.path.join(d, "kstego.png")
        kout = os.path.join(d, "kout.bin")
        rc = cli.main(["-H", "-c", cover, "-i", secret, "-o", kstego,
                       "--stego-key", "a-second-secret", "--passphrase-file",
                       passf, "-q", "--gisp", gisp])
        rc |= cli.main(["-X", "-i", kstego, "-o", kout, "--stego-key",
                        "a-second-secret", "--passphrase-file", passf, "-q",
                        "--gisp", gisp])
        kok = (rc == 0) and os.path.exists(kout) \
            and open(kout, "rb").read() == data
        # Without the stego-key the same image yields nothing (exit 1).
        rc_nokey = cli.main(["-X", "-i", kstego, "-o", os.devnull,
                             "--passphrase-file", passf, "-q", "--gisp", gisp])
        check("full gisp CLI round-trip (keyed)", kok and rc_nokey != 0)


def main():
    test_roundtrip_modes()
    test_lsb_matching_and_density()
    test_no_payload_and_tamper()
    test_crafted_length_is_bounded()
    test_output_permissions()
    test_capacity_exceeded()
    test_palette_promotion()
    test_png_fingerprint()
    test_stego_key()
    test_feistel_permutation()
    test_highlight_payload_parser()
    test_full_cli_with_gisp()
    sys.stdout.write("\n%s\n" % ("all tests passed" if _failures == 0
                                 else "%d test(s) FAILED" % _failures))
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
