# sting -- the embed / extract core.
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

"""Scatter a ciphertext through a carrier's LSBs, and gather it back.

The header is located by a fixed-key permutation so a reader can find it
with nothing but the image; it in turn carries the per-image SEED that keys
the payload permutation over the remaining samples.  Both sides derive the
same layout from the same keys, so no side channel is needed.
"""

import os
import zlib

import numpy as np

from .constants import (HDR_BITS, HDR_LEN, KEY_HEADER_DIR, KEY_HEADER_POS,
                        KEY_PAYLOAD_DIR, KEY_PAYLOAD_POS, MAGIC)
from .errors import StingError
from .keystream import (bits_to_bytes, bytes_to_bits, directions, permutation)


def _header_slots(n):
    return permutation(KEY_HEADER_POS, n)[:HDR_BITS]


def _payload_slots(n, seed, header_slots, count):
    """Return the first COUNT payload slots for SEED, skipping header slots."""
    order = permutation(KEY_PAYLOAD_POS + seed, n)
    taken = np.zeros(n, dtype=bool)
    taken[header_slots] = True
    free = order[~taken[order]]
    return free[:count]


def embed(carrier, ciphertext, ratio):
    """Scatter CIPHERTEXT through CARRIER and return the stego PNG bytes."""
    n = carrier.n_usable
    if n < HDR_BITS:
        raise StingError("carrier too small to hold the sting header")

    capacity = carrier.capacity_bytes(ratio)
    if len(ciphertext) > capacity:
        raise StingError(
            "carrier too small: payload is %d bytes but capacity at %.1f%% is "
            "%d bytes; use a larger carrier or a smaller secret"
            % (len(ciphertext), ratio * 100, capacity))

    seed = os.urandom(16)
    header = (MAGIC + bytes([0, 0]) + seed
              + len(ciphertext).to_bytes(8, "big"))
    header += (zlib.crc32(header) & 0xFFFFFFFF).to_bytes(4, "big")
    assert len(header) == HDR_LEN

    payload_bits = len(ciphertext) * 8
    hslots = _header_slots(n)
    pslots = _payload_slots(n, seed, hslots, payload_bits)

    carrier.write(hslots, bytes_to_bits(header),
                  directions(KEY_HEADER_DIR, HDR_BITS))
    carrier.write(pslots, bytes_to_bits(ciphertext),
                  directions(KEY_PAYLOAD_DIR + seed, payload_bits))
    return carrier.to_png_bytes()


def extract(carrier):
    """Recover and return the embedded ciphertext from CARRIER."""
    n = carrier.n_usable
    if n < HDR_BITS:
        raise StingError("no sting payload found (carrier too small)")

    hslots = _header_slots(n)
    header = bits_to_bytes(carrier.read(hslots))

    if header[:4] != MAGIC:
        raise StingError("no sting payload found in this image")
    if (zlib.crc32(header[:30]) & 0xFFFFFFFF) != int.from_bytes(
            header[30:34], "big"):
        raise StingError(
            "sting header failed its integrity check (image tampered or "
            "not produced by sting)")

    seed = header[6:22]
    length = int.from_bytes(header[22:30], "big")

    # Defence in depth: even with a valid CRC, never trust a length that the
    # carrier physically cannot hold.
    if length * 8 > n - HDR_BITS:
        raise StingError("embedded length is impossible for this carrier")

    pslots = _payload_slots(n, seed, hslots, length * 8)
    if pslots.size != length * 8:
        raise StingError("embedded payload is truncated or corrupt")
    return bits_to_bytes(carrier.read(pslots))
