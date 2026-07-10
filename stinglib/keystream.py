# sting -- deterministic keystream primitives for LSB placement.
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

"""Deterministic placement primitives.

Everything positional is derived from SHAKE-256, a standard-library
extendable-output function.  Using an explicit keystream (rather than the
language's PRNG) means the on-image layout is fixed forever and independent
of the Python or NumPy version that happens to be installed.
"""

from hashlib import shake_256

import numpy as np

from .constants import U64_BE


def keystream(key, nbytes):
    """Return NBYTES deterministic bytes derived from KEY."""
    return shake_256(key).digest(nbytes)


def permutation(key, n):
    """Return a deterministic permutation of range(N) as an index array.

    The permutation is the stable argsort of N keyed 64-bit values.  A stable
    sort makes the rare tie fully deterministic, so both the embed and the
    extract side always agree given the same KEY and N.
    """
    keys = np.frombuffer(keystream(key, 8 * n), dtype=U64_BE)
    return np.argsort(keys, kind="stable")


def directions(key, n):
    """Return an array of N pseudo-random steps, each +1 or -1."""
    raw = np.frombuffer(keystream(key, (n + 7) // 8), dtype=np.uint8)
    bits = np.unpackbits(raw)[:n]
    return np.where(bits == 1, 1, -1).astype(np.int16)


def bytes_to_bits(data):
    """Expand a bytes object to its bits, most-significant bit first."""
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def bits_to_bytes(bits):
    """Pack a bit array (length a multiple of 8) back into bytes."""
    return np.packbits(bits).tobytes()
