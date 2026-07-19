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

Placement is a keyed pseudo-random permutation of the usable-sample index
range [0, N) evaluated *on demand*: instead of materialising the whole
permutation, ``permutation_prefix`` returns only its first COUNT elements, so
peak memory is O(COUNT) rather than O(N).  The permutation is a balanced
Feistel network over the smallest power-of-two-with-even-exponent domain that
covers [0, N), with cycle-walking to fold that domain back onto [0, N).  Each
Feistel round mixes with a SHAKE-256-derived table, and the whole evaluation
is plain 64-bit integer arithmetic, so the layout stays bit-for-bit identical
across Python and NumPy versions -- both the embed and extract sides derive
the same slots from the same KEY and N.
"""

from hashlib import shake_256

import numpy as np

# Feistel rounds.  A balanced Feistel is a permutation for *any* round
# functions; the round count only governs mixing quality.  Six rounds give a
# comfortable margin for keyed, non-clustered placement.
_FEISTEL_ROUNDS = 6

# Domain separation for the per-round mixing tables.
_ROUND_TAG = b"sting/v2/feistel-round/"


def keystream(key, nbytes):
    """Return NBYTES deterministic bytes derived from KEY."""
    return shake_256(key).digest(nbytes)


def _domain_bits(n):
    """Smallest even bit-width W with 2**W >= N (at least 2)."""
    w = (n - 1).bit_length()
    if w & 1:
        w += 1
    return max(w, 2)


def _round_tables(key, w):
    """Build the per-round mixing tables for a W-bit Feistel over KEY.

    Each table maps an h-bit half (h = W/2) to an h-bit value, so it has
    2**h entries; the whole set is O(sqrt(domain)) = O(sqrt(N)) in size,
    independent of how many slots the caller ultimately reads.
    """
    h = w // 2
    size = 1 << h
    mask = size - 1
    tables = []
    for i in range(_FEISTEL_ROUNDS):
        raw = shake_256(key + _ROUND_TAG + bytes([i])).digest(size * 8)
        table = np.frombuffer(raw, dtype=">u8").astype(np.uint64) & mask
        tables.append(table)
    return tables


def _feistel_forward(x, tables, h, mask):
    """Apply the Feistel permutation to every value in the array X (< 2**W)."""
    left = (x >> np.uint64(h)) & mask
    right = x & mask
    for table in tables:
        left, right = right, (left ^ table[right]) & mask
    return (left << np.uint64(h)) | right


def permutation_prefix(key, n, count):
    """Return the first COUNT elements of the keyed permutation of [0, N).

    Equivalent to ``permutation(key, n)[:count]`` for the old full-array
    permutation, but evaluated lazily: only COUNT images are computed, so peak
    memory is O(COUNT + sqrt(N)) rather than O(N).
    """
    count = min(count, n)
    if count <= 0:
        return np.empty(0, dtype=np.int64)
    if n == 1:
        return np.zeros(1, dtype=np.int64)

    w = _domain_bits(n)
    h = w // 2
    mask = np.uint64((1 << h) - 1)
    tables = _round_tables(key, w)
    n_u = np.uint64(n)

    out = np.empty(count, dtype=np.int64)
    # Cycle-walking: start each rank at itself and re-encrypt until the image
    # lands inside [0, N).  The domain is < 2*N (worst case < 4*N), so the
    # expected number of passes per element is below 2 (worst case ~4).
    pos = np.arange(count)                       # output positions still walking
    cur = np.arange(count, dtype=np.uint64)      # their current domain value
    while pos.size:
        cur = _feistel_forward(cur, tables, h, mask)
        landed = cur < n_u
        if landed.any():
            done = pos[landed]
            out[done] = cur[landed].astype(np.int64)
            keep = ~landed
            pos = pos[keep]
            cur = cur[keep]
    return out


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
