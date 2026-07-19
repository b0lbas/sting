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

Both sides derive the identical usable-sample set and identical slots from the
same inputs, so no side channel is needed.  There are two modes:

  * OPEN mode (no stego-key) -- DETECTABLE.  The header sits at a fixed public
    key and starts with a constant MAGIC, so anyone with sting can locate it
    and confirm that a payload is present.  It exists for compatibility and
    convenience and offers no stealth.

  * KEYED mode (a stego-key is supplied) -- STEALTHY.  Both the header and the
    payload are placed by keys derived from the secret stego-key, so neither
    can be located without it.  The keyed header carries no MAGIC and no CRC:
    there is deliberately nothing to recognise.  Presence and correctness are
    proven only by gisp successfully decrypting the recovered bytes, so a
    wrong stego-key is indistinguishable from a clean image.

The stego-key is an independent secret and is NOT the gisp passphrase: sting
uses it only to place bits, never for encryption, and it is never forwarded to
gisp.  Content confidentiality and integrity still come entirely from gisp's
authenticated encryption.
"""

import os
import zlib
from hashlib import shake_256

import numpy as np

from .constants import (HDR_LEN, KEY_HEADER_DIR, KEY_HEADER_DIR_KEYED,
                        KEY_HEADER_POS, KEY_HEADER_POS_KEYED, KEY_PAYLOAD_DIR,
                        KEY_PAYLOAD_DIR_KEYED, KEY_PAYLOAD_POS,
                        KEY_PAYLOAD_POS_KEYED, KEYED_HDR_LEN, MAGIC,
                        MAX_RATIO, STEGO_KEY_TAG)
from .errors import StingError
from .keystream import (bits_to_bytes, bytes_to_bits, directions,
                        permutation_prefix)


# One generic message for every keyed-mode miss, so a wrong stego-key and an
# image with nothing embedded are reported identically.
_KEYED_MISS = ("no payload recovered: wrong stego-key, or nothing is embedded "
               "here")


def stego_material(stego_key):
    """Derive fixed 32-byte placement material from a stego-key.

    STEGO_KEY may be a bytes object (KEYED mode) or None (OPEN mode); None maps
    to None so the rest of the module can treat "no key" uniformly.
    """
    if stego_key is None:
        return None
    return shake_256(STEGO_KEY_TAG + stego_key).digest(32)


def header_bits(sk):
    """On-image header size, in bits, for the mode selected by SK."""
    return (KEYED_HDR_LEN if sk is not None else HDR_LEN) * 8


# -- per-mode layout keys --------------------------------------------------

def _header_pos_key(sk):
    return KEY_HEADER_POS if sk is None else KEY_HEADER_POS_KEYED + sk


def _header_dir_key(sk):
    return KEY_HEADER_DIR if sk is None else KEY_HEADER_DIR_KEYED + sk


def _payload_pos_key(sk, seed):
    if sk is None:
        return KEY_PAYLOAD_POS + seed
    return KEY_PAYLOAD_POS_KEYED + sk + seed


def _payload_dir_key(sk, seed):
    if sk is None:
        return KEY_PAYLOAD_DIR + seed
    return KEY_PAYLOAD_DIR_KEYED + sk + seed


def _header_slots(n, sk):
    return permutation_prefix(_header_pos_key(sk), n, header_bits(sk))


def _payload_slots(n, sk, seed, header_slots, count):
    """Return the first COUNT payload slots for SEED, skipping header slots.

    Only a prefix of the payload permutation is generated.  At most
    ``header_slots.size`` of its elements can be header slots, so a prefix of
    length ``count + header_slots.size`` always yields at least COUNT survivors
    -- identical to filtering the full permutation and taking the first COUNT.
    """
    prefix = permutation_prefix(_payload_pos_key(sk, seed), n,
                                count + header_slots.size)
    taken = np.zeros(n, dtype=bool)
    taken[header_slots] = True
    free = prefix[~taken[prefix]]
    return free[:count]


def _build_header(sk, seed, length):
    """Serialise the on-image header for the mode selected by SK."""
    if sk is None:
        header = (MAGIC + bytes([0, 0]) + seed + length.to_bytes(8, "big"))
        header += (zlib.crc32(header) & 0xFFFFFFFF).to_bytes(4, "big")
        assert len(header) == HDR_LEN
    else:
        header = seed + length.to_bytes(8, "big")
        assert len(header) == KEYED_HDR_LEN
    return header


def _parse_header(sk, header):
    """Return (seed, length) from a header, or raise on a structural miss.

    In OPEN mode the MAGIC and CRC give a cheap, definite "nothing here" answer.
    In KEYED mode there is intentionally nothing to check: any 24 bytes parse,
    and the caller relies on the length bound plus gisp to reject a wrong key.
    """
    if sk is None:
        if header[:4] != MAGIC:
            raise StingError("no sting payload found in this image")
        if (zlib.crc32(header[:30]) & 0xFFFFFFFF) != int.from_bytes(
                header[30:34], "big"):
            raise StingError(
                "sting header failed its integrity check (image tampered or "
                "not produced by sting)")
        return header[6:22], int.from_bytes(header[22:30], "big")
    return header[0:16], int.from_bytes(header[16:24], "big")


def embed(carrier, ciphertext, ratio, stego_key=None):
    """Scatter CIPHERTEXT through CARRIER and return the stego PNG bytes.

    When STEGO_KEY is given (bytes), placement is keyed and no MAGIC is written
    (KEYED mode); otherwise the detectable OPEN layout is used.
    """
    sk = stego_material(stego_key)
    n = carrier.n_usable
    hbits = header_bits(sk)
    if n < hbits:
        raise StingError("carrier too small to hold the sting header")

    capacity = carrier.capacity_bytes(ratio, hbits)
    if len(ciphertext) > capacity:
        raise StingError(
            "carrier too small: payload is %d bytes but capacity at %.1f%% is "
            "%d bytes; use a larger carrier or a smaller secret"
            % (len(ciphertext), ratio * 100, capacity))

    seed = os.urandom(16)
    header = _build_header(sk, seed, len(ciphertext))

    payload_bits = len(ciphertext) * 8
    hslots = _header_slots(n, sk)
    pslots = _payload_slots(n, sk, seed, hslots, payload_bits)

    carrier.write(hslots, bytes_to_bits(header),
                  directions(_header_dir_key(sk), hbits))
    carrier.write(pslots, bytes_to_bits(ciphertext),
                  directions(_payload_dir_key(sk, seed), payload_bits))
    return carrier.to_png_bytes()


def extract(carrier, stego_key=None):
    """Recover and return the embedded ciphertext from CARRIER.

    STEGO_KEY selects the mode and must match the one used to embed.  A wrong
    keyed key (or a clean image) raises a single generic StingError, so the two
    cases cannot be told apart.
    """
    sk = stego_material(stego_key)
    n = carrier.n_usable
    hbits = header_bits(sk)
    if n < hbits:
        raise StingError(_KEYED_MISS if sk is not None
                         else "no sting payload found (carrier too small)")

    hslots = _header_slots(n, sk)
    header = bits_to_bytes(carrier.read(hslots))
    seed, length = _parse_header(sk, header)

    # Defence in depth: never trust a length the carrier could not legitimately
    # hold.  The bound is the capacity at MAX_RATIO -- the absolute ceiling
    # embed() enforces, so no genuine payload can exceed it -- and not the raw
    # sample count, which is some 33x looser.  A header claiming a payload that
    # fills the whole image would otherwise make us materialise slot arrays for
    # it before anything else could object, so this is what keeps a crafted
    # stego PNG from turning into a memory and CPU exhaustion vector.  In KEYED
    # mode the same bound is also what rejects most wrong keys, whose random
    # length field is overwhelmingly out of range.
    if length > carrier.capacity_bytes(MAX_RATIO, hbits):
        raise StingError(_KEYED_MISS if sk is not None
                         else "embedded length is impossible for this carrier")

    pslots = _payload_slots(n, sk, seed, hslots, length * 8)
    if pslots.size != length * 8:
        raise StingError(_KEYED_MISS if sk is not None
                         else "embedded payload is truncated or corrupt")
    return bits_to_bytes(carrier.read(pslots))
