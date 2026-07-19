# sting -- shared constants: identity, exit status, and container format.
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

"""Constants shared across the package.

Kept dependency-light so every other module may import it without risk of a
cycle.
"""

import os
import sys


# --------------------------------------------------------------------------
# Program identity.
# --------------------------------------------------------------------------

def _program_name():
    """The name to print in diagnostics.

    Follows argv[0] so a renamed launcher reports its own name, but falls
    back to "sting" when invoked in a way that would otherwise show an
    unhelpful token (``python -m stinglib`` or a ``*.py`` path).
    """
    name = os.path.basename(sys.argv[0] or "")
    if not name or name.startswith("-") or name.endswith(".py"):
        return "sting"
    return name


PROGRAM_NAME = _program_name()
VERSION = "1.0"
BUG_ADDRESS = "cmrtumilovic@gmail.com"


# --------------------------------------------------------------------------
# Exit status, kept identical to gisp so the two compose predictably:
#   0  success
#   1  operational failure (bad password, tampered/corrupt data, I/O error)
#   2  command-line usage error
# --------------------------------------------------------------------------

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2


# --------------------------------------------------------------------------
# Steganographic parameters and the on-image container format.
# --------------------------------------------------------------------------

# Absolute ceiling on the fraction of usable samples that may be modified.
# The manual promise of "max 3%" is enforced here and cannot be raised from
# the command line; a lower value may be requested for extra margin.
MAX_RATIO = 0.03

# Container format v2 has two on-image header layouts, chosen by whether a
# stego-key is in use.  They are never confused because the *reader* selects
# the mode: extraction with a stego-key only ever looks for a keyed header,
# and extraction without one only ever looks for an open header.
#
# OPEN mode (no stego-key) -- DETECTABLE.  The header sits at a fixed, public
# key and starts with a constant MAGIC, so anyone holding sting can locate it
# and confirm a payload is present.  This mode exists for compatibility and
# convenience; it provides NO stealth.  Layout (all big-endian):
#
#   offset  size  field
#   ------  ----  ---------------------------------------------------------
#      0      4   MAGIC     "STG2"
#      4      1   FLAGS     reserved, currently 0
#      5      1   RESERVED  reserved, currently 0
#      6     16   SEED      per-image nonce keying the payload permutation
#     22      8   LENGTH    ciphertext length in bytes
#     30      4   CRC32     CRC-32 over bytes 0..29
#   --------------------------------------------------------------------- 34
#
# The CRC lets extraction reject a non-sting or damaged image *before* it
# trusts the length field, and the MAGIC gives a fast "nothing here" answer.
MAGIC = b"STG2"
HDR_LEN = 34
HDR_BITS = HDR_LEN * 8

# KEYED mode (stego-key set) -- STEALTHY.  The header is located by a key
# derived from the secret stego-key, so it cannot be found without it, and it
# carries NO MAGIC and NO CRC: there is deliberately nothing to recognise.
# Presence and correctness are proven only by gisp successfully decrypting the
# recovered bytes.  Layout (all big-endian):
#
#   offset  size  field
#   ------  ----  ---------------------------------------------------------
#      0     16   SEED      per-image nonce, also mixed with the stego-key
#     16      8   LENGTH    ciphertext length in bytes
#   --------------------------------------------------------------------- 24
KEYED_HDR_LEN = 24
KEYED_HDR_BITS = KEYED_HDR_LEN * 8

# Domain-separated keys for the deterministic permutations and +/-1
# directions.
#
# OPEN mode: the header uses a fixed public key so a reader can locate it with
# nothing but the image; the payload layout is keyed by the per-image SEED so
# its footprint differs for every carrier (but is still locatable, since SEED
# is read from the open header).
KEY_HEADER_POS = b"sting/v2/open-header-position"
KEY_HEADER_DIR = b"sting/v2/open-header-direction"
KEY_PAYLOAD_POS = b"sting/v2/open-payload-position/"
KEY_PAYLOAD_DIR = b"sting/v2/open-payload-direction/"

# KEYED mode: every layout key is additionally bound to the secret stego-key
# material, so neither the header nor the payload can be located without it.
# The payload keys mix in both the stego-key material and the per-image SEED.
STEGO_KEY_TAG = b"sting/v2/stego-key/"
KEY_HEADER_POS_KEYED = b"sting/v2/keyed-header-position/"
KEY_HEADER_DIR_KEYED = b"sting/v2/keyed-header-direction/"
KEY_PAYLOAD_POS_KEYED = b"sting/v2/keyed-payload-position/"
KEY_PAYLOAD_DIR_KEYED = b"sting/v2/keyed-payload-direction/"

# Refuse absurdly large carriers.  Placement no longer materialises a per-
# sample sort key (the keyed permutation is now an on-demand Feistel network,
# O(slots) in memory -- see keystream.py), so the peak-memory driver is instead
# the carrier's own usable-index array, one int64 per usable sample.  This cap
# bounds that array to ~1 GiB, which comfortably covers any real photographic
# carrier while still refusing a decompression-bomb-sized input.
MAX_CARRIER_SAMPLES = 128_000_000

# Per-mode carrier description: (colour channel offsets, alpha offset|None).
# These are the only PNG pixel modes sting embeds in directly; palette and
# bilevel carriers are promoted into one of these first (see carrier.py).
MODE_LAYOUT = {
    "L": ([0], None),
    "LA": ([0], 1),
    "RGB": ([0, 1, 2], None),
    "RGBA": ([0, 1, 2], 3),
}
