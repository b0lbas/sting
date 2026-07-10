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

import numpy as np


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

# Fixed header carried inside the image, laid out as (all big-endian):
#
#   offset  size  field
#   ------  ----  ---------------------------------------------------------
#      0      4   MAGIC     "STG1"
#      4      1   FLAGS     reserved, currently 0
#      5      1   RESERVED  reserved, currently 0
#      6     16   SEED      per-image nonce keying the payload permutation
#     22      8   LENGTH    ciphertext length in bytes
#     30      4   CRC32     CRC-32 over bytes 0..29
#   --------------------------------------------------------------------- 34
#
# The CRC lets extraction reject a non-sting or damaged image *before* it
# trusts the length field, and the MAGIC gives a fast "nothing here" answer.
MAGIC = b"STG1"
HDR_LEN = 34
HDR_BITS = HDR_LEN * 8

# Domain-separated keys for the deterministic permutations and +/-1
# directions.  The header layout uses a fixed key so a reader can locate it
# with nothing but the image; the payload layout is keyed by the per-image
# SEED so its footprint differs for every carrier.
KEY_HEADER_POS = b"sting/v1/header-position"
KEY_HEADER_DIR = b"sting/v1/header-direction"
KEY_PAYLOAD_POS = b"sting/v1/payload-position/"
KEY_PAYLOAD_DIR = b"sting/v1/payload-direction/"

# Refuse absurdly large carriers: the permutation materialises one 64-bit
# sort key per usable sample, so this bounds peak memory to a sane figure.
MAX_CARRIER_SAMPLES = 64_000_000

# Sort keys are read from the keystream as unsigned big-endian 64-bit
# integers so a container is portable across machines of either byte order.
U64_BE = np.dtype(">u8")

# Per-mode carrier description: (colour channel offsets, alpha offset|None).
# These are the only PNG pixel modes sting embeds in directly; palette and
# bilevel carriers are promoted into one of these first (see carrier.py).
MODE_LAYOUT = {
    "L": ([0], None),
    "LA": ([0], 1),
    "RGB": ([0, 1, 2], None),
    "RGBA": ([0, 1, 2], 3),
}
