# sting -- authenticated PNG steganography built on gisp.
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

"""sting -- hide an encrypted payload inside a PNG image, and recover it.

sting layers a low-capacity, pseudo-random least-significant-bit (LSB)
steganographic channel on top of the gisp file-encryption utility.  The
secret is never embedded in the clear: it is first passed through gisp for
XChaCha20-Poly1305 authenticated encryption with an Argon2id-derived key,
and only the resulting opaque container is scattered across the carrier.

Two properties are held throughout:

  * Confidentiality and integrity come entirely from gisp.  sting treats the
    ciphertext as an opaque blob; it never sees, derives, or stores the
    passphrase, so gisp's hardened (locked, guarded, wiped) key handling is
    not weakened by this wrapper.

  * Statistical undetectability comes from two design choices.  First, at
    most 3% of the carrier's usable samples are ever touched, keeping the
    embedding-rate far below the noise floor that RS / chi-square style
    steganalysis needs.  Second, the tool uses LSB *matching* (+/-1
    embedding) rather than LSB *replacement*, so it does not create the
    pair-of-values histogram signature that replacement is known for, and
    the touched samples are spread over the whole image by a keyed
    pseudo-random permutation rather than clustered.

The public entry point is stinglib.cli.main; the modules are:

    constants   identity, exit codes, and the on-image container format
    errors      the two exception types that steer exit status
    keystream   deterministic SHAKE-256 permutations and bit helpers
    carrier     PNG decode/encode and the "usable sample" model
    stego       the embed / extract core
    backend     invocation of the gisp subprocess
    streams     stdin/stdout- and file-aware byte I/O
    cli         command-line parsing and the mode handlers
"""

from .constants import VERSION

__version__ = VERSION
__all__ = ["main"]


def main(argv=None):
    """Convenience wrapper so ``stinglib.main()`` works like the CLI."""
    import sys
    from .cli import main as _main
    return _main(sys.argv[1:] if argv is None else argv)
