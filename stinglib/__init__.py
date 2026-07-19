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

Threat model -- what sting does and does not promise:

  * Content confidentiality and integrity come entirely from gisp.  sting
    treats the ciphertext as an opaque blob; it never sees, derives, or
    stores the passphrase, so gisp's hardened (locked, guarded, wiped) key
    handling is not weakened by this wrapper.  This holds unconditionally:
    even an adversary who *knows* a payload is present, and holds the stego
    image and the original carrier, learns nothing about the contents
    without the gisp passphrase.

  * Stealth -- concealing that a payload exists at all -- is a weaker and
    more conditional property.  It holds only against an adversary who sees
    just the stego object and does not hold sting's separate stego-key.  In
    that setting the payload's location is a secret-keyed pseudo-random
    permutation with nothing to recognise: no marker, no fixed header
    position.  Two design choices keep the *statistical* signal low rather
    than provably absent: at most 3% of usable samples are touched (well
    below the rate RS / chi-square steganalysis typically needs), and the
    tool uses LSB *matching* (+/-1) not LSB *replacement*, avoiding the
    pair-of-values histogram signature.  This lowers, but does not eliminate,
    the chance a determined steganalyst detects the channel.

  * Without a stego-key, sting runs in an explicitly DETECTABLE mode: the
    header sits at a fixed public location and carries a constant marker, so
    anyone with sting can confirm a payload is present (the contents still
    stay encrypted).  Use a stego-key when concealment matters.

  * No scheme offers stealth against an adversary who also holds the original
    carrier: a pixel-wise diff reveals every touched sample directly.  That
    is a fundamental limit of carrier-modifying steganography, not a defect
    in sting, and such comparison is outside the threat model.

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
