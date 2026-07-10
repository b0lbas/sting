# sting -- command-line parsing and the mode handlers.
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

"""The command-line front end: parse arguments, dispatch, map errors."""

import getopt
import sys

import numpy as np
import PIL

from .backend import gisp_decrypt, gisp_encrypt, locate_gisp
from .carrier import load_carrier
from .constants import (BUG_ADDRESS, EXIT_FAIL, EXIT_OK, EXIT_USAGE, HDR_BITS,
                        MAX_RATIO, PROGRAM_NAME, VERSION)
from .errors import StingError, UsageError
from .stego import embed, extract
from .streams import is_stdio, read_bytes, write_bytes


USAGE = """\
Usage: %(prog)s --hide    -c CARRIER [-i SECRET] [-o STEGO]  [gisp options]
       %(prog)s --extract [-i STEGO]  [-o SECRET]            [gisp options]
       %(prog)s --capacity -c CARRIER

Hide an encrypted payload inside a PNG, or recover one.  The secret is
encrypted with gisp (XChaCha20-Poly1305 / Argon2id) before being scattered,
at most 3%% of the carrier's samples, across the image by LSB matching.
A path of '-' selects standard input or standard output.

Mode:
  -H, --hide               Encrypt SECRET and embed it into CARRIER
  -X, --extract            Recover and decrypt the payload from STEGO
      --capacity           Report how much CARRIER can hold, then exit

Files:
  -c, --carrier <file>     Cover PNG to embed into (hide/capacity)
  -i, --in <file>          Secret to hide, or stego PNG to read (default: -)
  -o, --output <file>      Where to write the result (default: -)
      --ratio <fraction>   Cap on samples modified, 0<r<=0.03 (default: 0.03)

Passphrase (passed straight through to gisp):
      --passphrase-fd <n>      Read the passphrase from file descriptor N
      --passphrase-file <f>    Read the passphrase from file F

Key derivation, forwarded to gisp when hiding:
  -p, --opslimit <num>     Argon2id CPU ops limit
  -m, --memlimit <bytes>   Argon2id memory limit in bytes

Resource ceilings, forwarded to gisp when extracting:
      --max-opslimit <num>
      --max-memlimit <bytes>
      --max-filesize <bytes>
      --min-password-length <n>
      --allow-weak-password

  -g, --gisp <path>        Path to the gisp executable
  -q, --quiet              Suppress non-error messages
  -h, --help               Display this help and exit
  -v, --version            Display version information and exit

Report bugs to: <%(bug)s>
""" % {"prog": PROGRAM_NAME, "bug": BUG_ADDRESS}


class Options:
    """Parsed command-line state."""

    def __init__(self):
        self.mode = None                  # "hide" | "extract" | "capacity"
        self.carrier = None
        self.infile = "-"
        self.output = "-"
        self.ratio = MAX_RATIO
        self.gisp = None
        self.quiet = False
        # gisp pass-through, collected verbatim.
        self.pass_opts = []
        self.pass_fd = None
        self.kdf_opts = []
        self.ceil_opts = []


_LONG_OPTIONS = [
    "hide", "extract", "capacity",
    "carrier=", "in=", "output=", "ratio=",
    "passphrase-fd=", "passphrase-file=",
    "opslimit=", "memlimit=",
    "max-opslimit=", "max-memlimit=", "max-filesize=",
    "min-password-length=", "allow-weak-password",
    "gisp=", "quiet", "help", "version",
]


def _set_mode(opts, mode):
    if opts.mode is not None and opts.mode != mode:
        raise UsageError("options --hide, --extract and --capacity are "
                         "mutually exclusive")
    opts.mode = mode


def _positive_int(name, value):
    try:
        parsed = int(value, 10)
    except ValueError:
        parsed = -1
    if parsed < 0:
        raise UsageError("invalid %s value: '%s'" % (name, value))
    return parsed


def _print_version():
    sys.stdout.write("%s %s\n" % (PROGRAM_NAME, VERSION))
    sys.stdout.write("Copyright (C) 2026 Uladzislau Bolbas\n")
    sys.stdout.write(
        "License GPLv3+: GNU GPL version 3 or later.\n"
        "This is free software: you are free to change and redistribute it.\n")
    sys.stdout.write("Backed by gisp; Pillow %s, NumPy %s.\n"
                     % (PIL.__version__, np.__version__))


def parse_args(argv):
    opts = Options()
    try:
        parsed, extra = getopt.gnu_getopt(
            argv, "HXc:i:o:p:m:g:qhv", _LONG_OPTIONS)
    except getopt.GetoptError as exc:
        raise UsageError(str(exc))

    for name, value in parsed:
        if name in ("-h", "--help"):
            sys.stdout.write(USAGE)
            raise SystemExit(EXIT_OK)
        if name in ("-v", "--version"):
            _print_version()
            raise SystemExit(EXIT_OK)

        if name in ("-H", "--hide"):
            _set_mode(opts, "hide")
        elif name in ("-X", "--extract"):
            _set_mode(opts, "extract")
        elif name == "--capacity":
            _set_mode(opts, "capacity")
        elif name in ("-c", "--carrier"):
            opts.carrier = value
        elif name in ("-i", "--in"):
            opts.infile = value
        elif name in ("-o", "--output"):
            opts.output = value
        elif name == "--ratio":
            try:
                opts.ratio = float(value)
            except ValueError:
                raise UsageError("invalid ratio value: '%s'" % value)
            if not (0.0 < opts.ratio <= MAX_RATIO):
                raise UsageError(
                    "ratio must satisfy 0 < r <= %.3f" % MAX_RATIO)
        elif name in ("-g", "--gisp"):
            opts.gisp = value
        elif name in ("-q", "--quiet"):
            opts.quiet = True
        # -- passphrase pass-through --
        elif name == "--passphrase-fd":
            opts.pass_fd = _positive_int("file descriptor", value)
            opts.pass_opts = ["--passphrase-fd", str(opts.pass_fd)]
        elif name == "--passphrase-file":
            opts.pass_opts = ["--passphrase-file", value]
        # -- KDF pass-through (hide) --
        elif name in ("-p", "--opslimit"):
            opts.kdf_opts += ["--opslimit", value]
        elif name in ("-m", "--memlimit"):
            opts.kdf_opts += ["--memlimit", value]
        # -- ceilings pass-through (extract) --
        elif name == "--max-opslimit":
            opts.ceil_opts += ["--max-opslimit", value]
        elif name == "--max-memlimit":
            opts.ceil_opts += ["--max-memlimit", value]
        elif name == "--max-filesize":
            opts.ceil_opts += ["--max-filesize", value]
        # -- shared by both gisp directions --
        elif name == "--min-password-length":
            opts.kdf_opts += ["--min-password-length", value]
            opts.ceil_opts += ["--min-password-length", value]
        elif name == "--allow-weak-password":
            opts.kdf_opts.append("--allow-weak-password")
            opts.ceil_opts.append("--allow-weak-password")

    if extra:
        raise UsageError("unexpected argument: '%s'" % extra[0])
    if opts.mode is None:
        raise UsageError("one of --hide, --extract or --capacity is required")
    if opts.mode in ("hide", "capacity") and not opts.carrier:
        raise UsageError("--carrier is required for this mode")
    if opts.mode == "hide" and is_stdio(opts.carrier) and is_stdio(opts.infile):
        raise UsageError(
            "carrier and secret cannot both read from standard input")
    if opts.pass_fd is not None and "--passphrase-file" in opts.pass_opts:
        raise UsageError(
            "--passphrase-fd and --passphrase-file are mutually exclusive")
    return opts


# --------------------------------------------------------------------------
# Mode handlers.
# --------------------------------------------------------------------------

def do_capacity(opts):
    carrier = load_carrier(read_bytes(opts.carrier), opts.quiet)
    width, height = carrier.size
    capacity = carrier.capacity_bytes(opts.ratio)
    sys.stdout.write(
        "carrier:  %dx%d %s\n"
        "usable:   %d samples\n"
        "ratio:    %.3f\n"
        "capacity: %d bytes (payload after gisp encryption overhead)\n"
        % (width, height, carrier.mode, carrier.n_usable,
           opts.ratio, capacity))
    return EXIT_OK


def do_hide(opts):
    gisp = locate_gisp(opts.gisp)

    # Decode the carrier up front so an unusable cover fails before we bother
    # the user for a passphrase.
    carrier = load_carrier(read_bytes(opts.carrier), opts.quiet)

    ciphertext = gisp_encrypt(
        gisp, opts.infile, opts.pass_opts, opts.pass_fd, opts.kdf_opts,
        opts.quiet)
    if not ciphertext:
        raise StingError("gisp produced no ciphertext")

    stego = embed(carrier, ciphertext, opts.ratio)
    write_bytes(opts.output, stego)
    if not opts.quiet:
        sys.stderr.write(
            "%s: hid %d bytes in a %dx%d carrier (%.2f%% of samples used)\n"
            % (PROGRAM_NAME, len(ciphertext), carrier.size[0], carrier.size[1],
               100.0 * (HDR_BITS + len(ciphertext) * 8) / carrier.n_usable))
    return EXIT_OK


def do_extract(opts):
    gisp = locate_gisp(opts.gisp)
    carrier = load_carrier(read_bytes(opts.infile), opts.quiet)
    ciphertext = extract(carrier)
    plaintext = gisp_decrypt(
        gisp, ciphertext, opts.pass_opts, opts.pass_fd, opts.ceil_opts,
        opts.quiet)
    write_bytes(opts.output, plaintext)
    if not opts.quiet:
        sys.stderr.write("%s: payload recovered and decrypted\n"
                         % PROGRAM_NAME)
    return EXIT_OK


_HANDLERS = {"hide": do_hide, "extract": do_extract, "capacity": do_capacity}


def main(argv):
    """Parse ARGV, run the selected mode, and return an exit status."""
    try:
        opts = parse_args(argv)
    except UsageError as exc:
        sys.stderr.write("%s: error: %s\n" % (PROGRAM_NAME, exc))
        sys.stderr.write("Try '%s --help' for more information.\n"
                         % PROGRAM_NAME)
        return EXIT_USAGE

    try:
        return _HANDLERS[opts.mode](opts)
    except StingError as exc:
        sys.stderr.write("%s: error: %s\n" % (PROGRAM_NAME, exc))
        return EXIT_FAIL
    except BrokenPipeError:
        # A downstream consumer closed early; mirror standard filter behaviour.
        try:
            sys.stdout.close()
        except OSError:
            pass
        return EXIT_FAIL
    except KeyboardInterrupt:
        sys.stderr.write("\n%s: interrupted\n" % PROGRAM_NAME)
        return EXIT_FAIL
