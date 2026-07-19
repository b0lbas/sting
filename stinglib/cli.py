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
from .constants import (BUG_ADDRESS, EXIT_FAIL, EXIT_OK, EXIT_USAGE,
                        MAX_RATIO, PROGRAM_NAME, VERSION)
from .errors import StingError, UsageError
from .stego import embed, extract, header_bits, stego_material
from .streams import is_stdio, read_bytes, write_bytes


USAGE = """\
Usage: %(prog)s --hide    -c CARRIER [-i SECRET] [-o STEGO]  [gisp options]
       %(prog)s --extract [-i STEGO]  [-o SECRET]            [gisp options]
       %(prog)s --capacity -c CARRIER

Hide an encrypted payload inside a PNG, or recover one.  The secret is
encrypted with gisp (XChaCha20-Poly1305 / Argon2id) before being scattered,
at most 3%% of the carrier's samples, across the image by LSB matching.
A path of '-' selects standard input or standard output.

Without a stego-key the embedding is DETECTABLE: the header sits at a fixed
location and carries a constant marker, so anyone with sting can tell a
payload is present (the secret itself stays encrypted).  Supply a stego-key
to place the data by a secret-derived layout instead, leaving nothing to
recognise; a wrong stego-key then looks the same as a clean image.

Mode:
  -H, --hide               Encrypt SECRET and embed it into CARRIER
  -X, --extract            Recover and decrypt the payload from STEGO
      --capacity           Report how much CARRIER can hold, then exit

Files:
  -c, --carrier <file>     Cover PNG to embed into (hide/capacity)
  -i, --in <file>          Secret to hide, or stego PNG to read (default: -)
  -o, --output <file>      Where to write the result (default: -)
      --ratio <fraction>   Cap on samples modified, 0<r<=0.03 (default: 0.03)

Stealth (independent of the gisp passphrase; never sent to gisp):
      --stego-key <str>        Place data by a layout keyed with this secret
      --stego-key-file <f>     Read the stego-key from file F (one line)

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
        # Stego-key: an independent placement secret, isolated from gisp.
        self.stego_key = None             # literal string from --stego-key
        self.stego_key_file = None        # path from --stego-key-file
        # gisp pass-through, collected verbatim.
        self.pass_opts = []
        self.pass_fd = None
        self.pass_source = None            # "--passphrase-fd" | "--passphrase-file"
        self.kdf_opts = []
        self.ceil_opts = []


_LONG_OPTIONS = [
    "hide", "extract", "capacity",
    "carrier=", "in=", "output=", "ratio=",
    "stego-key=", "stego-key-file=",
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


def _set_pass_source(opts, source):
    """Record the passphrase source, rejecting a conflicting second one.

    Guarding here rather than by inspecting the collected pass_opts makes the
    check order-independent: --passphrase-fd and --passphrase-file conflict in
    either order, while repeating the same option is harmless.
    """
    if opts.pass_source is not None and opts.pass_source != source:
        raise UsageError(
            "--passphrase-fd and --passphrase-file are mutually exclusive")
    opts.pass_source = source


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
        # -- stego-key (sting's own placement secret; never sent to gisp) --
        elif name == "--stego-key":
            if opts.stego_key_file is not None:
                raise UsageError("--stego-key and --stego-key-file are "
                                 "mutually exclusive")
            opts.stego_key = value
            opts.stego_key_file = None
        elif name == "--stego-key-file":
            if opts.stego_key is not None:
                raise UsageError("--stego-key and --stego-key-file are "
                                 "mutually exclusive")
            opts.stego_key_file = value
            opts.stego_key = None
        # -- passphrase pass-through --
        elif name == "--passphrase-fd":
            _set_pass_source(opts, "--passphrase-fd")
            opts.pass_fd = _positive_int("file descriptor", value)
            opts.pass_opts = ["--passphrase-fd", str(opts.pass_fd)]
        elif name == "--passphrase-file":
            _set_pass_source(opts, "--passphrase-file")
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

    # A "-" input reads standard input.  When that is an interactive terminal
    # the user almost certainly forgot -i/-c: gisp would prompt for the
    # password on /dev/tty and then block waiting for the data to be typed in,
    # with no prompt -- indistinguishable from a hang.  Refuse instead.
    if opts.mode == "hide":
        _reject_tty_input(opts.carrier, "the carrier PNG", "-c")
        _reject_tty_input(opts.infile, "the secret to hide", "-i")
    elif opts.mode == "extract":
        _reject_tty_input(opts.infile, "the stego PNG", "-i")
    elif opts.mode == "capacity":
        _reject_tty_input(opts.carrier, "the carrier PNG", "-c")
    return opts


def _stdin_is_tty():
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (ValueError, OSError):
        return False


def _reject_tty_input(path, role, option):
    """Refuse to read PATH from an interactive terminal (a silent-hang trap)."""
    if is_stdio(path) and _stdin_is_tty():
        raise UsageError(
            "%s would be read from the terminal; pass %s FILE, or feed data on "
            "standard input with a pipe or '< file'" % (role, option))


# --------------------------------------------------------------------------
# Mode handlers.
# --------------------------------------------------------------------------

def _resolve_stego_key(opts):
    """Return the stego-key as bytes, or None when none was requested.

    The literal --stego-key is taken as its UTF-8 bytes; --stego-key-file reads
    the file and strips one trailing newline so `echo key > f` behaves as
    expected.  An empty key is refused as a foot-gun.  This value is sting's
    own and is never forwarded to gisp.
    """
    if opts.stego_key is not None:
        key = opts.stego_key.encode("utf-8")
    elif opts.stego_key_file is not None:
        if is_stdio(opts.stego_key_file):
            raise UsageError("--stego-key-file cannot read from standard input")
        try:
            with open(opts.stego_key_file, "rb") as handle:
                key = handle.read()
        except OSError as exc:
            raise StingError("cannot read stego-key file %s: %s"
                             % (opts.stego_key_file, exc))
        if key.endswith(b"\r\n"):
            key = key[:-2]
        elif key.endswith((b"\n", b"\r")):
            key = key[:-1]
    else:
        return None
    if not key:
        raise StingError("stego-key must not be empty")
    return key


def do_capacity(opts):
    carrier = load_carrier(read_bytes(opts.carrier), opts.quiet)
    stego_key = _resolve_stego_key(opts)
    hbits = header_bits(stego_material(stego_key))
    width, height = carrier.size
    capacity = carrier.capacity_bytes(opts.ratio, hbits)
    sys.stdout.write(
        "carrier:  %dx%d %s\n"
        "usable:   %d samples\n"
        "ratio:    %.3f\n"
        "mode:     %s\n"
        "capacity: %d bytes (payload after gisp encryption overhead)\n"
        % (width, height, carrier.mode, carrier.n_usable, opts.ratio,
           "keyed (stealth)" if stego_key is not None else "open (detectable)",
           capacity))
    return EXIT_OK


def do_hide(opts):
    gisp = locate_gisp(opts.gisp)
    stego_key = _resolve_stego_key(opts)

    # Decode the carrier up front so an unusable cover fails before we bother
    # the user for a passphrase.
    carrier = load_carrier(read_bytes(opts.carrier), opts.quiet)

    ciphertext = gisp_encrypt(
        gisp, opts.infile, opts.pass_opts, opts.pass_fd, opts.kdf_opts,
        opts.quiet)
    if not ciphertext:
        raise StingError("gisp produced no ciphertext")

    stego = embed(carrier, ciphertext, opts.ratio, stego_key)
    # The stego image is meant to pass as an ordinary picture, so it takes the
    # umask default rather than the private 0600 a recovered secret gets.
    write_bytes(opts.output, stego, private=False)
    if not opts.quiet:
        hbits = header_bits(stego_material(stego_key))
        sys.stderr.write(
            "%s: hid %d bytes in a %dx%d carrier (%.2f%% of samples used, %s)\n"
            % (PROGRAM_NAME, len(ciphertext), carrier.size[0], carrier.size[1],
               100.0 * (hbits + len(ciphertext) * 8) / carrier.n_usable,
               "keyed" if stego_key is not None else "open/detectable"))
    return EXIT_OK


def do_extract(opts):
    gisp = locate_gisp(opts.gisp)
    stego_key = _resolve_stego_key(opts)
    carrier = load_carrier(read_bytes(opts.infile), opts.quiet)
    ciphertext = extract(carrier, stego_key)
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
