# sting -- invocation of the gisp encryption back end.
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

"""The gisp subprocess boundary.

sting performs no cryptography itself: it shells out to gisp for
XChaCha20-Poly1305 / Argon2id and treats the container as opaque bytes.
The passphrase never passes through sting -- it is forwarded to gisp by
descriptor, by file, or read straight from the terminal by gisp itself.
"""

import os
import shutil
import subprocess
import sys

from .errors import StingError


def locate_gisp(explicit):
    """Resolve the gisp executable, or raise StingError.

    An explicitly requested backend (--gisp PATH or STING_GISP) is
    authoritative: if it is given but unusable, sting fails loudly rather
    than silently substituting a different gisp, since for a tool whose
    value rests on a specific vetted crypto backend the identity of that
    binary matters.  Only when no backend is requested does sting search
    PATH and the well-known checkout location.
    """
    requested = explicit or os.environ.get("STING_GISP")
    if requested:
        if os.path.isfile(requested) and os.access(requested, os.X_OK):
            return requested
        raise StingError(
            "requested gisp %r is not an executable file" % requested)

    for path in (shutil.which("gisp"),
                 os.path.expanduser("~/Scripts/gisp/src/gisp")):
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise StingError(
        "cannot find the gisp executable; pass --gisp PATH or set STING_GISP")


def _run_gisp(argv, pass_fd, input_bytes, stdin_passthrough, quiet):
    """Invoke gisp, returning its stdout bytes; raise StingError on failure.

    Exactly one of INPUT_BYTES (fed through a pipe) or STDIN_PASSTHROUGH
    (inherit this process's stdin) selects gisp's data source.  PASS_FD, when
    not None, is an already-open descriptor holding the passphrase; it is kept
    open across the fork so gisp can read it via --passphrase-fd.

    gisp's own stderr is captured rather than inherited, so sting manages
    verbosity itself: this keeps behaviour identical across gisp builds
    (older ones lack --quiet) and never collides with the passphrase prompt,
    which gisp writes straight to /dev/tty.  The captured diagnostics are
    forwarded whenever gisp fails, and on success unless --quiet was given.
    """
    pass_fds = (pass_fd,) if pass_fd is not None else ()
    if stdin_passthrough:
        stdin = sys.stdin           # gisp reads the secret from our stdin
    elif input_bytes is not None:
        stdin = subprocess.PIPE
    else:
        stdin = subprocess.DEVNULL

    try:
        proc = subprocess.Popen(
            argv, stdin=stdin, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, pass_fds=pass_fds)
    except OSError as exc:
        raise StingError("cannot execute gisp: %s" % exc)

    # communicate() drains stdout and stderr concurrently, so there is no
    # deadlock whether or not we are also writing gisp's stdin.
    try:
        out, err = proc.communicate(input_bytes if stdin is subprocess.PIPE
                                    else None)
    except OSError as exc:
        proc.kill()
        raise StingError("gisp I/O failed: %s" % exc)
    except BaseException:
        # Ctrl-C while gisp grinds through Argon2id lands here; without the
        # kill the child would outlive us with the passphrase descriptor
        # still open.
        proc.kill()
        proc.wait()
        raise

    if proc.returncode != 0:
        if err:
            sys.stderr.buffer.write(err)
        # A wrong password and a tampered container are indistinguishable by
        # design, so keep our own message correspondingly generic.
        raise StingError("gisp exited with status %d" % proc.returncode)
    if err and not quiet:
        sys.stderr.buffer.write(err)
    return out


def gisp_encrypt(gisp, secret_path, pass_opts, pass_fd, kdf_opts, quiet):
    """Encrypt SECRET_PATH with gisp and return the container bytes."""
    argv = [gisp, "-e", secret_path, "-o", "-"] + pass_opts + kdf_opts
    passthrough = (secret_path == "-")
    return _run_gisp(argv, pass_fd, None if passthrough else b"", passthrough,
                     quiet)


def gisp_decrypt(gisp, ciphertext, pass_opts, pass_fd, ceil_opts, quiet):
    """Decrypt CIPHERTEXT with gisp and return the plaintext bytes."""
    argv = [gisp, "-d", "-", "-o", "-"] + pass_opts + ceil_opts
    return _run_gisp(argv, pass_fd, ciphertext, False, quiet)
