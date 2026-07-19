# sting -- stdin/stdout- and file-aware byte I/O.
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

"""Byte I/O helpers.

A path of "-" selects standard input or standard output, mirroring gisp so
sting drops into the same pipelines.  Named outputs are written through a
temporary file and an atomic rename so a reader never sees a partial result.
"""

import os
import stat
import sys
import tempfile

from .errors import StingError


def is_stdio(path):
    """True when PATH is the "-" sentinel for standard input/output."""
    return path == "-"


def read_bytes(path):
    """Read a whole input (a file, or standard input for "-")."""
    try:
        if is_stdio(path):
            return sys.stdin.buffer.read()
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise StingError("cannot read %s: %s"
                         % ("standard input" if is_stdio(path) else path, exc))


def _is_regular_target(path):
    """True when PATH names an ordinary file or does not exist yet.

    A non-existent path is treated as regular: the caller will create it, and a
    fresh regular file is exactly what the atomic rename produces.  Existing
    non-regular targets (devices, FIFOs, and symlinks that resolve to them) are
    written through directly instead.
    """
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except FileNotFoundError:
        return True
    except OSError:
        # Unable to tell (e.g. a dangling symlink); let the write path try and
        # surface any real error itself.
        return True


def write_bytes(path, data):
    """Write DATA to standard output, or atomically to a named file."""
    if is_stdio(path):
        try:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        except OSError as exc:
            raise StingError("cannot write to standard output: %s" % exc)
        return

    # The atomic temp-file-plus-rename below only makes sense for a regular
    # file: for anything else (a character device like /dev/null, a FIFO, a
    # symlink to one) there is no sibling directory to stage in and no partial
    # result to hide, so write straight through instead of failing to create a
    # temp file next to it.
    if not _is_regular_target(path):
        try:
            with open(path, "wb") as handle:
                handle.write(data)
                handle.flush()
        except OSError as exc:
            raise StingError("cannot write %s: %s" % (path, exc))
        return

    # Write to a sibling temporary file, flush to disk, then rename into
    # place so a reader never observes a half-written result.
    directory = os.path.dirname(os.path.abspath(path)) or "."
    try:
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".sting-")
    except OSError as exc:
        raise StingError("cannot create a temporary file: %s" % exc)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise StingError("cannot write %s: %s" % (path, exc))
