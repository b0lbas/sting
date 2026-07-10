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


def write_bytes(path, data):
    """Write DATA to standard output, or atomically to a named file."""
    if is_stdio(path):
        try:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        except OSError as exc:
            raise StingError("cannot write to standard output: %s" % exc)
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
