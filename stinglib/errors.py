# sting -- exception types that steer the process exit status.
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

"""The two error types sting raises internally.

The command-line front end (cli.main) catches each and maps it to the
matching exit code, so the rest of the package can signal failures by
raising rather than by returning status codes.
"""


class UsageError(Exception):
    """A command-line mistake; reported with the usage hint, exit code 2."""


class StingError(Exception):
    """An operational failure; reported plainly, exit code 1."""
