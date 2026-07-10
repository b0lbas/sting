# Makefile for sting -- authenticated PNG steganography built on gisp.
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

PACKAGE = sting
VERSION = 1.0

# Toolchain.  Override on the command line, e.g. `make PYTHON=python3.12`.
PYTHON  = python3
INSTALL = install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA    = $(INSTALL) -m 644
SED     = sed

# GNU standard installation directories.  Override any of these, e.g.
# `make install prefix=$HOME/.local` or `make install DESTDIR=/tmp/stage`.
prefix      = /usr/local
exec_prefix = $(prefix)
bindir      = $(exec_prefix)/bin
datarootdir = $(prefix)/share
datadir     = $(datarootdir)
mandir      = $(datarootdir)/man
man1dir     = $(mandir)/man1
docdir      = $(datarootdir)/doc/$(PACKAGE)

# Pure-Python package tree installs under $(pkgdatadir); the launcher adds
# this directory to sys.path so `import stinglib` resolves.
pkgdatadir  = $(datadir)/$(PACKAGE)

# The Python sources that make up the package.
PKGSOURCES = \
	stinglib/__init__.py \
	stinglib/__main__.py \
	stinglib/constants.py \
	stinglib/errors.py \
	stinglib/keystream.py \
	stinglib/carrier.py \
	stinglib/stego.py \
	stinglib/backend.py \
	stinglib/streams.py \
	stinglib/cli.py

DOCS = COPYING README

.PHONY: all check install install-lib install-bin install-man install-doc \
        uninstall clean distclean help build/sting

# Default target: generate the installed launcher with the right sys.path.
all: build/sting

# Deliberately phony: the substituted @pythondir@ comes from $(pkgdatadir),
# which may be set on the command line and is not tracked as a prerequisite,
# so the launcher is regenerated every time to avoid a stale path.
build/sting: sting.in
	@mkdir -p build
	$(SED) 's#@pythondir@#$(pkgdatadir)#g' sting.in > build/sting
	chmod +x build/sting

# Run the self-test.  The pure steganographic layer is always exercised; the
# full gisp round-trip is added automatically when a gisp binary is found.
check:
	$(PYTHON) tests/run-tests.py

install: all install-lib install-bin install-man install-doc

install-lib:
	$(INSTALL) -d $(DESTDIR)$(pkgdatadir)/stinglib
	$(INSTALL_DATA) $(PKGSOURCES) $(DESTDIR)$(pkgdatadir)/stinglib/

install-bin: build/sting
	$(INSTALL) -d $(DESTDIR)$(bindir)
	$(INSTALL_PROGRAM) build/sting $(DESTDIR)$(bindir)/sting

install-man:
	$(INSTALL) -d $(DESTDIR)$(man1dir)
	$(INSTALL_DATA) sting.1 $(DESTDIR)$(man1dir)/sting.1

install-doc:
	$(INSTALL) -d $(DESTDIR)$(docdir)
	$(INSTALL_DATA) $(DOCS) $(DESTDIR)$(docdir)/

uninstall:
	rm -f  $(DESTDIR)$(bindir)/sting
	rm -rf $(DESTDIR)$(pkgdatadir)/stinglib
	-rmdir $(DESTDIR)$(pkgdatadir) 2>/dev/null || true
	rm -f  $(DESTDIR)$(man1dir)/sting.1
	rm -rf $(DESTDIR)$(docdir)

clean:
	rm -rf build
	rm -rf stinglib/__pycache__ tests/__pycache__

distclean: clean

help:
	@echo 'sting $(VERSION) -- Makefile targets:'
	@echo '  make            Build the installable launcher (build/sting)'
	@echo '  make check      Run the self-test (uses gisp if available)'
	@echo '  make install    Install under $$(prefix) [default $(prefix)]'
	@echo '  make uninstall  Remove an installation'
	@echo '  make clean      Remove build artefacts'
	@echo
	@echo 'Common overrides:'
	@echo '  make install prefix=$$HOME/.local'
	@echo '  make install DESTDIR=/tmp/stage'
	@echo '  make PYTHON=python3.12 check'
