# sting -- PNG carrier decode/encode and the usable-sample model.
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

"""The carrier: a decoded PNG plus its set of embeddable samples.

A "usable sample" is one 8-bit colour sample that sting is willing to
perturb: colour channels only (never alpha), and never a sample belonging
to a fully transparent pixel, since altering the colour behind full
transparency is both pointless and a giveaway.  The usable set is computed
identically on both sides so the permutations line up.
"""

import io
import sys

import numpy as np
import PIL
from PIL import Image

from .constants import (HDR_BITS, MAX_CARRIER_SAMPLES, MODE_LAYOUT,
                        PROGRAM_NAME)
from .errors import StingError


class Carrier:
    """A decoded PNG in a form ready for LSB embedding or extraction."""

    def __init__(self, image):
        mode = image.mode
        if mode not in MODE_LAYOUT:
            raise StingError(
                "unsupported PNG mode %r; sting handles 8-bit L, LA, RGB and "
                "RGBA images (convert palette or 16-bit images first)" % mode)

        arr = np.asarray(image)
        if arr.dtype != np.uint8:
            raise StingError(
                "unsupported PNG sample depth; sting requires 8 bits per "
                "channel")

        # Work on a private, contiguous, writable copy.  The flat view shares
        # its buffer, so LSB edits land back in the image bytes.
        self.mode = mode
        self.size = image.size            # (width, height)
        self._arr = np.ascontiguousarray(arr).copy()
        self._flat = self._arr.reshape(-1)

        channels = 1 if self._arr.ndim == 2 else self._arr.shape[2]
        colour, alpha = MODE_LAYOUT[mode]
        npix = self.size[0] * self.size[1]
        base = np.arange(npix, dtype=np.int64) * channels

        parts = []
        for c in colour:
            idx = base + c
            if alpha is not None:
                # Drop samples of fully transparent pixels.
                opaque = self._flat[base + alpha] != 0
                idx = idx[opaque]
            parts.append(idx)

        # Sort into a single canonical raster order shared by both sides.
        self.usable = np.sort(np.concatenate(parts))
        if self.usable.size > MAX_CARRIER_SAMPLES:
            raise StingError(
                "carrier too large: %d usable samples exceeds the %d limit"
                % (self.usable.size, MAX_CARRIER_SAMPLES))

    @property
    def n_usable(self):
        return int(self.usable.size)

    def capacity_bytes(self, ratio):
        """Maximum payload, in bytes, at the given change RATIO."""
        cap_bits = int(self.n_usable * ratio)
        payload_bits = cap_bits - HDR_BITS
        if payload_bits < 8:
            return 0
        return payload_bits // 8

    # -- bit-level access -------------------------------------------------

    def write(self, slots, bits, steps):
        """LSB-match BITS into the samples named by SLOTS (usable indices)."""
        pos = self.usable[slots]
        vals = self._flat[pos].astype(np.int16)
        change = (vals & 1) != bits
        step = steps.copy()
        # Never step past the 0..255 range; at an edge the only legal move
        # still flips the LSB to the wanted value.
        step[vals == 0] = 1
        step[vals == 255] = -1
        vals = np.where(change, vals + step, vals)
        self._flat[pos] = vals.astype(np.uint8)

    def read(self, slots):
        """Return the LSBs of the samples named by SLOTS."""
        return (self._flat[self.usable[slots]] & 1).astype(np.uint8)

    def to_png_bytes(self):
        """Re-encode the (possibly modified) pixels as a PNG byte string."""
        image = Image.frombytes(self.mode, self.size, self._arr.tobytes())
        buf = io.BytesIO()
        image.save(buf, format="PNG", optimize=False)
        return buf.getvalue()


def _normalise_mode(image, quiet):
    """Promote a carrier to a mode sting can embed in, or raise StingError.

    L, LA, RGB and RGBA are used as-is.  Palette ("P"/"PA") and bilevel ("1")
    images are promoted to true colour: the LSB of a palette *index* has no
    relation to the colour it names, so embedding there is trivially visible,
    whereas the promoted colour channels behave like any ordinary photo.  The
    resulting stego is a normal true-colour PNG.  16-bit and other exotic
    modes are refused rather than silently degraded.
    """
    mode = image.mode
    if mode in MODE_LAYOUT:
        return image
    if mode in ("P", "PA", "1"):
        if mode == "1":
            target = "L"
        elif mode == "PA" or "transparency" in image.info:
            target = "RGBA"
        else:
            target = "RGB"
        if not quiet:
            sys.stderr.write(
                "%s: note: promoting %s carrier to %s for embedding\n"
                % (PROGRAM_NAME, mode, target))
        try:
            return image.convert(target)
        except (OSError, ValueError) as exc:
            raise StingError("cannot convert %s carrier: %s" % (mode, exc))
    raise StingError(
        "unsupported PNG mode %r; sting embeds in 8-bit L, LA, RGB and RGBA "
        "(and promotes palette or 1-bit carriers); convert 16-bit images first"
        % mode)


def load_carrier(raw, quiet=False):
    """Decode PNG bytes into a Carrier, mapping every failure to StingError."""
    try:
        image = Image.open(io.BytesIO(raw))
        image.load()                      # force a full, validating decode
    except PIL.UnidentifiedImageError:
        raise StingError("carrier is not a recognisable image")
    except Image.DecompressionBombError:
        raise StingError("carrier rejected: image is implausibly large")
    except (OSError, ValueError) as exc:
        raise StingError("cannot decode carrier PNG: %s" % exc)
    if image.format != "PNG":
        raise StingError(
            "carrier must be a PNG image (got %s)" % (image.format or "unknown"))
    return Carrier(_normalise_mode(image, quiet))
