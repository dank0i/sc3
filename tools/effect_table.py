#!/usr/bin/env python3
"""The SC3's effect table, resolved at runtime rather than shipped.

The 54 node names are FIFINE's and MVsilicon's, so this repository does not
carry a copy of them.  Nothing is lost by that: both runtime sources need only
something you already own, and either is more trustworthy than a table baked in
here, because a different firmware revision can reorder or rename nodes.

* **The device recites them itself.**  ACP control `0x80` with a one-byte index
  returns that effect's own name (`acp.Acp.effect_name`).  Use `DeviceNames`
  below, which caches so a watch loop pays only for nodes it actually reports.
* **A decrypted image carries the table** at flash `TABLE_FLASH_ADDR`, 25-byte
  stride, 54 entries.  `names_from_image` parses it.  Feed it the output of
  `python -m decrypt decrypt FIRMWARE.MVA`.

Naming convention, for reading the results: the digit before the colon is the
chain the node belongs to, so `2:Music Delay` is node index 25 on the Music
chain.  ACP node address = `NODE_BASE + index`.

Caveat worth carrying: node `0xB6` is labelled as a SPDIF input by the firmware,
but the SC3 has no SPDIF connector and that node is demonstrably driven by the
LINE-IN fader.  FIFINE reused an unused input-gain slot.  The same is true of
`0xB3` and `0xB4`, which sit parked at a constant.  Trust the hardware
behaviour over the label.
"""

from __future__ import annotations

NODE_BASE = 0x81
NODE_COUNT = 54

#: Where the table lives in a DECRYPTED image, and how it is laid out.  A name
#: is padded to either 25 or 23 characters; a 23-character literal carries two
#: trailing NULs.
TABLE_FLASH_ADDR = 0x000D4508
TABLE_STRIDE = 25

CHAIN_NAMES = {1: "Mic", 2: "Music", 3: "Guitar", 4: "Rec"}


def index_for(addr: int) -> int | None:
    """Table index for an ACP node address, or None if out of range."""
    i = addr - NODE_BASE
    return i if 0 <= i < NODE_COUNT else None


def names_from_image(plain: bytes, *, count: int = NODE_COUNT) -> tuple[str, ...]:
    """Parse the effect table out of a decrypted firmware image.

    `plain` is the whole decrypted code record, so flash addresses index it
    directly.  Raises ValueError rather than returning junk if the image is too
    short or the region does not look like the table.
    """
    end = TABLE_FLASH_ADDR + count * TABLE_STRIDE
    if len(plain) < end:
        raise ValueError(
            f"image is {len(plain)} bytes, need at least {end} for the effect table"
        )
    out = []
    for i in range(count):
        off = TABLE_FLASH_ADDR + i * TABLE_STRIDE
        raw = plain[off:off + TABLE_STRIDE]
        name = raw.split(b"\x00", 1)[0].decode("ascii", "replace").strip()
        if not name:
            raise ValueError(
                f"entry {i} at {off:#08x} is empty; this is probably not a "
                f"decrypted SC3 image, or the table has moved in this revision"
            )
        out.append(name)
    return tuple(out)


class DeviceNames:
    """Node names read from the device on demand, cached per address.

    Reads are not free and not perfectly reliable (see the SAFETY notes), so
    this never bulk-fetches: a `watch` run pays for the handful of nodes it
    actually reports, not for all 54.
    """

    def __init__(self, dev):
        self._dev = dev
        self._cache: dict[int, str | None] = {}

    def get(self, addr: int) -> str | None:
        """Name for an ACP node address, or None if unknown or unreadable.

        A failed read is NOT cached. The transport is lossy at the default
        timing, and caching one transient miss would mislabel that node as
        unknown for the rest of the run.
        """
        if addr in self._cache:
            return self._cache[addr]
        i = index_for(addr)
        if i is None:
            return None
        name = self._dev.effect_name(i)
        if name is not None:
            self._cache[addr] = name
        return name

    def all(self) -> tuple[str | None, ...]:
        """Every node name, fetching any not already cached."""
        return tuple(self.get(NODE_BASE + i) for i in range(NODE_COUNT))


def chain_for(name: str | None) -> int | None:
    """Chain id (1-4) from a node name like `2:Music Delay`, or None."""
    # `str.isdigit()` is true for superscripts and other numerals that `int()`
    # then refuses, so this checks membership rather than the digit property.
    # A name read off a device with a lost byte should return None, not raise.
    if not name or len(name) < 2 or name[1] != ":" or name[0] not in "0123456789":
        return None
    return int(name[0])


def main():
    """Print the effect table from a decrypted image. Needs no hardware."""
    import argparse
    import sys

    ap = argparse.ArgumentParser(description=main.__doc__)
    ap.add_argument("image", help="decrypted code image (python -m decrypt decrypt ...)")
    args = ap.parse_args()
    try:
        with open(args.image, "rb") as fh:
            names = names_from_image(fh.read())
    except (OSError, ValueError) as exc:
        sys.exit(f"error: {args.image}: {exc}")
    for i, name in enumerate(names):
        print(f"{i:>3}  {NODE_BASE + i:#04x}  {name}")


if __name__ == "__main__":
    main()
