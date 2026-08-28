"""Per-address cipher label tables.

`e(a)` and `s(a)` have no known closed form.  They were recovered one address at
a time by the known-plaintext attack described in docs/cipher.md, and the result
is a flat table of one label per code word.  This module stores and loads those
tables.

A label table is NOT firmware.  It holds no plaintext and no ciphertext: it is a
list of cipher labels, useful only in combination with a ciphertext image you
already have.  It is the practical equivalent of a key.

On-disk format (gzip-compressed):

    0    6     magic  b"SC3LBL"
    6    1     format version (1)
    7    1     length of the image name
    8    n     image name, ascii
    ..   4     word count, u32 LE
    ..   1     size of the (e, s) table
    ..   2*k   the (e, s) table, one byte each
    ..   32    SHA-256 of the code record payload this table belongs to
    ..   nwords  one label byte per code word

Label byte values:

    0 .. k-1   index into the (e, s) table
    0xFE       word is stored UNENCRYPTED in the container; pass it through
    0xFF       unsolved

The 0xFE case is real and matters: on the SC3 the 23 words at flash 0xA4..0xFF
are stored in the clear (loader header fields, the const base, the code length
and the 0x55 "encrypted" flag).  Running them through the cipher corrupts them.
"""

from __future__ import annotations

import gzip
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"SC3LBL"
VERSION = 1

PLAINTEXT = 0xFE
UNSOLVED = 0xFF

LABELS_DIR = Path(__file__).resolve().parent / "labels"


class LabelError(Exception):
    pass


@dataclass
class LabelTable:
    name: str
    es_table: tuple  # tuple of (e, s)
    sha256: bytes  # of the code record payload
    labels: bytes  # one byte per word

    def __len__(self) -> int:
        return len(self.labels)

    @property
    def solved(self) -> int:
        return sum(1 for b in self.labels if b not in (PLAINTEXT, UNSOLVED))

    @property
    def passthrough(self) -> int:
        return self.labels.count(PLAINTEXT)

    @property
    def unsolved(self) -> int:
        return self.labels.count(UNSOLVED)

    def label(self, index: int):
        """-> (e, s), or the PLAINTEXT / UNSOLVED sentinel."""
        b = self.labels[index]
        if b in (PLAINTEXT, UNSOLVED):
            return b
        return self.es_table[b]

    def matches(self, code_payload: bytes) -> bool:
        return hashlib.sha256(code_payload).digest() == self.sha256


def build(name: str, es_table, code_payload: bytes, labels: bytes) -> LabelTable:
    if len(es_table) > 0xFE:
        raise LabelError("(e, s) table is too large for a one-byte label")
    return LabelTable(
        name=name,
        es_table=tuple(tuple(x) for x in es_table),
        sha256=hashlib.sha256(code_payload).digest(),
        labels=bytes(labels),
    )


def dumps(table: LabelTable) -> bytes:
    name = table.name.encode("ascii")
    if len(name) > 255:
        raise LabelError("image name is too long")
    head = bytearray(MAGIC)
    head.append(VERSION)
    head.append(len(name))
    head += name
    head += struct.pack("<I", len(table.labels))
    head.append(len(table.es_table))
    for e, s in table.es_table:
        head.append(e)
        head.append(s)
    head += table.sha256
    return gzip.compress(bytes(head) + table.labels, 9)


def loads(blob: bytes) -> LabelTable:
    raw = gzip.decompress(blob)
    if raw[:6] != MAGIC:
        raise LabelError("not a label table")
    if raw[6] != VERSION:
        raise LabelError(f"unsupported label table version {raw[6]}")
    nlen = raw[7]
    off = 8
    name = raw[off : off + nlen].decode("ascii")
    off += nlen
    (nwords,) = struct.unpack_from("<I", raw, off)
    off += 4
    k = raw[off]
    off += 1
    es = tuple((raw[off + 2 * i], raw[off + 2 * i + 1]) for i in range(k))
    off += 2 * k
    sha = raw[off : off + 32]
    off += 32
    labels = raw[off : off + nwords]
    if len(labels) != nwords:
        raise LabelError(f"label table is truncated: {len(labels)} of {nwords} words")
    return LabelTable(name=name, es_table=es, sha256=sha, labels=labels)


def save(table: LabelTable, path) -> None:
    Path(path).write_bytes(dumps(table))


def load(path) -> LabelTable:
    return loads(Path(path).read_bytes())


def available() -> list:
    """Label tables shipped with this repository."""
    if not LABELS_DIR.is_dir():
        return []
    return sorted(p for p in LABELS_DIR.glob("*.labels.gz"))


def find_for(code_payload: bytes):
    """Return the shipped label table whose SHA-256 matches this code record.

    Returns None if no shipped table matches, which is the normal outcome for any
    image other than the one that was solved.
    """
    want = hashlib.sha256(code_payload).digest()
    for path in available():
        try:
            table = load(path)
        except (LabelError, OSError):
            continue
        if table.sha256 == want:
            return table
    return None
