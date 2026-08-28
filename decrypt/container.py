"""The MVsilicon `.MVA` firmware container.

Layout of the generation-0x58 variant used by the FIFINE SC3 (verified against
the shipped V22 image and against the vendor flash tool's own parser):

    offset  size  meaning
    0       2     magic, ascii "MV"
    2       1     chip id       (0xB1 for this family; 0x4F and 0xB5 also exist)
    3       1     generation    (0x58 here)
    4       1     record count
    5       ...   records, each  [type:u8][length:u32 LE][payload:length]
    -4      4     trailer: CRC16-CCITT as u16 LE, then two zero bytes

Record types, named verbatim by the vendor's own burner tool:

    1  Command
    2  Code                            <- the encrypted code image
    3  Flash Driver                    <- 1524 bytes, byte-identical across images
    4  Const (Index Data and Table)    <- plaintext resource filesystem
    5  Config Data

The vendor also documents 0x06 KeyInfo, 0x07 SN, 0x08/0x09 MAC, 0x0A BTName and
0xFD Algorithm Code; the SC3 image carries only types 1, 2, 3 and 4.

**The first four bytes of a record payload are the FLASH BASE ADDRESS** (u32 LE),
not data.  Flash address `A` therefore lives at `payload[4 + A]`.  For the SC3
the Code record is based at 0x00000000 and the Const record at 0x00135000.

The trailer is **CRC16-CCITT**: polynomial 0x1021, MSB-first, init 0x0000, no
final XOR, computed over `file[:-4]`.  It is not CRC32; an early note claiming
CRC32 was wrong and any image rebuilt with CRC32 is rejected by the flash tool.

Older SDK sample images use a different 22-byte-header layout entirely.  Do not
assume this parser applies to them.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

MAGIC = b"MV"

RECORD_TYPES = {
    1: "Command",
    2: "Code",
    3: "FlashDriver",
    4: "Const",
    5: "Config",
    6: "KeyInfo",
    7: "SN",
    8: "MAC",
    9: "MAC2",
    10: "BTName",
    0xFD: "AlgorithmCode",
}

TYPE_CODE = 2
TYPE_CONST = 4

# Record types whose payload begins with a 4-byte flash base address.  The
# Command record does not: on the SC3 it is 3 bytes, `35 ba 69`, the SPI-flash
# write-protect unlock magic the SDK passes to IOCTL_FLASH_UNPROTECT.
TYPES_WITH_BASE = frozenset({2, 3, 4, 5})


class MvaError(Exception):
    """Raised when a file is not a parseable MVA container."""


@dataclass
class Record:
    """One TLV record."""

    type: int
    payload: bytes
    file_offset: int  # offset of the payload within the whole file

    @property
    def type_name(self) -> str:
        return RECORD_TYPES.get(self.type, "Unknown")

    @property
    def flash_base(self):
        """The u32 LE flash base address in the first 4 payload bytes, or None.

        Only Code, FlashDriver, Const and Config records carry one; see
        TYPES_WITH_BASE.
        """
        if self.type not in TYPES_WITH_BASE or len(self.payload) < 8:
            return None
        return struct.unpack_from("<I", self.payload, 0)[0]

    @property
    def body(self) -> bytes:
        """The payload with the 4-byte flash base address stripped.

        Only meaningful for records that carry a base; see `flash_base`.
        """
        return self.payload[4:]


@dataclass
class Mva:
    """A parsed container."""

    raw: bytes
    chip: int
    generation: int
    records: list

    def record(self, type_: int) -> Record:
        for r in self.records:
            if r.type == type_:
                return r
        raise MvaError(f"no record of type {type_} in this file")

    def has(self, type_: int) -> bool:
        return any(r.type == type_ for r in self.records)

    @property
    def stored_crc(self) -> int:
        return struct.unpack_from("<H", self.raw, len(self.raw) - 4)[0]

    @property
    def computed_crc(self) -> int:
        return crc16_ccitt(self.raw[:-4])

    @property
    def crc_ok(self) -> bool:
        return self.stored_crc == self.computed_crc


def crc16_ccitt(data: bytes) -> int:
    """CRC16-CCITT, poly 0x1021, MSB-first, init 0x0000, no final XOR."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def parse(data: bytes) -> Mva:
    """Parse an MVA container from bytes.  Raises MvaError on anything odd."""
    if len(data) < 9:
        raise MvaError("file is far too short to be an MVA container")
    if data[:2] != MAGIC:
        raise MvaError(f"bad magic {data[:2]!r}, expected {MAGIC!r}")

    chip, generation, count = data[2], data[3], data[4]
    records = []
    off = 5
    for i in range(count):
        if off + 5 > len(data) - 4:
            raise MvaError(f"record {i} header runs past the end of the file")
        rtype = data[off]
        (length,) = struct.unpack_from("<I", data, off + 1)
        start = off + 5
        end = start + length
        if end > len(data) - 4:
            raise MvaError(
                f"record {i} (type {rtype}) claims {length} bytes but only "
                f"{len(data) - 4 - start} remain before the trailer"
            )
        records.append(Record(rtype, data[start:end], start))
        off = end

    trailing = len(data) - 4 - off
    if trailing != 0:
        raise MvaError(f"{trailing} unaccounted bytes between the last record and the trailer")

    return Mva(raw=data, chip=chip, generation=generation, records=records)


def load(path) -> Mva:
    """Read and parse an MVA file.  Propagates OSError if the file is missing."""
    with open(path, "rb") as fh:
        return parse(fh.read())


def rebuild(mva: Mva, replacements: dict) -> bytes:
    """Rebuild the container with some record payloads replaced, fixing the CRC.

    ``replacements`` maps record type -> new payload bytes.  Every replacement
    must be exactly the same length as the record it replaces: record lengths are
    stored in the header and the flash tool validates them, so changing a length
    would need the header rewritten too and is refused here rather than done
    silently.
    """
    out = bytearray(mva.raw)
    for rtype, payload in replacements.items():
        rec = mva.record(rtype)
        if len(payload) != len(rec.payload):
            raise MvaError(
                f"replacement for record type {rtype} is {len(payload)} bytes, "
                f"expected {len(rec.payload)}"
            )
        out[rec.file_offset : rec.file_offset + len(payload)] = payload
    crc = crc16_ccitt(bytes(out[:-4]))
    out[-4:] = struct.pack("<HH", crc, 0)
    return bytes(out)


# --------------------------------------------------------------------------
# The Const record: an "MVUB" resource filesystem, never encrypted.
# --------------------------------------------------------------------------

MVUB_MAGIC = b"MVUB"


@dataclass
class Resource:
    name: str
    offset: int  # relative to the start of the MVUB blob
    size: int


def parse_mvub(body: bytes) -> list:
    """Parse the MVUB directory out of a Const record body.

    ``body`` is the record payload with its 4-byte flash base stripped, i.e.
    ``mva.record(4).body``.  Layout:

        0    "MVUB"
        4    u32   (total size field)
        8    u8    entry count
        9    entries, stride 16: [name: 8 bytes, space padded][offset u32 LE][size u32 LE]
        ...  payload, first blob at 0x1000, offsets relative to the MVUB start

    On the SC3 every blob is an MPEG-1 Layer II frame stream (voice prompts).
    """
    if body[:4] != MVUB_MAGIC:
        raise MvaError(f"const record does not start with {MVUB_MAGIC!r}")
    count = body[8]
    out = []
    for i in range(count):
        entry = body[9 + 16 * i : 9 + 16 * i + 16]
        if len(entry) < 16:
            raise MvaError(f"MVUB entry {i} is truncated")
        name = entry[:8].decode("latin1").rstrip().rstrip("\x00")
        offset, size = struct.unpack_from("<II", entry, 8)
        if offset + size > len(body):
            raise MvaError(f"MVUB entry {i} ({name!r}) runs past the end of the record")
        out.append(Resource(name, offset, size))
    return out


def read_resource(body: bytes, res: Resource) -> bytes:
    return body[res.offset : res.offset + res.size]
