# The `.MVA` firmware container

MVsilicon's firmware package format, generation `0x58` variant, as used by the
FIFINE SC3. Verified against the shipped V22 image and against the vendor flash
tool's own parser.

Implemented in [`decrypt/container.py`](../decrypt/container.py); inspect a file
with `python -m decrypt info FIRMWARE.MVA`.

---

## Layout

```
offset  size  meaning
0       2     magic, ascii "MV"
2       1     chip id
3       1     generation
4       1     record count
5       ...   records, each  [type:u8][length:u32 LE][payload:length]
-4      4     trailer: CRC16-CCITT as u16 LE, then two zero bytes
```

The SC3's file begins `4D 56 B1 58 04`: `"MV"`, chip `0xB1`, generation `0x58`,
four records.

Chip ids seen across the wider corpus: `0xB1` (BP1048B2, the SC3's family),
`0xB5`, `0x4F`. Generation `0x12` goes with chip `0x4F` and its container
differs in ways that this parser does **not** cover: no 4-byte load-address
prefix, and the header magic sits at a different offset. Do not assume this
layout applies to it.

Older SDK sample images use a completely different 22-byte-header format
(`"MVO\x12"`, then a payload mapped 1:1 to flash). Also not this.

## Record types

Named verbatim by the vendor's own burner tool:

| type | name | in the SC3 image |
|---|---|---|
| 1 | Command | 3 bytes: `35 BA 69` |
| 2 | **Code** | 1,262,620 bytes, the encrypted code image |
| 3 | Flash Driver | 1,524 bytes |
| 4 | Const (Index Data and Table) | 462,645 bytes, plaintext resources |
| 5 | Config Data | absent |

The vendor also documents `0x06` KeyInfo, `0x07` SN, `0x08`/`0x09` MAC, `0x0A`
BTName and `0xFD` Algorithm Code. The SC3 image has **no Config record**.

Two details that were misread at various points and are worth stating plainly:

* The **Command** record's `35 BA 69` is the SPI-flash write-protect unlock
  magic the SDK passes to `IOCTL_FLASH_UNPROTECT`. It is not a version or an
  id.
* The **Flash Driver** record is byte-identical across every image examined,
  across two different chips and two different keys. It is the flash driver
  uploaded to the chip, not data, and it is not keystream. A long detour was
  spent testing it as an S-box and as a keystream before the vendor tool named
  it.

## The flash base prefix

**The first four bytes of a record payload are the flash base address** (u32
LE), not data. Flash address `A` therefore lives at `payload[4 + A]`.

For the SC3: Code is based at `0x00000000`, Const at `0x00135000`.

Getting this wrong by a constant offset silently poisons every downstream
artifact (it happened once with a `payload - 0x28` mapping that was off by
`+0x24`), and a wrong base makes the cipher's own consistency checks return zero
hits, which reads as "the model is broken" rather than "the framing is wrong".

## The trailer

**CRC16-CCITT**: polynomial `0x1021`, MSB-first, init `0x0000`, no final XOR,
over `file[:-4]`. Stored as a u16 little-endian followed by two zero bytes.

For the stock SC3 V22 image it is `0x4531`.

It is **not** CRC32. An early note said otherwise; an image rebuilt with a CRC32
trailer is rejected by the flash tool. Validate any implementation by
reproducing an existing file's own trailer before trusting it to produce a new
one: `python -m decrypt crc FIRMWARE.MVA` does exactly that.

Note the trailer covers **ciphertext**, so it is no help as a plaintext oracle.

## Code record internals

Flash addresses within the SC3's Code record:

| flash | contents |
|---|---|
| `0x000000`-`0x00F0E0` | the **flashboot**, separately linked, with its own 41-entry NDS32 vector table |
| `0x0000A4`-`0x0000FF` | header fields, **stored unencrypted** (23 words) |
| `0x0100A0`-`0x0100FC` | the application's own header block, mirroring the flashboot's |
| `0x010000`-`0x134418` | the application (the Code record ends here; `0x135000` is the Const base) |

The image is **two separately linked programs**, each carrying its own copy of
the driver library and its own vector table.

Header fields, in the unencrypted window:

| flash | value | meaning |
|---|---|---|
| `0xB0` | `0x00135000` | Const bank base |
| `0xB4` | `0x001F0000` | user data base |
| `0xBC` | `0x0000C7BC` | header CRC16 (not a standard byte-wise CRC16: all 65,536 polynomials × 2 reflections × 9 masks × 2 byte orders were tried) |
| `0xCC` | `0x00004230` | differs from the flashboot donor; carried through verbatim |
| `0xC0` | `0xB0BEBDC9` | "this is a legal image" magic |
| `0xD0` | low 24 bits `0x134418` | code image length |
| `0xFF` (byte) | `0x55` | encrypted (`0xFF` would mean plaintext) |

## The Const record: an `MVUB` resource filesystem

Never encrypted. Layout, relative to the record body (payload with the 4-byte
flash base stripped):

```
0     "MVUB"
4     u32   total size field
8     u8    entry count
9     entries, stride 16: [name: 8 bytes, space padded][offset u32 LE][size u32 LE]
...   payload, first blob at 0x1000, offsets relative to the MVUB start
```

Entries start at **+9, not +8**, and the entries are contiguous
(`off[n] + size[n] == off[n+1]`).

The SC3 carries **33 resources**, all MPEG-1 Layer II, 96 kbps, 44.1 kHz mono,
the device's voice prompts: twelve semitone names for the auto-tune key prompts
(`A`, `A_flat`, `B`, … `G_falt`, sic), the voice presets (`DianYin`, `HanMai`,
`LiuXingH`, `MoYin`, `NanShen`, `NvShen`, `WaWaYin`, `REChuifa`, `DLguodi`) and
system prompts (`kaiji`, `guanji`, `connect`, `disconne`, `luyin`, `shangyis`,
`xiayisou`, `cardmode`, `Upanmode`, `callring`, `kong`, `zhangshe`).

Because this record is plaintext, **the sound effects are replaceable without
touching the encrypted part of the image**.

```sh
python -m decrypt resources FIRMWARE.MVA           # list them
python -m decrypt resources FIRMWARE.MVA -o out/   # write them out
```

Not every image in this family uses MVUB for its Const record; the parser
reports cleanly when the magic is absent.
