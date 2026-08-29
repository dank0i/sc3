# The ACP protocol on the FIFINE SC3

ACP is MVsilicon's configuration protocol for the AP82xx / BP10xx audio SoCs.
On the SC3 it is reachable over USB with no driver, no vendor software and no
hardware modification.

Everything below was either read out of the vendor's own SDK source, read out of
the decrypted SC3 firmware, or measured on the device. Where those disagree it is
called out.

---

## Transport

| | |
|---|---|
| device | `VID 0x3142`, `PID 0x0C33` |
| interface | `MI_04`, HID, usage page `0xFF00`, usage `0x55AA` |
| report length | 257 bytes in and out, report ID 0 |
| send | `HidD_SetOutputReport` (`hid.write` in hidapi) |
| receive | `HidD_GetInputReport` (`hid.get_input_report`) |

The usage `0x55AA` is a vendor convention. It is tempting to read it as the
frame magic, but the magic is `A5 5A` and `0x55AA` is neither `A55A` nor
`5AA5`, so the resemblance is a coincidence rather than a derivation.
Interface `MI_03` is a plain consumer-control HID with exactly 8 single-bit
usages (Volume Up/Down, Next/Prev Track, Mute, Fast Forward, Play/Pause, Stop)
so the SC3's buttons are standard media keys that any remapper can use. The
faders are **not** on that interface; standard HID sees no continuous control.

### Framing

```
TX:  A5 5A [CTRL] [LEN] [body ...] 16       LEN = 0 means READ
RX:  A5 5A [CTRL] [LEN] [body ...] 16
```

The frame begins at `buf[1]` because `buf[0]` is the report ID.

### Two behaviours that produce false results

1. **`GetInputReport` returns a cached report.** The device does not push
   unsolicited reports, and when a control does not answer it **re-serves the
   previous reply**. A client that does not check `reply CTRL == request CTRL`
   will read the last successful reply and conclude a dead control is alive. This
   is exactly what made one unimplemented control look responsive during an early
   sweep. `tools/acp.py` enforces the match on every read.
2. **Reads need settle time.** At `delay = 0.006 s, retries = 1` every read fails
   silently, and a watcher that does not count failures then reports "nothing
   changed", indistinguishable from a real negative. Use `delay = 0.010,
   retries = 2` as a floor and always print ok/fail counts.

There is **no checksum on ACP bodies**. A `crc16()` exists in the vendor's
protocol source and is never called.

---

## SAFETY

### Never read above node `0xB6`

The SC3 has exactly 54 effect nodes, `0x81`-`0xB6`. The dispatcher's default arm
computes `idx = (CTRL + 0x7F) & 0xFF` and only requires `idx < 0x7D`, so it
happily forwards `0xB7`-`0xFD` to the node accessor, which then indexes a
54-entry node-type table out of bounds. Observed: junk replies (`72 72 72`)
followed by **the whole ACP interface going unresponsive**, 3,366 consecutive
failed reads against a healthy baseline. It recovers on reopen. A sweep capped at
`0x80` completed cleanly; every sweep that ran to `0xFA` wedged.

### Never send `0xFB`, `0xFD` or `0xFE`

* **`0xFE` is a one-way trip to flashboot.** The vendor handler sets an OTA
  counter and never reads the payload, so any frame including an empty one
  triggers it. The counter is decremented once per main-loop iteration and
  **nothing in the vendor tree ever clears it**. When it hits zero the device
  boots to the flashboot. The only abort is unplugging before it expires.
  Mitigating detail: the boot call writes a hardware register, not flash, so a
  power cycle recovers.
* **`0xFB`** has an unchecked length in the vendor source (`num = buf[0]` with no
  bound, then u32 writes into a 256-byte buffer). On the SC3 build it was
  measured **inert**: it produces no report at all and behaves like an
  unimplemented code, so the handler is probably not compiled in or returns
  early. That is a reason not to worry retroactively, not a reason to send it.
* **`0xFD`** falls into the dispatcher's default arm with `idx = 124`, i.e. it
  gets treated as an out-of-range node. Excluded for the same reason as `0xB7+`.
  (An earlier note claiming `0xFD` saves parameters to flash has no source behind
  it and should not be repeated.)

### Other things that look like faults

* Writes to `0xB9`-`0xE4` make the device reconfigure its USB audio interface; a
  capture started immediately afterwards returns nothing and recovers after
  about 8 seconds. It is the write itself, not the value.
* Node `0x07` (ADC1 digital volume) is driven by the physical mute button and
  reads back zeroed while the user has the mic muted, overriding writes.
* Node `0xB0` ("Usb Out Gain") is driven by the physical mic gain knob and moves
  on its own.

---

## Control map

The names come from `ACPWorkbench.ini`'s section headers and from the vendor
SDK; the "SC3" column is what was measured on the device.

| CTRL | block | SC3 |
|---|---|---|
| `0x00` | Firmware version | answers |
| `0x01` | System control | answers |
| `0x02` | System query (5 fields: memory used, MCPS, MCPS max, ...) | answers, and moves with audio, so it behaves as a meter |
| `0x03` | PGA0: the analog input front end (line1 L/R, line2 L/R, mic3/mic4 gain + boost) | answers |
| `0x04` | ADC0: line-in digital volume | answers; offsets 5-8 are the L/R 16-bit volumes |
| `0x05` | AGC0 | **no reply** |
| `0x06` | PGA1 | answers |
| `0x07` | ADC1: mic digital volume | answers; driven by the mute button |
| `0x08` | AGC1 | answers |
| `0x09` | DAC0 | answers |
| `0x0A` | DAC1 | answers |
| `0x0B` | I2S0 | answers |
| `0x0C` | I2S1 | answers |
| `0x0D` | SPDIF | answers |
| `0x0E` | GPIO | answers with all zeros: **the handler body is empty** |
| `0x0F`-`0x7F` | n/a | nothing answers |
| `0x80` | effect list / effect-graph stream | answers; with a 1-byte index it returns that effect's name |
| `0x81`-`0xFA` | **effect node addresses** | only `0x81`-`0xB6` exist on the SC3 |
| `0xFB` | output-routing enquiry in the vendor source | inert here, **do not send** |
| `0xFC` | 32-byte scratch RAM read/write | a stub returning `FF 01 02 03 04`; the fader patch repurposes it |
| `0xFE` | OTA → flashboot | **DANGEROUS, do not send** |
| `0xFF` | encryption lock; a `LEN=0` read returns 8 bytes carrying the encrypted flag | |

`0x11` appears in the vendor flash tool as a flash/boot-mode control. It does not
answer in normal operation on the SC3. Boot mode is entered by a completely
different mechanism (a 9-byte `HidD_SetFeature` handshake beginning `00 AA`), and
the bootloader that comes up does not speak ACP at all.

### Correction worth carrying

`0xFC`'s `01 02 03 04` reply was once read as a list of chain ids. It is not: an
unrelated karaoke board reports the identical four bytes, so it is a vendor
default, and the vendor source describes `0xFC` as a scratch area. The chain ids
actually come from the `N:` prefix in the `0x80` name strings.

---

## Effect nodes

**`ACP address = 0x81 + index`** into the effect table. Confirmed three ways: by
the vendor SDK (`DEMO_gain_control0_ADDR = 0x81`; `count = DEMO_COUNT_ADDR -
0x81`), by the decrypted firmware (`addi $r16, $r0, #-129` at the node accessor),
and structurally on the device: `0x9D`-`0x9F` are 3 nodes of 18 parameters (the
three DRCs), `0xA0`-`0xA6` are 7 nodes of **52** parameters, and the SDK documents
`eq` as having exactly 52.

Node totals close exactly: 28 fixed nodes (`0x81`-`0x9C`) + 3 DRC + 7 EQ + 16
gain = **54**.

### Reading a node

```
request  A5 5A <addr> 00 16
reply    A5 5A <addr> <LEN> FF <status:i16> <p0:i16> <p1:i16> ... 16
```

The leading `FF` is a **parameter selector**, not data: `0xFF` = all parameters,
`0x00` = the enable flag, `1..n` = one specific parameter. So a single parameter
can be read or written without touching the whole block. Expected `LEN` for a
node with `N` parameters is `(N + 1) * 2 + 1`.

The read path returns **stored node state** copied out of the node's context
memory. Local knob and fader handlers write into that same context, which is why
readback tracks hardware.

### Writing a node

```
all parameters:   A5 5A <addr> <LEN> FF <status:i16> <p0:i16> ... 16
one parameter:    A5 5A <addr> 03 <index:u8> <value:i16 LE> 16
```

The single-parameter form needs **`LEN = 3`**, not 2. A read-modify-write through
the `0xFF` bulk form round-trips byte for byte.

ACP writes land in live registers and a power cycle reverts them.

### Gain nodes

The sixteen nodes `0xA7`-`0xB6` are `gain_control`, effect type `0x0F`, proven by
the registration loop in the decrypted firmware (16 iterations, `movi55 $r4,#0xf`,
ACP addresses `0xA7..0xB6`).

They report `status` plus two parameters; the gain is the second, at **raw report
offset 10**. Values are **linear Q12 with 4096 = unity**, applied as
`out = clip16((gain * in + 0x800) >> 12)`. Writes clamp to `0x3FFF`.

This contradicts the SDK descriptor, which documents the parameter as centi-dB
clamped to -9000..+1200; measured values of 4096 / 3254 / 7284 / 0 are impossible
in that range. Treat the SC3 as linear Q12.

Observed resting values: `0xA7`-`0xAF` 4096, `0xB0` (Usb Out) 7284, `0xB3`-`0xB5`
3254, `0xB6` whatever the line-in fader is set to.

### Per-type parameter counts

Read out of the decrypted firmware's dispatch table (each handler writes
`tx_buf[3] = LEN`, and `nparams = (LEN - 1) / 2 - 1`):

| type | params | | type | params | | type | params |
|---|---|---|---|---|---|---|---|
| 3 | 5 | | 13 | 3 | | 23 | 2 |
| **4 (`eq`)** | **52** | | 14 | 2 | | 24 | 3 |
| 5 | 4 | | 15 | 2 | | 25 | 3 |
| 7 | 1 | | 16 | 1 | | 26 | 6 |
| 9 | 1 | | 19 | 2 | | 27 | 6 |
| 10 | 6 | | 20 | 1 | | 28 | 1 |
| 11 | 1 | | 21 | 2 | | 29 | 5 |
| 12 | 1 | | 22 | 1 | | 30 | 1 |

`gain_control` is type `0x0F` (15).

### Dispatch, from the decrypted firmware

```
0x0257D0  Communication_Effect_Config(r0 = CTRL, r1 = body, r2 = len)
          switch on 0x01 0x02 0x03 0x04 0x06 0x08 0x0A 0x0B 0x0C 0x0D 0x80 0xFC 0xFF
          default:  idx = (CTRL + 0x7F) & 0xFF ; require idx < 0x7D ; jal 0x025574
0x025574  SetEffectParamsByAddr(r0 = addr, r1 = body, r2 = len)
          idx  = addr - 0x81
          type = u16 table at gp-38132 indexed by idx     (must be < 31)
          jump table at 0x02559C, 31 entries
          each stub loads the node context from the table at gp-38372, then calls
          the per-type handler
```

The response builder lives at `gp-40900`: each handler does
`memset(tx_buf, 0, 0x100)` then writes `A5 5A <addr> <LEN> FF` and copies the
node's parameters out of its context.

The **node type table is not in flash.** Every 54-entry u16 window in the image
was searched under the correct constraints and nothing matched; it is built in
RAM at init, presumably from the effect-graph blob that `0x80` streams. (A
54-entry table at flash `0x123012` does satisfy the structural filter and implies
a plausible `$gp`, but its values are a monotone staircase and the implied
context table holds packed u16 pairs rather than pointers. It is a coincidence
and was rejected.)

The **only caller** of `SetEffectParamsByAddr` is the ACP dispatcher, so nothing
inside the firmware writes effect parameters except an incoming host command.

---

## The effect table

Read directly out of the decrypted firmware at flash `0x000D4508`, 25-byte
stride, 54 entries, ending at `0x000D4A4E`. A name is padded to either 25 or 23
characters; a 23-character literal carries two trailing NULs.

The digit before the colon is the chain: **1 = Mic, 2 = Music, 3 = Guitar,
4 = Rec**. Typos are the vendor's.

The names themselves are the vendor's, so this repository does not reproduce
them. Two ways to get the list, both needing only something you already own:

```sh
# ask the device: control 0x80 with a one-byte index returns that node's name
python tools/sc3_nodes.py names

# or parse the table out of your own decrypted image
python -m decrypt decrypt FIRMWARE.MVA -o plain.bin
python tools/sc3_nodes.py names --image plain.bin   # cross-checks the two
```

`tools/effect_table.py` holds the parser (`names_from_image`) and a caching
reader for the device (`DeviceNames`). Prefer either over a table written down
anywhere: a different firmware revision can rename or reorder nodes, and the
device is always right about itself.
### `0xB6` is the line-in fader, whatever the label says

The SC3 has no SPDIF connector. FIFINE reused three unused input-gain slots
(`0xB3` I2s, `0xB4` Bt, `0xB6` Spdif), and `0xB6` is wired to the **line-in
fader**. Three-point calibration with the fader physically set:

| fader | `0xB6` | step |
|---|---|---|
| 0 % | 0 | 0 / 31 |
| 25 % | 528 | 4 / 31 |
| 100 % | 4092 | 31 / 31 |

Endpoints exact; the compressed midpoint is an audio-taper pot, which is correct
for a volume control. Reported values are always multiples of **132**, and
`132 × 31 = 4092`, so the fader is a **32-position ladder**, not a 10-bit value.
(An earlier "1023 × 4" reading was arithmetically consistent but the wrong
interpretation.)

`0xB3`/`0xB4`/`0xB5` sit at a constant 3254 and are not connected to anything.

---

## What the protocol does NOT give you

Established by measurement and by three independent readings of the vendor
source; do not re-walk these.

* **No memory read primitive.** The firmware-side dispatcher handles only a fixed
  set of controls and **no command carries an address operand**. Probing every
  responsive control with 1- and 4-byte payloads found only `0x80` to be
  parameterised. Two independent public reverse-engineering efforts reached the
  same conclusion. The official flash tool contains no read anywhere either.
* **No audio-path routing control.** Nothing in the config space selects or
  switches a path. `PhubPathSel` is compiled into the code image and set at init.
  The persisted flash configuration covers `0x00`, `0x01`, `0x03`-`0x0D`, `0x80`,
  `0x81`-`0xFB` and `0xFC`, with no path entry.
* **No exploitable memory disclosure.** The reachable node handler has the same
  unchecked-length shape as `0xFB`, but the maximum parameter count on this
  device is 52 (104 bytes), well short of the ~124 needed to wrap the `uint8_t`
  length field. The write path's over-read stays inside the 257-byte HID report
  buffer and leaks only the caller's own prior payload.

## Tooling

```sh
python tools/sc3_nodes.py devices    # list the SC3's HID interfaces
python tools/sc3_nodes.py dump       # every node, 0x81..0xB6, with names
python tools/sc3_nodes.py system     # the codec/system blocks
python tools/sc3_nodes.py names      # make the device recite its own table
python tools/sc3_nodes.py watch      # poll and print what changes
```
