# FIFINE SC3: firmware decryption and a four-fader patch

Two pieces of work on the FIFINE SC3, a desktop USB audio mixer built on an
MVsilicon BP1048B2 (the AP82xx audio SoC family, Andes NDS32 core).

**[`decrypt/`](decrypt/)** breaks the firmware encryption. The whole code image
comes out, all 315,654 words of it, verified against independently obtained
plaintext. The cipher is written out in full below and derived in
[docs/cipher.md](docs/cipher.md).

**[`patch/`](patch/)** and **[`tools/`](tools/)** are what I actually wanted:
a firmware patch that exposes all four hardware fader positions over USB HID,
and the host-side tools that turn them into per-application volume. Stock
firmware publishes exactly one fader. The patch was built, flashed, and
confirmed running on real hardware.

The two halves are related but separable. The tools work on stock firmware, at
one fader. The decryption is what made the patch findable.

This repository contains **only original tooling and documentation**. It ships
no firmware: no `.MVA` files, no decrypted images, no extracted audio
resources. Every command here takes a firmware file that *you* supply.

## Why I did any of this

I did not set out to decrypt anything. I had an echo problem.

My motherboard's line out goes into the SC3's line in, so the line-in fader
works as a hardware volume knob for game and Discord audio. That is a good
setup right up until you notice that line in is also being summed into the USB
microphone send, so everyone in the call hears themselves back with a delay.

I tried the obvious things first and all of them failed. Discord's echo
cancellation does not touch it, because as far as the PC is concerned it is
genuine microphone audio. Swapping which source sits on line in just moves the
problem. VoiceMeeter adds a software layer to work around a hardware routing
bug. FIFINE's own V22 firmware release notes say it fixes teammates hearing
your PC audio, and it does close the USB loopback, but the analog line-in path
is still there. Muting the mic does not stop it either, which is what told me
line in has its own path into the USB send rather than bleeding across the
preamp.

So the routing lives in the DSP graph, the DSP graph lives in the firmware, and
the firmware is encrypted. There is no public reverse-engineering tooling for
MVsilicon parts. That is how I ended up here.

Along the way the goal changed. The SC3 has four faders and the
firmware reports exactly one of them to the host. I already wanted a hardware
volume mixer for per-application audio, and I was looking at building a
[deej](https://github.com/omriharel/deej) box out of potentiometers to get it.
It turned out I was sitting in front of a device with four faders that were
already digitised, already scanned by an ADC, and simply never sent anywhere.
That is what the patch fixes.

| what I wanted | what it forced |
|---|---|
| stop line in bleeding into the mic send | reading the DSP routing, which meant decrypting the firmware |
| a hardware per-app volume mixer | a firmware patch, because stock reports one fader out of four |
| do it without opening the case | finding a USB control path, which is the vendor's ACP protocol on `MI_04` |
| do it without bricking the mixer | a reproducible byte-for-byte image build and a verified stock rollback |

The decryption came first and the patch fell out of it. Neither was the point
when I started.

## What the SC3 is

The FIFINE SC3 is a desktop USB audio mixer/interface with an XLR microphone
input, a 3.5 mm line input, headphone and line outputs, four physical faders and
eight buttons. Internally it is an **MVsilicon BP1048B2** (the AP82xx / BP10xx
audio SoC family) running an **Andes NDS32** core, big-endian instructions over
little-endian data. Firmware ships as a `.MVA` container whose code record is
encrypted.

On USB it enumerates as `VID 0x3142 PID 0x0C33`, a composite device:

| interface | class | what it is |
|---|---|---|
| `MI_00` | Audio | the USB audio device |
| `MI_03` | HID | consumer control, 8 standard media-key usages (the buttons) |
| `MI_04` | HID | vendor-defined, usage page `0xFF00`, usage `0x55AA`, **the ACP control channel** |

`MI_04` is the interesting one. It carries the vendor's ACP protocol: 257-byte
input/output reports through which the running DSP graph can be read and
written.

---

## The cipher

The code record is protected by a pure **address-keyed XOR stream** with two
byteswap toggles. For a word-aligned flash address `a`:

```
plaintext(a) = bswap^g(a)( ciphertext_LE(a) ^ ks(a) )

ks(a)        = bswap^e(a)( L(a) ^ C[phi(a)] ^ R[s(a)] )

L(a)         = ((a << 20) ^ (a >> 2)) & 0xFFFFFFFF
phi(a)       = 4-bit nibble-XOR-fold of (a >> 2)
```

* `C`: 16 **key-independent** constants (identical across every image tested in
  this family).
* `R`: 10 **key-dependent** words, selected by `s(a)`.
* `e`, `s`, `g`: per-address labels. `e` and `s` have **no known closed form**.

`g` is not free: it is a **deterministic function of `(e, s)`**.

```
g = 0  iff  (e, s) in {(0,3), (1,5), (1,7), (1,8)}
g = 1  otherwise
```

Only 14 of the 18 possible `(e, s)` pairs occur in the SC3 image (`e=1` pairs
with every `s` in 0..8; `e=0` pairs with only `s` in `{0, 1, 3, 5, 8}`), and a
tenth R word adds a fifteenth pair, `(e=1, s=9)`, on 620 words. So the generator
emits 15 candidate plaintexts per address, against a naive space of 40.

Three exact **invariance laws** hold across the image:

```
ks(a) ^ ks(a ^ d)   is constant   for d in {0x880, 0x110000, 0x110880}
```

For `d = 0x880` the constant is one of `{0x88000220, 0x20020088}`. Those four
deltas (including 0) form a group under XOR, the labels are constant on each
orbit, and that is what lets a solved label propagate to three more addresses.

Full derivation, the ten R constants for the three devices whose keys are known,
and the honest limits of the model are in **[docs/cipher.md](docs/cipher.md)**.

### Why it fell

Two properties, together:

* **It is a stream cipher.** `ct = pt ^ F(key, a)`. There is no chaining and no
  data feedback, proven by a 65,501-byte run of zeros in the XOR of two
  independently built images sharing a key. Recover the plaintext anywhere and
  you have the keystream there for free.
* **The plaintext was already public.** **81 of the 87 chip-0xB1 / gen-0x58
  images still in the collection ship completely unencrypted**, and they are
  built from the same MVsilicon SDK. Encryption is a per-vendor build option and
  most vendors do not use it. Strings recovered from the SC3 appear verbatim in
  roughly a fifth of them.

That turns the problem from a two-time-pad puzzle into a **known-plaintext
attack**: drag SDK code blocks from unencrypted siblings across the SC3
ciphertext, keep only 8-byte exact hits, and every hit yields keystream, which
yields labels, which propagate along the invariance laws. No key was ever
recovered and none was needed.

The 32-bit key itself is burned into chip OTP by a dedicated vendor programmer
and is documented by MVsilicon as unreadable, with decryption done in hardware
on the instruction-fetch path. Extracting the key from hardware is not a route.

---

## The ACP protocol

`MI_04` speaks a framed request/response protocol over 257-byte HID reports
(report ID 0, the frame starts at `buf[1]`):

```
TX:  A5 5A [CTRL] [LEN] [body ...] 16          LEN = 0 means READ
RX:  A5 5A [CTRL] [LEN] [body ...] 16          reply CTRL must equal request CTRL
```

Transport is `SetOutputReport` to send and `GetInputReport` to receive.
`GetInputReport` returns a **cached** report, not an event stream. The device
re-serves the previous reply when a control does not answer, so any client must
poll until the reply's control byte matches the request or it will silently read
stale data.

Control bytes fall into two groups:

* **`0x00`-`0x0E`: codec and system blocks.** `0x00` version, `0x01` system,
  `0x02` query, `0x03` PGA0, `0x04` ADC0, `0x05` AGC0, `0x06` PGA1, `0x07` ADC1,
  `0x08` AGC1, `0x09` DAC0, `0x0A` DAC1, `0x0B` I2S0, `0x0C` I2S1, `0x0D` SPDIF,
  `0x0E` GPIO (documented by the SDK, but this firmware does not answer it).
* **`0x81`-`0xFA`: effect node addresses**, not commands. `addr = 0x81 + index`
  into the effect table. That is the SDK's declared range; the dispatcher's
  default arm actually forwards `0x81`-`0xFB` and `0xFD` (`0xFC` has its own
  arm), which is why reads above the last
  real node are dangerous rather than merely useless.
  **The SC3 has exactly 54 nodes, `0x81`-`0xB6`.**

Also present: `0x80` effect-list / effect-graph stream, `0xFC` a 32-byte scratch
area (a stub on stock firmware, and what the fader patch repurposes),
`0xFE` OTA (**dangerous**, see below), `0xFF` encryption lock.

The full map, how to read the 54-entry effect table out of your own image or
device, and the gain-block payload layout are in
**[docs/acp-protocol.md](docs/acp-protocol.md)**.

---

## SAFETY

Read this before pointing any of these tools at a device.

> **Never read an effect address above `0xB6`.**
> The SC3 has 54 nodes. Addresses above `0xB6` make the firmware index past its
> node array; they "answer" with junk and then **the entire ACP interface stops
> responding** (measured: 3,366 consecutive failures after one such sweep). It
> recovers on its own or on reopen, but every read in between is lost, and a
> wedged interface looks exactly like a clean negative result.

> **Never send `0xFB`, `0xFD` or `0xFE`.**
> `0xFE` is the OTA trigger. In the vendor source its handler sets an upgrade
> counter and never reads the payload, so **any frame including an empty one
> triggers it**; the counter is decremented in the main loop and nothing in the
> tree ever clears it. When it expires the device boots to flashboot. There is no
> gate and no abort short of unplugging first.
> `0xFB` has an unchecked length in the vendor source (it was measured inert on
> this particular build, but the handler is not something to probe). `0xFD` is
> excluded as a precaution.
>
> Every tool in `tools/` refuses these three by raising, not by `assert`, so
> `python -O` cannot disable them, and caps node reads at `0xB6`. Do not remove
> those guards.

Also worth knowing:

* Writes to `0xB9`-`0xE4` make the device reconfigure its USB audio interface,
  so a capture started immediately afterwards fails. It recovers after ~8 s.
* Reads are lossy, and retries matter more than delay. The defaults are
  `delay=0.010, retries=4`, measured at 0% loss over 400 reads; `retries=2` at
  the same delay loses one read in six. Longer delays are not better: 50 ms
  loses everything. **Always print ok/fail counts.** A watcher that does not is
  indistinguishable from a real negative.
* Flashing firmware carries real risk. See [docs/patch.md](docs/patch.md) for
  what was actually required, including the erase-all step and exactly why it
  was recoverable in this one case.

---

## Repository layout

```
decrypt/                    the cipher, the container parser, and a CLI
  cipher.py                   L, phi, keystream, candidates, the invariance laws
  container.py                MVA TLV parse/rebuild + CRC16-CCITT + MVUB resources
  labels.py                   per-address (e, s) label tables
  image.py                    whole-image decrypt / re-encrypt
  cli.py, __main__.py         `python -m decrypt ...`
  labels/sc3_v22.labels.gz    the solved label table for the SC3 V22 image
tools/                      HID/ACP client and utilities, read-only by default
  acp.py                      the protocol client and every safety guard
  effect_table.py             effect-table parser + cached device name reader
  sc3_nodes.py                dump nodes / system blocks / names, watch for changes
  sc3_faders.py               read the faders, stock or patched
  sc3_appvol.py               faders -> Windows per-application volume
patch/                      reproducible build of the four-fader firmware patch
  fader_patch.py              the patch as a commented data specification
  build_fader_patch.py        build, verify, and `--check` an image
docs/
  cipher.md                   the cipher, how it was broken, what is unknown
  acp-protocol.md             the full control map; how to read the effect table
  patch.md                    what the patch does, how to build it, how it flashed
  mva-container.md            the .MVA container format
tests/                      73 tests; no firmware and no hardware needed
```

Documentation index: [cipher.md](docs/cipher.md) ·
[acp-protocol.md](docs/acp-protocol.md) · [patch.md](docs/patch.md) ·
[mva-container.md](docs/mva-container.md)

## Requirements

* Python 3.9+
* `decrypt/`, `patch/` and `tests/` use **only the standard library**.
* `tools/` needs `hidapi` (`pip install hidapi`). `tools/sc3_appvol.py`
  additionally needs `pycaw` + `comtypes` and is Windows-only.

## Quick start

You supply the firmware. Nothing here downloads or contains one. Run everything
from the repository root.

```sh
# what is in the container
python -m decrypt info FIRMWARE.MVA

# pull a record out verbatim (1=Command 2=Code 3=FlashDriver 4=Const)
python -m decrypt extract FIRMWARE.MVA --type 4 -o const.bin

# decrypt the code record using the shipped SC3 label table
python -m decrypt decrypt FIRMWARE.MVA -o SC3_plain.bin

# verify the container CRC16 trailer
python -m decrypt crc FIRMWARE.MVA

# cipher self-test, needs no firmware at all
python -m decrypt selftest

# build your own patch: decrypt, edit, re-encrypt, rebuild, verify
# ADDR:EXPECT:NEW, length-neutral, nothing written unless it verifies
python -m decrypt patch STOCK.MVA -o OUT.MVA \
    --edit 0x1ECA6:8006ae75:d5108000 --dry-run
```

`patch` is the generic form of `patch/build_fader_patch.py`. Read
[docs/patch.md](docs/patch.md) section 8 before using it, and section 6 before
flashing anything it produces.

```sh
# read every effect node safely (caps at 0xB6)
python tools/sc3_nodes.py dump

# read the line-in fader on stock firmware, or all four on patched firmware
python tools/sc3_faders.py --watch

# drive Windows per-app volume from the faders
python tools/sc3_appvol.py --map 0=master 3=discord.exe
```

```sh
# the test suite needs neither a firmware file nor a device
python tests/test_all.py
```

## What "decrypt" needs, honestly

`C` is key-independent and is baked in. `R` for the SC3 is baked in. But `e(a)`
and `s(a)` have no closed form. They were solved per address by the
known-plaintext attack, and that solve is what `decrypt/labels/` holds. So:

* **The SC3 V22 image decrypts completely, out of the box.** The label table is
  checked against the SHA-256 of the code record before it is applied, so it
  cannot silently be used on the wrong image.
* **A different image needs its own label solve**, plus its own `R`. The
  primitives to do that (candidate generation, keystream validation against `R`,
  invariance-law propagation) are in `decrypt/`, but the donor corpus that
  supplies the known plaintext is not distributed here.

The label table contains no firmware content. It is a per-address list of cipher
labels, useful only in combination with a ciphertext you already have.

## Status of the fader patch

Built, verified offline (the rebuilt image decrypts back to exactly the intended
plaintext; 14 ciphertext words change, all inside the patched region, leaving
315,640 of 315,654 byte-identical), flashed with the vendor tool, and
**confirmed running**:

```
stock   A5 5A FC 05 FF 01 02 03 04 16      <- hardcoded stub constants
patched A5 5A FC 05 FF 00 17 00 00 16      <- live fader positions, 0..31
```

`patch/build_fader_patch.py` rebuilds that image byte-for-byte from a stock V22
`.MVA`. Read [docs/patch.md](docs/patch.md) before flashing anything.

## Disclaimer

This material is provided as is, without warranty of any kind, express or
implied. It is published for research, interoperability and educational
purposes.

**You use it entirely at your own risk. I accept no responsibility or liability
for any damage, data loss, bricked hardware, voided warranty, loss of function,
or any other harm arising from the use or misuse of anything in this
repository.**

Specifically, be aware that:

- Writing to a device's flash can render it unusable. The procedure in
  [docs/patch.md](docs/patch.md) required an erase-all step, and it was only
  recoverable because the image being written happened to contain a complete
  flashboot. That is a property of this one file, not a general safety net.
- Probing the ACP interface can wedge it, one control byte can trigger an OTA
that ends at the flashboot prompt, and two more are excluded as a precaution.
Read [SAFETY](#safety) before pointing any of these tools at a device. The
guards in `tools/` are there for reasons that were all measured.
- Modifying firmware will almost certainly void your warranty, and may breach
  the terms of sale or licence for your device.
- Every offset here came from one device on one firmware revision
  (`V22`). A different revision may place things elsewhere, and applying an
  offset blindly can corrupt an image that was otherwise fine.
- Nothing here is legal advice. Laws covering reverse engineering, circumvention
  and modification differ by country, and it is your responsibility to know what
  applies to you.

Do not apply any of this to hardware you cannot afford to lose, and always keep
a verified stock dump before writing anything.

## Credits

This work sits on top of other people's:

| project | used for |
|---|---|
| GNU binutils, Andes NDS32 support | disassembling the decrypted image (`objdump -D -b binary -m n1h -EB`) |
| MVsilicon's own `ACPWorkbench.ini` | the codec and system block names in the control map |
| [hidapi](https://github.com/libusb/hidapi) | the HID transport for every tool in `tools/` |
| [pycaw](https://github.com/AndreMiras/pycaw) | Windows per-application volume in `sc3_appvol.py` |

The attack itself depends on other vendors' choices more than on anything I did.
Encryption is a per-vendor build option in the MVsilicon SDK and most vendors
leave it off, so the same SDK code that sits encrypted in the SC3 sits in the
clear in dozens of sibling firmwares. Without that corpus there is no
known-plaintext attack and none of this happens.

## Licence

MIT. See [LICENSE](LICENSE).

The MIT grant covers my own work: the code, the documentation, and the solved
label table. Vendor-derived material is kept to what interoperability actually
requires, which is now the block names in the control map and the 47 bytes of
stock instruction encoding in `patch/fader_patch.py` that the builder checks
before it writes. Those are FIFINE's and MVsilicon's and are not licensed onward
by me. The 54 effect node names are deliberately **not** reproduced anywhere
here: `tools/effect_table.py` reads them from your device or from your own
decrypted image at runtime.

This is independent interoperability research on hardware I own. "FIFINE",
"MVsilicon" and product names are the trademarks of their respective owners; no
affiliation or endorsement is implied, and no vendor firmware, software or
documentation is redistributed here.
