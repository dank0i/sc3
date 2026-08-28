# The four-fader firmware patch

Stock SC3 firmware exposes **one** of its four fader positions to a host. This
patch exposes all four.

```
stock     A5 5A FC 00 16  ->  A5 5A FC 05 FF 01 02 03 04 16     hardcoded stub
patched   A5 5A FC 00 16  ->  A5 5A FC 05 FF s0 s1 s2 s3 16     live positions, 0..31
```

Built, verified offline, flashed with the vendor's own tool, and **confirmed
running on hardware**, stable across consecutive reads.

> Read the whole of section 5 before flashing. Getting the patch onto the device
> required erasing all flash, which is survivable only because of a specific
> property of this particular file.

---

## 1. Why a patch was needed

All four faders *are* digitised. The scan chain, traced end to end in the
decrypted firmware:

```
0x02AE46  RTOS task, ~40 ms period
0x027D20  poll; calls the key scanner and the fader scanner
0x026C38  enumerator over a 14-entry table at flash 0x0D8A18, keeping mask & 0xE20
          -> four channels: 5, 9, 10, 11.  Drives select lines through GPIO and
          arms a 2 ms settle timer
0x026B34  channel dispatch, each calling ADC_SingleModeDataGet (0x0399C0)
0x026C9A  deadband: reject unless abs(new - last) >= 101 counts
0x026CB6  quantiser: 12-bit result >> 7, clamped to 31   -> 32 positions
0x026D4E  emits message 0x9100 / 0x9200 / 0x9300 / 0x9400 plus the step
```

Where each one ends up is the problem:

| channel | destination | host-readable? |
|---|---|---|
| 10 | ACP gain node **0xB6**, parameter index 2, gain = 132 × step | **yes** |
| 11 | on-chip codec digital volume, register `0x4002D030` bits [13:0] and [29:16] | no, not an ACP node |
| 5, 9 | 10-bit serial frames out two two-wire buses (0x2D3BA, 0x2D42E) to what look like M62429-family attenuators | no |

So three of the four have no representation the ACP protocol can report, but
the firmware holds all four positions in RAM, and the LED bar driver reads them.
A patch only has to publish what is already there.

### A correction worth recording

An earlier analysis concluded the opposite: that the SAR ADC was dead code, that
the faders were pure analog pots, and that **no firmware modification could ever
expose them**. Every one of those was an artifact of working from a partially
decrypted image: `grep -c "jal 0x399c0"` returns 0 at 84.49% coverage and **15**
at 100%. Never conclude absence-of-callers from an incomplete image, and treat a
user's contradicting physical observation as evidence rather than noise.

---

## 2. Where the positions live

Four consecutive bytes at `$gp` offsets **-24720, -24719, -24718, -24717**, one
per fader, each 0..31. (`$gp = 0x2000DFD8`, from `sethi $gp,#0x2000d ; ori
$gp,$gp,#0xfd8` at flash 0x11A90.)

Found through the **LED bar driver** at flash 0x02E29E / 0x02E36C / 0x02E53C /
0x02E60C, which computes `level = (step * 9) / 31 - 1` (the division by 31 done
with the magic constant `0x84210843`), and dispatches to one of nine LED
patterns. That is also the definitive proof that the LED bars display fader
*position* and not audio level.

The step is persisted as a byte and the gain recomputed from it on unmute and on
global refresh, which is why the value survives.

---

## 3. Why ACP `0xFC` was the right target

The `0xFC` handler at flash 0x01EC74 is a stub. Its read path and its write path
were **both** dead code, and the read path replied with four hardcoded constants,
exactly the shape needed, so the response length, the frame terminator and the
send call all stay untouched. 32 bytes of dead code were available; the patch
uses 30.

The vendor SDK describes `0xFC` as a 32-byte scratch RAM area. Nothing else in
the image reads that path.

---

## 4. The patch

```
0x1ECA6  d5 10                j8 0x1ECC6            read path -> the new block
0x1ECA8  8x (80 00)           mov55 $r0,$r0         padding

0x1ECC6  80 06                mov55 $r0,$r6         tx_buf, for the send
0x1ECC8  2e 17 9f 70          lbi.gp $r1,[+#-24720] fader 0
0x1ECCC  ae 75                sbi333 $r1,[$r6+#0x5] -> tx_buf[5]
0x1ECCE  2e 17 9f 71          lbi.gp $r1,[+#-24719] fader 1
0x1ECD2  ae 76                sbi333 $r1,[$r6+#0x6] -> tx_buf[6]
0x1ECD4  2e 17 9f 72          lbi.gp $r1,[+#-24718] fader 2
0x1ECD8  ae 77                sbi333 $r1,[$r6+#0x7] -> tx_buf[7]
0x1ECDA  2e 17 9f 73          lbi.gp $r1,[+#-24717] fader 3
0x1ECDE  10 13 00 08          sbi    $r1,[$r6+#0x8] -> tx_buf[8]   (32-bit form)
0x1ECE2  d5 eb                j8 0x1ECB8            rejoin: terminator + jal 0x1E8FA
```

The existing `bnez38 $r7, 0x1ECC6` at 0x1ECA4 also lands in the new block, so the
write path returns fader data too.

**`lbi.gp` encoding**, since it is not obvious: `2e <reg<<4 | 7> <imm16
big-endian>`. So `2e 17 9f 70` is `lbi.gp $r1,[+#-24720]`, with `0x9F70` read as
a signed int16. Confirmed against the image's own `2e 17 9f 56` = `[+#-24746]`.

### The version byte

The build also changes one plaintext byte at flash `0x0100BB`, `0x01` → `0x04`.

The vendor flash tool logs a `temp_codeversion` and uses it to decide whether to
write the **Const** record. It reads the raw **ciphertext** u32 at flash
`0x0100B8` *without decrypting it*, so the value it compares is ciphertext:
`0x178FB3EB` stock, `0x178FB3EE` patched.

Two things worth carrying away:

* **When a field is read undecrypted, reason about the ciphertext.** An earlier
  build bumped the plaintext version and the ciphertext went *down*
  (`…EB` → `…E8`), so the tool saw a downgrade.
* **It does not gate the Code write.** Lowering it still ran the Const upgrade;
  raising it made the Const line vanish; neither ever produced a Code write. The
  byte is included only so the build reproduces the image that was flashed.
  `--no-version-bump` omits it.

---

## 5. Building it

```sh
python patch/build_fader_patch.py STOCK_V22.MVA -o SC3_V22_FADERS.MVA
python patch/build_fader_patch.py --check SC3_V22_FADERS.MVA
```

The build is deterministic and self-verifying. It:

1. parses the container and confirms the code record is the exact image the
   shipped label table was solved for (SHA-256), refusing anything else;
2. decrypts the code record;
3. confirms the bytes about to be overwritten are the stock bytes it expects,
   refusing an already-patched or unrecognised build;
4. applies the plaintext edits;
5. re-encrypts under the same keystream;
6. rebuilds the container and recomputes the CRC16-CCITT trailer;
7. verifies the result.

Verification output on the reference build:

```
PASS  re-encrypted image decrypts back to exactly the intended plaintext
PASS  0x0100bb / 0x01eca6 / 0x01ecc6 / 0x01ecd3 read back as intended
PASS  14 ciphertext words changed, all inside the patched region
      315640 of 315654 words left byte-identical
PASS  changed-word count 14 (reference build: 14)
PASS  CRC16 trailer recomputed: 0x4524 (was 0x4531)
info  49 bytes differ from the input, out of 1726821
```

`--no-version-bump` produces trailer `0xA00B` and 13 changed words.

**The CRC matters.** The trailer is CRC16-CCITT (poly 0x1021, MSB-first, init 0,
no final XOR) over `file[:-4]`, stored as a u16 LE followed by two zero bytes.
The implementation is validated by reproducing the *stock* file's own trailer,
`0x4531`, before it is trusted to produce a new one. An image with a CRC32
trailer is rejected by the flash tool.

---

## 6. Flashing it

> **This is the dangerous part and it is not a routine operation.** What follows
> is a record of what actually happened, not a recommendation.

Tool: `MV_AP82xx_BP10xx_PC_Tools_V2.2.9`, function 1 (MVA file upgrade). Two
checkboxes:

| label | meaning |
|---|---|
| 强制升级 | force upgrade: safe, and on its own it did nothing useful |
| 全部擦除Flash | **erase all flash**, the dangerous one |

### What did not work

Six attempts. Force-upgrade alone, and three different `temp_codeversion` values.
Every one of them reached 100%, reported success, and wrote **only the Const
record**. The device was never changed and never damaged: `0xFC` still returned
the stub, the version was identical, both HID interfaces stayed up and the mic
meter stayed live throughout.

### What did work

**Erase-all-flash + force-upgrade**, with the patched image.

### Two things that will mislead you

* **The tool never announces a Code write.** Its log said `Const upgrade..... /
  upgrade ok!`, exactly what it said on all five failures. **Judge success by
  reading the device, not by the tool's log.**
* **Immediately after the flash, enumeration returned nothing** and I thought I
  had bricked it. It was transient: the device was still re-enumerating, and a
  full HID enumeration moments later showed both interfaces back. **Always
  re-check enumeration before declaring a device dead.**

### Why erase-all was survivable here

The type-2 Code record spans flash `0x000000`-`0x134418`, which **includes a
complete flashboot**, verified by decrypting `code[0:0xF0E0]` and matching it
against a known plaintext flashboot, 61,654 of 61,664 bytes, the differences
being SC3-specific header fields. So the erase is repaired by the same write that
follows it.

The flash tool itself embeds **no fallback bootloader** (zero `MV` + chip + gen
signatures in its 11.5 MB executable). That property of the *file*, not of the
tool, is the only reason erase-all was recoverable.

**If your image's Code record does not include the flashboot, an erase-all
failure mid-write leaves no bootloader and no software recovery.** Every attempt
before this one was safe precisely because the flashboot was never in play.

### Before you flash

* Keep the stock `.MVA`. It is the recovery image.
* No rescue mode is documented anywhere for this device. Recovery from a truly
  failed write would need a SOIC-8 clip on the SPI flash.
* Nothing in this repository writes to the device. Flashing is done with the
  vendor tool, deliberately.

---

## 7. Reading the faders afterwards

```sh
python tools/sc3_faders.py --watch
```

```
request  A5 5A FC 00 16
reply    A5 5A FC 05 FF s0 s1 s2 s3 16      each sN = 0..31
percent  = 100 * sN / 31
```

Then map them to per-application volume:

```sh
python tools/sc3_appvol.py --map 0=master 3=discord.exe     # Windows
```

### Feeding deej instead

There is no deej bridge in this repository, because `sc3_appvol.py` already does
the job the SC3 was bought for and a second path to the same outcome is a second
thing to keep working. If you already run
[deej](https://github.com/omriharel/deej) and would rather the SC3 stood in for
its hardware, the wire format is short enough to state here rather than ship.

deej's serial receiver takes one line per update: fader values in channel order,
pipe-delimited, terminated with `\n`. The scale is **0..1023**, and the SC3's 32
positions land on it exactly, because `31 * 33 == 1023`. So `s * 33` is lossless
and needs no rounding:

```
0|561|1023|264\n
```

Two things will waste your afternoon if you skip them:

* **The scales differ between deej transports.** Serial is 0..1023, but DeejNG's
  WebSocket interface takes **0..100**, and it swallows the first update after
  connect as calibration. Sending a 0.0..1.0 float down the serial route yields
  `0.42/1023`, which is silence, and looks like a dead device rather than a unit
  mistake.
* **Serial needs a virtual COM pair** (`com0com` on Windows, a pty elsewhere),
  since the SC3 is an HID device and has no serial port of its own.

At 25 Hz, matching the firmware's own fader scan rate, that is the whole
integration.

## 8. Building a patch of your own

`patch/build_fader_patch.py` reproduces one specific patch. For anything else
there is a generic command:

```sh
python -m decrypt patch STOCK.MVA -o OUT.MVA \
    --edit 0x4420A:04:01
```

`--edit` is `ADDR:EXPECT:NEW`, repeatable, and the address is a flash address in
the **decrypted** image. It decrypts, checks every target holds exactly the bytes
you said it would, applies the edits, re-encrypts, rebuilds the container with a
corrected CRC16 trailer, and then decrypts the result again to prove it matches
what you intended. If any of that fails, nothing is written. Add `--dry-run` to
run the whole thing and write nothing regardless.

The usual loop:

```sh
python -m decrypt decrypt STOCK.MVA -o plain.bin     # 1. get the plaintext
objdump -D -b binary -m n1h -EB plain.bin | less     # 2. find your target
python -m decrypt patch STOCK.MVA -o OUT.MVA \       # 3. build
    --edit 0xADDR:<stock bytes>:<your bytes> --dry-run
```

Step 2 is the whole job. The tool does the bookkeeping; it has no idea whether
your replacement instructions are correct.

### What the command refuses to do, and why

* **Length changes.** `EXPECTED` and `NEW` must be the same size. Nothing here
  relinks, so growing or shrinking code shifts every branch target after it and
  produces an image that decrypts perfectly and runs into the weeds. Pad with
  no-ops instead: `80 00` is `mov55 $r0,$r0`.
* **An edit whose target does not hold the expected bytes.** This is the guard
  that stops a patch written for one build being applied to another. It is not
  optional and there is no flag to skip it.
* **Overlapping edits**, because the result would depend on application order.
* **An image with unsolved words.** Re-encrypting a partial decrypt writes
  garbage.
* **A damaged input.** If the container CRC16 does not match, it stops.

### Traps that will not announce themselves

**The flash tool reads the version as CIPHERTEXT.** `temp_codeversion` is the raw
u32 at flash `0x0100B8`, read **without decrypting**. Bumping the plaintext
version byte therefore moves the ciphertext by an unrelated amount, and it can
move it *down*: an earlier build here raised the plaintext and sent the
ciphertext from `0x178FB3EB` to `0x178FB3E8`, so the tool saw a downgrade. If you
touch a field something reads undecrypted, reason about the ciphertext.

**The header CRC16 cannot be recomputed.** The word at flash `0xBC` is a header
CRC16 that is not a standard byte-wise CRC16; all 65,536 polynomials by 2
reflections by 9 masks by 2 byte orders were tried and none reproduces it. So a
patch landing in the header windows (`0xA4`-`0xFF`, and the application's mirror
at `0x0100A4`-`0x0100FF`) cannot have its CRC corrected by anything here. The
fader patch does change `0x0100BB` and the device boots and runs, which suggests
that field is not verified at boot, but that is one observation on one device and
not a guarantee. Treat the header windows as off limits unless you have a reason.

**Those windows are also stored unencrypted.** 23 words at `0xA4`-`0xFF` are
plaintext in the image. The tooling passes them through correctly, but do not be
surprised when a hex editor shows your edit unchanged in the built `.MVA`.

**The vendor tool never announces a Code write.** Its log says
`Const upgrade..... / upgrade ok!` whether or not your code reached the device.
Judge success by reading the device back, never by the log. See section 6.

### Before you flash anything this produces

Everything in section 6 applies unchanged, and none of it is optional:

1. Keep the stock `.MVA` you built from. It is your only rollback.
2. `python -m decrypt patch ... --dry-run` first, and read every PASS line.
3. Expect to need erase-all-flash plus force-upgrade. That is the only sequence
   that ever produced a Code write here.
4. Understand *why* erase-all was survivable: the type-2 Code record spans flash
   `0x000000`-`0x134418` and includes a complete flashboot, so the erase is
   repaired by the same write. That is a property of this file. Verify it holds
   for yours before you rely on it.
5. Read the device back and confirm the behaviour changed. A device that
   enumerates is not a device that took your patch.

If any of that sounds like more risk than the change is worth, it probably is.
There is no recovery path here that does not depend on the image you are writing
being bootable.

### Still unmapped

**Which physical fader is `s0`..`s3` is not established.** Move one at a time
with `tools/sc3_faders.py --watch` and read it off. The scan order in the
firmware is channels 5, 9, 10, 11, and channel 10 is the line-in fader (the one
that also appears at ACP `0xB6`), which gives a starting hypothesis but not an
answer.

Resolution is **32 positions**, about 3.2% per step. That is the firmware's own
quantiser and no host software can improve on it.
