"""The four-fader patch, as a data specification.

WHAT IT DOES
------------
Stock SC3 firmware publishes exactly one of the four fader positions to a host
(the line-in fader, ACP node 0xB6).  All four are digitised internally, but the
other three end up in an on-chip codec register and on two off-chip serial
attenuators, none of which is an ACP node.

The patch takes the handler for ACP `0xFC` - a dead stub whose read path replies
with four hardcoded constants `01 02 03 04` - and makes it reply with the four
live fader positions instead.  The stub's shape is already exactly right: four
bytes in the response body.

    before   A5 5A FC 05 FF 01 02 03 04 16
    after    A5 5A FC 05 FF s0 s1 s2 s3 16      each sN = 0..31

WHERE THE POSITIONS LIVE
------------------------
Four consecutive bytes at `$gp` offsets **-24720, -24719, -24718, -24717**, one
per fader, each holding a ladder position 0..31.

They were located through the LED bar driver at flash 0x02E29E / 0x02E36C /
0x02E53C / 0x02E60C, which computes `level = (step * 9) / 31 - 1` (the division
by 31 done with the magic constant 0x84210843) and dispatches to one of nine LED
patterns.  That is also the proof the LED bars display fader POSITION rather than
audio level.

The scan chain that fills them: an RTOS task at 0x02AE46 polls every ~40 ms via
0x027D20, the enumerator at 0x026C38 walks a 14-entry table at flash 0x0D8A18
selecting four channels (5, 9, 10, 11), 0x026B34 dispatches each to
`ADC_SingleModeDataGet` (0x0399C0), 0x026C9A applies a 101-count deadband, and
0x026CB6 quantises the 12-bit result to 5 bits, giving 32 positions.

ENCODING NOTE
-------------
`lbi.gp $rX, [+#imm16]` encodes as `2e <X<<4 | 7> <imm16 big-endian>`.  So
`2e 17 9f 70` is `lbi.gp $r1, [+#-24720]` (0x9F70 read as a signed int16).
Confirmed against the image's own `2e 17 9f 56` = `[+#-24746]`.
"""

from __future__ import annotations

#: Flash address of the 0xFC handler.
HANDLER_ADDR = 0x01EC74

#: $gp offsets of the four fader positions, one byte each, values 0..31.
FADER_GP_OFFSETS = (-24720, -24719, -24718, -24717)

#: Plaintext byte edits: flash address -> new bytes.
#:
#: Together they occupy 30 of the 32 bytes available in the dead stub.  The
#: existing `bnez38 $r7, 0x1ECC6` at 0x1ECA4 also lands in the new block, so the
#: write path returns fader data too.
PATCH_EDITS = {
    # Read path: jump into the new block, then padding out to it.
    #   0x1ECA6  d5 10        j8 0x1ECC6
    #   0x1ECA8  8x 80 00     mov55 $r0,$r0   (nop padding)
    0x01ECA6: bytes([0xD5, 0x10] + [0x80, 0x00] * 8),

    # The new block.
    #   80 06        mov55 $r0,$r6            tx_buf, for the send call
    #   2e 17 9f 70  lbi.gp $r1,[+#-24720]    fader 0
    #   ae 75        sbi333 $r1,[$r6+#0x5]    -> tx_buf[5]
    #   2e 17 9f 71  lbi.gp $r1,[+#-24719]    fader 1
    0x01ECC6: bytes([0x80, 0x06,
                     0x2E, 0x17, 0x9F, 0x70,
                     0xAE, 0x75,
                     0x2E, 0x17, 0x9F, 0x71]),

    # (0x1ECD2 already holds 0xAE and is left alone.)
    #   76           sbi333 $r1,[$r6+#0x6]    -> tx_buf[6]
    #   2e 17 9f 72  lbi.gp $r1,[+#-24718]    fader 2
    #   ae 77        sbi333 $r1,[$r6+#0x7]    -> tx_buf[7]
    #   2e 17 9f 73  lbi.gp $r1,[+#-24717]    fader 3
    #   10 13 00 08  sbi    $r1,[$r6+#0x8]    -> tx_buf[8]  (32-bit form)
    #   d5 eb        j8 0x1ECB8               rejoin: terminator + jal 0x1E8FA
    0x01ECD3: bytes([0x76,
                     0x2E, 0x17, 0x9F, 0x72,
                     0xAE, 0x77,
                     0x2E, 0x17, 0x9F, 0x73,
                     0x10, 0x13, 0x00, 0x08,
                     0xD5, 0xEB]),
}

#: What those addresses hold in the stock image.  The builder checks this before
#: writing anything, so it cannot silently patch the wrong build.
EXPECTED_ORIGINAL = {
    0x01ECA6: bytes([0x80, 0x06, 0xAE, 0x75, 0x84, 0x22, 0xAE, 0x76,
                     0x84, 0x23, 0xAE, 0x77, 0x84, 0x24, 0x10, 0x13,
                     0x00, 0x08]),
    0x01ECC6: bytes([0x3E, 0x0F, 0x60, 0x3C, 0xAE, 0x45, 0x84, 0x22,
                     0xAE, 0x46, 0x84, 0x23]),
    0x01ECD3: bytes([0x47, 0x84, 0x24, 0x10, 0x10, 0x00, 0x08, 0xFA,
                     0x26, 0x10, 0x10, 0x00, 0x09, 0x84, 0x2A, 0x49,
                     0xFF]),
}

# --------------------------------------------------------------------------
# The version byte.
# --------------------------------------------------------------------------
#
# The vendor flash tool logs `temp_codeversion` and uses it to decide whether to
# write the Const record.  It reads the raw CIPHERTEXT u32 at flash 0x0100B8
# WITHOUT decrypting it, so the value it compares is a ciphertext value.
#
# The plaintext word there is 0x010100B1, in the application's own header block
# at flash 0x0100A0-0x0100FC (which mirrors the flashboot header at 0xA0-0xFC).
# Bumping the plaintext high byte 0x01 -> 0x04 moves the ciphertext u32 from
# 0x178FB3EB to 0x178FB3EE.
#
# TRAP WORTH KEEPING: an earlier attempt bumped the plaintext and the ciphertext
# went DOWN (0x..EB -> 0x..E8), so the tool saw a downgrade.  When a field is
# read without being decrypted, reason about the ciphertext, not the plaintext.
#
# It does NOT gate the Code write.  Lowering it still ran the Const upgrade;
# raising it made the Const line disappear; neither ever produced a Code write.
# It is included so the build reproduces the image that was actually flashed.

VERSION_BYTE_ADDR = 0x0100BB
VERSION_BYTE_ORIGINAL = 0x01
VERSION_BYTE_PATCHED = 0x04

#: Flash address whose ciphertext u32 the flash tool prints as temp_codeversion.
TEMP_CODEVERSION_ADDR = 0x0100B8

# --------------------------------------------------------------------------
# Expected results, for self-verification.
# --------------------------------------------------------------------------

#: Ciphertext words that change (the patched region plus the version word).
EXPECTED_CIPHERTEXT_WORDS_CHANGED = 14

#: CRC16 trailer of the stock V22 image and of the patched build.
STOCK_CRC = 0x4531
PATCHED_CRC = 0x4524

#: What a patched device replies to `A5 5A FC 00 16`.
PATCHED_REPLY_SHAPE = "A5 5A FC 05 FF s0 s1 s2 s3 16"
