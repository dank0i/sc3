# The MVsilicon AP82xx / BP10xx code cipher

How the FIFINE SC3's firmware is encrypted, how it was broken, and what is still
unknown.

---

## 1. The scheme

For a word-aligned flash address `a`:

```
plaintext(a) = bswap^g(a)( ciphertext_LE(a) ^ ks(a) )

ks(a)        = bswap^e(a)( L(a) ^ C[phi(a)] ^ R[s(a)] )

L(a)         = ((a << 20) ^ (a >> 2)) & 0xFFFFFFFF
phi(a)       = nibble-XOR-fold of (a >> 2), giving 4 bits
```

`bswap` is a 32-bit byte reversal and is an involution, so `bswap^0` is the
identity and encryption is the same expression run backwards.

Three per-address labels:

| label | range | role |
|---|---|---|
| `e` | 0, 1 | byteswaps the keystream **inside** the XOR |
| `s` | 0..9 | selects a word of the key-dependent table `R` |
| `g` | 0, 1 | byteswaps the result **outside** the XOR |

`g` is not independent. It is a **function of `(e, s)`**:

```
g = 0  iff  (e, s) in {(0,3), (1,5), (1,7), (1,8)}
g = 1  otherwise
```

Verified over 15,362 ground-truth words: zero words where the rule is
impossible. This collapses the candidate set per address from 36 to the 15 that
actually occur.

Not all `(e, s)` pairs occur. In the SC3 image `e = 1` pairs with every `s` in
0..8, but `e = 0` pairs with only `s` in `{0, 1, 3, 5, 8}`. `s` is also wildly
non-uniform (chi-squared over 9 bins ≈ 1096, where uniform would be ~8).

### `phi` in detail

`phi(a)` is the XOR of the eight nibbles of `a >> 2`. Implemented as four
parities, which is what `decrypt/cipher.py` does:

```
bit 0 = parity(a & 0x44444444)
bit 1 = parity(a & 0x88888888)
bit 2 = parity(a & 0x11111110)
bit 3 = parity(a & 0x22222220)
```

Because it folds `a >> 2`, address bits 0 and 1 never participate.

### Constants

`C` is **key-independent**: the same 16 words appear in every image of this
family that has been examined.

```
C = 00000000 14A98027 2B8C9A38 2E86EA45 5B939ACC E64E5F89 814C87E6 8ACCE9D8
    A6DBFDF0 172715FE D586D309 C24C4816 F97C9ADA FFA6FB85 7CB74D7E 534758F1
```

`R` is **key-dependent**. Three are known, one per device whose keystream could
be exposed:

```
R_SC3     = 02CB99CA 0BD40F34 2A10CB15 2B792BE3 731CEEF9
            8CE31106 9297505B D486D41C E7F1036D 454F888C
R_SY002   = 0D71D5DA 13059487 3B3591EC 551410C0 AAEBEF3F
            AB820FC9 D7109DB5 DE0F0B4B F28E2A25
R_ONOORUS = 0A7A8487 521F419D 5376A16B 75BE694D 7CA1FFB3
            999B6514 ADE0BE62 EBF13A25 F5857B78
```

The tenth entry, `R[9] = 0x454F888C`, is **only established for the SC3**. It is
rare (used with `(e=1, s=9)` on 620 words image-wide, about 32 per 64 KB
region), and it was invisible until 84% of the image was already solved. Adding
it dropped unexplained ground-truth words from 54 to 23. No tenth value has been
derived for SY002 or O-NOORUS, so **those two images cannot be fully decrypted
with the tables above**, even though they reach ~81% with the nine.

### Invariance laws

```
ks(a) ^ ks(a ^ d)  is constant  for d in {0x880, 0x110000, 0x110880}
```

For `d = 0x880` the constant is one of `{0x88000220, 0x20020088}`, which is
exactly `L(0x880) = 0x88000220` and its byteswap. The law is `L` being linear in
the address, with `e` selecting the orientation.

A full scan of all 32,767 phi-preserving deltas below 2^21 found **exactly
three**. An earlier claim that 0x880 was the only invariant was wrong; that scan
only reached 0xFFFF. `0x110000` links `[0x010000, 0x020000)` to
`[0x100000, 0x110000)`, which is why the worst-covered region of the image jumped
from 50.3% to 99.8% once it was included.

`{0, 0x880, 0x110000, 0x110880}` is closed under XOR, so it forms a group of
order 4 and every address has three partners whose labels are forced equal to
its own. Closure under that group took coverage from 84.49% to 93.94% with zero
intra-orbit conflicts over 296,540 words.

The labels themselves are invariant under those deltas: `(e,s)(a) = (e,s)(a ^
0x880)` held 1750/1750 in two images. That also rules out a stateful generator:
in walk order that single relation is four different signed distances at once
(-544, -480, +480, +544 words), selected by address bits 7 and 11, and a
forward-clocked machine cannot be exactly equal at a distance that depends on
address bits. When a predictor for `s` was fitted by greedy forward selection it
reached 92.4% using `[phi, bits 2-6, 9, 10, 13, 14, 15]` and **never selected
bits 7 or 11** (the two bits of 0x880), confirming the invariance from a
completely different direction.

### Framing

Getting this wrong produces zero hits and looks like the model is broken. It cost
a full re-derivation once.

* Ciphertext word `i` is at offset `4 + 4*i` of the **Code record payload**, read
  **little-endian**. The first 4 payload bytes are the flash base address.
* Flash address `a = record_base + 4*i`; for the SC3's code record the base is 0.
* NDS32 instructions are **big-endian**, so the opcode byte is the *low* byte of
  the little-endian word. Disassemble with `objdump -D -b binary -m n1h -EB`.
* **23 words at flash `0xA4`-`0xFF` are stored unencrypted** in the SC3 image and
  must be passed through verbatim. They are loader header fields: `0xB0` const
  base `0x00135000`, `0xC0` magic `0xB0BEBDC9`, `0xD0` code length `0x134418` in
  its low 24 bits, and the byte at `0xFF` = `0x55` meaning "encrypted"
  (`0xFF` would mean plaintext). Decrypting them corrupts them.

---

## 2. How I broke it

### 2.1 It is a stream cipher

Two independently built images that share a key XOR to a **65,501-byte run of
zeros**. That proves `ct = pt ^ F(key, a)`: no chaining, no data feedback. So
recovering plaintext anywhere hands you the keystream there for free, and the
whole attack reduces to finding plaintext.

I ruled these out along the way, all measured rather than assumed: XOR at every
lag 1 to 4096; additive difference; ECB at 4/8/16/32 bytes; any unaligned
16-byte repeat in 1.2 MB; any keystream period up to 1 MB; GF(2)-affine or
degree-2 dependence on the address; the keystream being determined by a subset
of address bits.

### 2.2 The plaintext was already public

The decisive fact, and it was sitting in the corpus for a long time before it was
noticed:

> **~88 of ~111 collected chip-0xB1 / gen-0x58 firmware images ship completely
> unencrypted**, and they are built from the same MVsilicon SDK as the SC3.

Encryption is a per-vendor build option. Most vendors do not enable it. Byte
entropy of the Code record separates the two cases cleanly: plaintext images sit
at ~7.0-7.2 bits/byte, encrypted ones at 7.998+, which is what
`python -m decrypt info` reports.

Strings later recovered from the SC3 appear verbatim in about 20 of those
images: `CMD7_SELECT_DESELECT_CARD` in 21/88, `USB_DT_INTERFACE` in 20/88,
`jump to sdk` in 67/88. So this is a **known-plaintext attack**, not a two-time
pad, and it needed no purchase, no vendor contact and no hardware.

### 2.3 The ladder

Each rung is gated on ground truth: the SC3's first `0xF0E0` bytes are a
flashboot that also exists as a standalone plaintext file, giving 15,416 words of
independent check. Any step that broke ground truth was rejected.

| step | technique | coverage |
|---|---|---|
| 1 | 2-gram byte-exact drag against the donor corpus | 14.11% |
| 2 | `+` invariance-law propagation | 17.12% |
| 3 | `+` the `g` label (the model fix, see below) | 80.89% |
| 4 | `+` 3-word donor context on two-sided gaps | 81.15% |
| 5 | `+` law-constrained candidates with an ASCII tiebreak | 81.25% |
| 6 | `+` law-constrained candidates with an NDS32 opcode model | 84.49% |
| 7 | `+` `g` as a function of `(e,s)`, `R[9]`, and the two extra laws | **100%** |

**The 2-gram drag.** Build every consecutive-word pair (8 bytes as a uint64)
across all plaintext donors, about 2.7M unique grams. At each SC3 position
enumerate the candidate plaintexts for word `i` and `i+1`, form all pairs, and
binary-search the gram table. An 8-byte hit in a corpus that size is essentially
certainly real.

**The signature trick.** Byte reversal does not change a word's *sorted* bytes.
Matching on sorted-byte signature therefore proves `s` regardless of `e`, which
roughly doubled the yield over byte-exact matching. Do **not** resolve `e` by
assuming the donor's byte order, which silently discards the hits where the two
differ.

**The instruction-plausibility fill.** At an unsolved address whose law partner
is solved, `ks` is known up to the two law values, so there are only 4 candidate
plaintexts instead of 14. Score each with an opcode model learned from donor code
(`log P(b0) + log P(b1|b0)`, where `b0` is the low byte of the little-endian
word and therefore the NDS32 opcode) and accept only when the best beats the
runner-up by a margin. A margin of 3.0 was rejected by the ground-truth gate for
producing 6 wrong words; 6.0 and then 4.5 both held perfectly. This works
*because* the law reduces the field to 4; the same scorer used as a filter across
all candidates is far too weak and would delete correct words.

### 2.4 The `g` label was the whole ceiling

This is the single most important correction I made, and it is worth stating as
a lesson rather than a footnote.

With only `e` and `s` modelled, coverage plateaued at ~17% and a fraction of the
recovered words came out **byte-reversed**: `Openlif re e!ror` for
`OpenFile error!`, `ecivres` for `service`. I blamed the reversals on the `e`
bit, on the donor corpus, and on three separate augmentation techniques, and I
rejected all three of those for "injecting byte-reversed words".

The cause was a missing third label. Adding the outer `bswap^g` (one change to
the candidate generator) took coverage from 14.11% to 80.89% in a single run,
and the text came out clean for the first time. Re-running the three "harmful"
augmentations under the corrected model showed they added +16 words and broke
nothing; they had always been fine.

Evidence for `g`, which I gathered independently before accepting it:

* Extending to four combinations explained 111 of 112 words in the firmware's own
  name table.
* `g = 1` for 66.9% of 168,012 ground-truth words, flat across every 64 KB region
  (0.650-0.678), with no correlation to `phi` and none to any address bit
  (mutual information < 0.006).
* Against a sibling image over 315,654 overlapping words: 5,244 positions where
  the sibling's value is model-admissible against **10,815** where only its byte
  reversal is. Chance expectation for that ratio is 0.0013.
* A self-contained proof needing no sibling: flash `0xD4628` is a fully-proven
  contiguous ASCII run that reads correctly only with `0xD4640` reversed, and
  `0x00BDA8` and `0x00BDC8` hold the same word in opposite orientations.

**The generalisable lesson:** the forward-vs-reversed token count was the right
instrument and it correctly flagged that something was wrong. The mistake was
attributing the symptom to the techniques being tested rather than to the model
they were being tested under.

### 2.5 Validation

Against `fb.bin`, the standalone plaintext flashboot that is byte-for-byte the
SC3's first `0xF0E0` bytes:

```
15,411 / 15,416 words correct
```

**Zero decrypted words disagree with the donor.** All five differences sit at
`0xB0`, `0xBC`, `0xCC`, `0xD0` and `0xFC`, inside the stored-plaintext window
`0xA4`-`0xFF`, so they are carried through verbatim and are not decrypt output at
all. They are header fields that genuinely differ between the two images: `0xB0`
= `0x00135000` (the SC3's own const base), `0xD0` = the SC3's code length, `0xFC`
= the `0x55` encrypted flag (the standalone flashboot is not encrypted), plus the
header CRC at `0xBC` and `0xCC`, which move with them. The first three were
independently confirmed before the decrypt existed.

Quality gate on the finished image: 309 forward tokens, **0 reversed**.

One caveat stated plainly: the flashboot also appears in the donor corpus, so
this measures consistency more than fully independent ground truth. It is,
however, the cleanest available demonstration, and the old-model-versus-new-model
comparison is unaffected because both were scored identically (the 18-candidate
model scored 3,085/3,143 = 98.15% over the same range, i.e. 58 wrong words).

---

## 3. The key schedule

### What is established

The two known `R` tables for chip 0xB1 differ by **one 32-bit constant**:

```
R_SY002[j] = R_SC3[i] ^ d            for 6 of 9 words,  d = 0x8192C4DC
R_SY002[j] = R_SC3[i] ^ bswap(d)     for the other 3
```

a complete 9-of-9 bijection, every index on both sides used exactly once. So

```
R[k] = BASE[k] ^ bswap^h(k)( D(key) )
```

with `BASE` key-independent and `D(key)` a single 32-bit value. The 288-bit `R`
table therefore carries only ~32 bits of key, matching the vendor's documented
32-bit key.

Independent support:

* Null control, 3000 random 9-word set-pairs: best pair count 2, best coverage
  1/9. The observed 6 pairs / 9-of-9 is far outside that.
* GF(2) rank of each `R` table is 8/9, of the union 10/18. Two thousand random
  9-sets gave rank 9 in 2000/2000. One shared `d` would cap union rank at 9; `d`
  plus `bswap(d)` caps it at 10. The measured rank is 10, the same structure
  computed two independent ways, agreeing exactly.
* A **third** key was later found (O-NOORUS D4). Its delta to the SC3 is
  `0x79666A7E` (×6, plus its byteswap ×3) and to SY002 `0xF8F4AEA2` (same 6/3
  split), and the triangle closes **exactly**:
  `0x79666A7E ^ 0xF8F4AEA2 = 0x8192C4DC`, the SC3↔SY002 delta measured long
  before that file existed. One `BASE` explains all three tables with a unique
  three-way slot correspondence.

### What is NOT established

* **`BASE` is unknown and cannot be pinned by more keys alone.** There is exactly
  32 bits of gauge freedom: shifting every `D` by a constant `c` and compensating
  `BASE[k] -> BASE[k] ^ bswap^h(k)(c)` leaves every `R` unchanged. A third key
  fixes the structure, not the gauge.
* **The SC3's key is not known.** Synido's SY002 declares its key in the firmware
  *filename* (`KEY A1-B2-C3-D4` = `0xA1B2C3D4`), and that one is solid. If and
  only if `D` were the identity, the SC3's key would follow as `0x20200708`,
  which is
  suggestively low-weight and reads as a date. **That is a conjecture, not a
  result.** Testing `D` in {identity, bswap, complement, all 31 rotations}
  produced scores indistinguishable from a null of 200 random deltas, and the
  implied O-NOORUS key under the same assumption looks like noise. Nothing here
  depends on knowing any key.
* **Do not cite the chip-0x4F family as confirming this model.** Two
  constant-plus-byteswap keystream differences were found there, and it was
  initially written up as independent confirmation. That was an over-read: such a
  difference follows from *any* cipher of the form `ks(a) = F(a) ^ G(key)` with a
  per-address byteswap, and does not evidence a nine-value `R` indexed by `s(a)`.
  The chip-0xB1 evidence stands on its own; the chip-0x4F evidence does not add
  to it.

### Where the key lives

MVsilicon's own encryption documentation states it directly: a user-supplied
**32-bit key**, burned into an on-chip **one-time-fuse key store that cannot be
read**, loaded into a hardware decrypt module at power-up, with instructions
descrambled on the fetch path and no user control over the process. The
encryption side runs on a USB dongle that the vendor sells separately; the key
programmer is a third, separate tool.

Consequences that shaped this project:

* The key cannot be extracted from hardware, even with the case open and a debug
  port attached.
* Dumping the SPI flash yields the same ciphertext that is already in the `.MVA`.
  Plaintext exists only in icache/SRAM.
* Writing plaintext code to a chip whose key is already fused would be
  descrambled into garbage on fetch. The flash byte at `0xFF` (`0x55` encrypted /
  `0xFF` plaintext) is a tooling convention that the SDK *reports* and the
  flashboot *validates*; nothing indicates it disables the hardware descrambler.
  That is the leading conclusion and it rests on strong evidence (the vendor
  documentation plus the bootloader never configuring the descrambler), but the
  documentation never mentions the flag, so it is not proof.

**None of that matters for patching**, because a patch re-encrypts under the
already-known keystream rather than needing the key. See [patch.md](patch.md).

---

## 4. Reproducing a decrypt

```sh
python -m decrypt info      FIRMWARE.MVA     # identify, classify, check CRC
python -m decrypt decrypt   FIRMWARE.MVA -o plain.bin
python -m decrypt verify    FIRMWARE.MVA     # decrypt -> re-encrypt -> diff
python -m decrypt selftest                   # no firmware needed
```

`verify` is the honest check: it decrypts the whole Code record, re-encrypts it,
and confirms the container comes back byte-identical.

### Decrypting an image that is not the SC3 V22

You would need two things this repository does not ship:

1. **That image's `R` table.** Derive it from exposed keystream: flash regions
   whose plaintext is architecturally zero, such as the zero pad, where
   `ks = ct` directly. Then `R = bswap^e(ks) ^ L(a) ^ C[phi(a)]`, tallied over
   many addresses; the true values recur sharply. On the O-NOORUS image the top 9
   values explained 886 of 888 addresses, with the 9th at 23 hits and the 10th at
   2.
2. **That image's label solve**, which needs a corpus of unencrypted siblings.
   The primitives are here (`cipher.candidates`, `cipher.law_partners`,
   `cipher.check_law_0x880`); the corpus is not.

A blind `R` recovery without any key is also feasible: for each sampled address
and each high-frequency donor word, compute the implied `R` for each `(g, e)` and
tally. Validated on the SC3 with `R` known: from 1,200 sampled addresses and the
top 20,000 donor words, 5 of the 9 true values appeared in the top 12. Rank by
**distinct contributing addresses**, not raw hit count, because clustered donor
vocabulary otherwise surfaces near-variants of a strong value. And build the
tally in numpy; a Python loop over the candidate array is ~1e9 iterations and
will not finish.

---

## 5. Negative results worth not re-walking

* **No software implementation of the cipher exists to steal.** The PC flash tool
  copies the image verbatim (`rep movsb`, no cipher); it imports `fopen`/`fread`
  and no crypto API, and its only constant tables are CRC. `driver.lib` has zero
  crypto symbols. The Keil flash algorithm has none either.
* **The `R` words do not lie on a PRNG orbit.** 39 step functions (xorshift32,
  LCG/MCG, Galois and Fibonacci LFSRs, splitmix32, rotate/multiply variants) to
  depth 300: no orbit contains even 3 of the 9. No `R` word is the XOR of two
  others; none is in `C`.
* **The keystream bias is real but key-specific.** Per-lane chi-squared 1656-3523
  against ~255 for random, but the correlation between two images sharing a key
  is +0.72 to +0.87 while across keys it is +0.19 to -0.46, and sign agreement
  across keys is 15/32 bits, which is chance. It is not a property of `F` and not
  a route to it.
* **The header CRC at flash 0xBC is not a standard byte-wise CRC16.** All 65,536
  polynomials × 2 reflections × 9 masks × 2 byte orders were tried.
* **Berlekamp-Massey does not retire the LFSR class.** A linear complexity of N/2
  means "indistinguishable from random", not "maximal"; and BM has zero error
  tolerance, so one wrong bit in 24,576 takes the measured complexity from 64 to
  13,993. I read it as a decisive elimination once, off the back of a
  transcription error.
* **A brute-force over the 32-bit key was never the obstacle.** Not knowing `F`
  was. Once `F` is known the key is not needed at all.
