# Label tables

`e(a)` and `s(a)` have no closed form. They were solved one address at a time by
the known-plaintext attack in [../../docs/cipher.md](../../docs/cipher.md), and
the result is stored here: one label byte per code word.

| file | image | words |
|---|---|---|
| `sc3_v22.labels.gz` | FIFINE SC3 firmware V22 (`HJ_SK_E08_20230421_V22_0x0209_189.MVA`) | 315,631 solved + 23 stored-plaintext |

**These files contain no firmware.** They hold no plaintext and no ciphertext,
only cipher labels, which are useful solely in combination with a ciphertext
image you already have. Functionally they are a key, not a copy of the work.

Each table is bound to the SHA-256 of the code record it was solved for, so it
cannot silently be applied to the wrong image. `python -m decrypt decrypt
--force` relaxes that to a word-count check, which is what you want for an image
you derived yourself (a patched build has a different hash but the same
per-address labels).

Format is documented in [`../labels.py`](../labels.py).
