"""Whole-image decryption and re-encryption, tying cipher + container + labels together."""

from __future__ import annotations

import struct

from . import cipher, labels as labels_mod
from .container import Mva, MvaError, TYPE_CODE


class DecryptError(Exception):
    pass


def code_words(payload: bytes):
    """Ciphertext words of a Code record payload, little-endian.

    The first 4 payload bytes are the flash base address, not code, so word `i`
    starts at payload offset `4 + 4*i` and lives at flash address `4*i` (for a
    record based at 0).
    """
    n = (len(payload) - 4) // 4
    return list(struct.unpack_from("<%dI" % n, payload, 4)), n


def decrypt_code(payload: bytes, table, R=cipher.R_SC3, strict: bool = True):
    """Decrypt a Code record payload.

    Returns ``(plaintext_bytes, stats)``.  ``plaintext_bytes`` is the flash image
    starting at the record's base address, so flash address A is at offset A.

    Unsolved words become zero when ``strict`` is False, and raise otherwise.
    """
    ct, n = code_words(payload)
    if len(table) != n:
        raise DecryptError(
            f"label table covers {len(table)} words but this record has {n}"
        )
    out = [0] * n
    solved = passthrough = unsolved = 0
    for i in range(n):
        b = table.labels[i]
        if b == labels_mod.PLAINTEXT:
            out[i] = ct[i]
            passthrough += 1
            continue
        if b == labels_mod.UNSOLVED:
            if strict:
                raise DecryptError(
                    f"word {i} (flash {4*i:#x}) has no label; pass strict=False to zero it"
                )
            unsolved += 1
            continue
        e, s = table.es_table[b]
        out[i] = cipher.decrypt_word(ct[i], 4 * i, e, s, R)
        solved += 1
    stats = {"words": n, "solved": solved, "passthrough": passthrough, "unsolved": unsolved}
    return struct.pack("<%dI" % n, *out), stats


def encrypt_code(plain: bytes, payload: bytes, table, R=cipher.R_SC3) -> bytes:
    """Re-encrypt a plaintext flash image back into a Code record payload.

    ``payload`` is the original record payload; its 4-byte base address and any
    trailing bytes past the last whole word are preserved verbatim.  Unsolved
    words keep their ORIGINAL ciphertext rather than being invented, so a
    partially-solved table still round-trips cleanly outside the words it can
    account for.
    """
    ct, n = code_words(payload)
    if len(plain) != 4 * n:
        raise DecryptError(f"plaintext is {len(plain)} bytes, expected {4*n}")
    pt = struct.unpack("<%dI" % n, plain)
    out = list(ct)
    for i in range(n):
        b = table.labels[i]
        if b == labels_mod.PLAINTEXT:
            out[i] = pt[i]
        elif b != labels_mod.UNSOLVED:
            e, s = table.es_table[b]
            out[i] = cipher.encrypt_word(pt[i], 4 * i, e, s, R)
    return payload[:4] + struct.pack("<%dI" % n, *out) + payload[4 + 4 * n :]


def resolve_table(mva: Mva, explicit=None, force: bool = False):
    """Pick a label table for this image, or explain why none applies.

    A table is bound to the SHA-256 of the code record it was solved for, so it
    cannot silently be applied to the wrong image.  ``force`` relaxes that to a
    word-count check, which is what you want for an image you patched yourself:
    the labels are per-ADDRESS, so they still hold after the ciphertext changes.
    Applying a forced table to an unrelated image produces garbage.

    Returns ``(table, exact)``.
    """
    try:
        code = mva.record(TYPE_CODE)
    except MvaError as exc:
        raise DecryptError(str(exc)) from exc

    if explicit is not None:
        table = labels_mod.load(explicit)
        if table.matches(code.payload):
            return table, True
        if not force:
            raise DecryptError(
                f"label table {explicit} was solved for a different image "
                "(SHA-256 of the code record does not match). Pass force=True "
                "if this image is a derivative you built yourself."
            )
        _check_size(table, code.payload, explicit)
        return table, False

    table = labels_mod.find_for(code.payload)
    if table is not None:
        return table, True

    if force:
        n = (len(code.payload) - 4) // 4
        for path in labels_mod.available():
            candidate = labels_mod.load(path)
            if len(candidate) == n:
                return candidate, False

    raise DecryptError(
        "no label table matches this image's code record.\n"
        "  e(a) and s(a) have no closed form; a new image needs its own\n"
        "  label solve and its own R table. See docs/cipher.md."
    )


def _check_size(table, payload, where):
    n = (len(payload) - 4) // 4
    if len(table) != n:
        raise DecryptError(
            f"label table {where} covers {len(table)} words but this code "
            f"record has {n}; they are not the same image family"
        )
