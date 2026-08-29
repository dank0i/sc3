#!/usr/bin/env python3
"""Build the four-fader firmware patch from a stock SC3 V22 .MVA.

    python patch/build_fader_patch.py STOCK.MVA -o SC3_V22_FADERS.MVA
    python patch/build_fader_patch.py --check ANY.MVA

You supply the stock firmware; nothing is bundled here.  The build is
deterministic: given the same input it produces a byte-identical output.

WHAT IT DOES, IN ORDER
  1. parse the container and confirm the code record is the image the shipped
     label table was solved for (SHA-256), refusing anything else
  2. decrypt the code record
  3. confirm the bytes about to be overwritten are the ones expected
  4. apply the plaintext edits
  5. re-encrypt under the same keystream
  6. rebuild the container and recompute the CRC16 trailer
  7. verify: the patched region decrypts back to exactly what was intended, and
     every other ciphertext word is byte-identical to the original

READ docs/patch.md BEFORE FLASHING ANYTHING.  Flashing this required erasing all
flash, which is only survivable because of a specific property of this file.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from decrypt import cipher, container, image, labels  # noqa: E402
import fader_patch as spec  # noqa: E402


def die(msg):
    sys.exit(f"error: {msg}")


def load_mva(path):
    try:
        return container.load(path)
    except FileNotFoundError:
        die(f"no such file: {path}")
    except OSError as exc:
        die(f"cannot read {path}: {exc}")
    except container.MvaError as exc:
        die(f"{path} is not a usable MVA container: {exc}")


def decrypt(mva, force=False):
    try:
        table, exact = image.resolve_table(mva, force=force)
        code = mva.record(container.TYPE_CODE)
        plain, stats = image.decrypt_code(code.payload, table)
    except (image.DecryptError, container.MvaError, labels.LabelError) as exc:
        die(str(exc))
    return code, table, plain, stats, exact


def edits(with_version_bump: bool):
    out = dict(spec.PATCH_EDITS)
    if with_version_bump:
        out[spec.VERSION_BYTE_ADDR] = bytes([spec.VERSION_BYTE_PATCHED])
    return out


def cmd_check(path):
    mva = load_mva(path)
    print(f"{path}")
    print(f"  chip {mva.chip:#04x} gen {mva.generation:#04x}, "
          f"CRC {mva.stored_crc:#06x} {'OK' if mva.crc_ok else 'MISMATCH'}")
    # A patched image has a different code-record hash, so --check has to accept
    # a table that was solved for the stock build it was derived from.
    code, table, plain, _, exact = decrypt(mva, force=True)
    print(f"  label table: {table.name}"
          f"{'' if exact else '   (assumed - this image is not the one it was solved for)'}")

    patched = clean = other = 0
    for addr, want in spec.PATCH_EDITS.items():
        have = plain[addr : addr + len(want)]
        if have == want:
            patched += 1
        elif have == spec.EXPECTED_ORIGINAL[addr]:
            clean += 1
        else:
            other += 1
            print(f"  {addr:#08x}: unrecognised\n"
                  f"      have {have.hex(' ')}")
    if other:
        print("  VERDICT: neither stock nor this patch. Do not flash it.")
        return 1
    if patched == len(spec.PATCH_EDITS):
        print("  VERDICT: the four-fader patch is present")
    elif clean == len(spec.PATCH_EDITS):
        print("  VERDICT: stock 0xFC stub, not patched")
    else:
        print("  VERDICT: partially patched - do not flash it")
        return 1

    vb = plain[spec.VERSION_BYTE_ADDR]
    ct, _ = image.code_words(code.payload)
    tcv = ct[spec.TEMP_CODEVERSION_ADDR // 4]
    print(f"  version byte at {spec.VERSION_BYTE_ADDR:#08x}: {vb:#04x} "
          f"({'bumped' if vb == spec.VERSION_BYTE_PATCHED else 'stock'})")
    print(f"  temp_codeversion (ciphertext u32 at {spec.TEMP_CODEVERSION_ADDR:#08x}): {tcv:#010x}")
    return 0


def refuse_if_same_file(out, src):
    """Exit if the output would overwrite the source image.

    This is the builder the README and docs/patch.md point people at, so the
    guard matters here more than anywhere. `Path.resolve()` on its own is not
    enough: it does not case-fold, so on macOS and Windows `-o stock.MVA`
    against `Stock.MVA` slips past it. `samefile` compares st_dev/st_ino and
    catches that, plus hard links and symlinks.
    """
    out_p, src_p = Path(out), Path(src)
    try:
        same = out_p.exists() and out_p.samefile(src_p)
    except OSError:
        same = False
    if same or out_p.resolve() == src_p.resolve():
        die("--output is the input image. That is your only rollback if a "
            "flash goes wrong; refusing to overwrite it.")


def cmd_build(args):
    refuse_if_same_file(args.output or "SC3_V22_FADERS.MVA", args.mva)
    mva = load_mva(args.mva)
    if not mva.crc_ok:
        die(f"input CRC16 is {mva.stored_crc:#06x} but the file computes "
            f"{mva.computed_crc:#06x}; this file is damaged")
    code, table, plain, stats, exact = decrypt(mva, force=True)
    if not exact:
        if all(plain[a:a + len(v)] == v for a, v in spec.PATCH_EDITS.items()):
            die("this image already carries the four-fader patch. "
                "Build from the stock V22 image instead.")
        die("no label table matches this image's code record.\n"
            "  e(a) and s(a) have no closed form; a new image needs its own\n"
            "  label solve and its own R table. See docs/cipher.md.")
    print(f"input : {args.mva}")
    print(f"  label table {table.name}")
    print(f"  {stats['solved']} words decrypted, {stats['passthrough']} stored-plaintext, "
          f"{stats['unsolved']} unsolved")

    # 3. refuse anything that is not the exact stock code we expect.
    for addr, want in spec.EXPECTED_ORIGINAL.items():
        have = plain[addr : addr + len(want)]
        if have == spec.PATCH_EDITS[addr]:
            die(f"{addr:#08x} already holds the patch; this image is already patched")
        if have != want:
            die(f"{addr:#08x} does not hold the expected stock bytes\n"
                f"  expected {want.hex(' ')}\n"
                f"  found    {have.hex(' ')}\n"
                "  refusing to patch an image this script does not recognise")
    if plain[spec.VERSION_BYTE_ADDR] != spec.VERSION_BYTE_ORIGINAL:
        die(f"version byte at {spec.VERSION_BYTE_ADDR:#08x} is "
            f"{plain[spec.VERSION_BYTE_ADDR]:#04x}, expected "
            f"{spec.VERSION_BYTE_ORIGINAL:#04x}")

    # 4. apply.
    patched_plain = bytearray(plain)
    todo = edits(not args.no_version_bump)
    for addr, data in sorted(todo.items()):
        patched_plain[addr : addr + len(data)] = data
        print(f"  patch {addr:#08x}  {len(data):>2} bytes  {data.hex(' ')}")

    # 5, 6. re-encrypt and rebuild.
    new_payload = image.encrypt_code(bytes(patched_plain), code.payload, table)
    out_raw = container.rebuild(mva, {container.TYPE_CODE: new_payload})

    # 7. verify.
    ok = verify(mva, code, table, out_raw, bytes(patched_plain), todo)
    if not ok:
        die("verification failed; nothing was written")

    if args.dry_run:
        print("\ndry run: no file written")
        return
    out = args.output or "SC3_V22_FADERS.MVA"
    try:
        with open(out, "wb") as fh:
            fh.write(out_raw)
    except OSError as exc:
        die(f"cannot write {out}: {exc}")
    print(f"\nwrote {len(out_raw)} bytes to {out}")
    print("READ docs/patch.md BEFORE FLASHING.")


def verify(mva, code, table, out_raw, want_plain, todo):
    print("\nverification")
    ok = True

    new = container.parse(out_raw)
    new_code = new.record(container.TYPE_CODE)

    back, _ = image.decrypt_code(new_code.payload, table)
    same_plain = back == want_plain
    print(f"  {'PASS' if same_plain else 'FAIL'}  re-encrypted image decrypts back "
          "to exactly the intended plaintext")
    ok &= same_plain

    for addr, data in sorted(todo.items()):
        got = back[addr : addr + len(data)]
        good = got == data
        print(f"  {'PASS' if good else 'FAIL'}  {addr:#08x} reads back as intended")
        ok &= good

    old_ct, n = image.code_words(code.payload)
    new_ct, _ = image.code_words(new_code.payload)
    changed = [i for i in range(n) if old_ct[i] != new_ct[i]]
    touched = set()
    for addr, data in todo.items():
        for off in range(len(data)):
            touched.add((addr + off) // 4)
    inside = all(i in touched for i in changed)
    print(f"  {'PASS' if inside else 'FAIL'}  {len(changed)} ciphertext words changed, "
          f"all inside the patched region")
    print(f"        {n - len(changed)} of {n} words left byte-identical")
    ok &= inside

    expected_n = spec.EXPECTED_CIPHERTEXT_WORDS_CHANGED
    if len(todo) == len(spec.PATCH_EDITS) + 1:
        match = len(changed) == expected_n
        print(f"  {'PASS' if match else 'note'}  changed-word count {len(changed)} "
              f"(reference build: {expected_n})")

    crc_ok = new.crc_ok
    print(f"  {'PASS' if crc_ok else 'FAIL'}  CRC16 trailer recomputed: "
          f"{new.stored_crc:#06x} (was {mva.stored_crc:#06x})")
    ok &= crc_ok

    diff = sum(1 for a, b in zip(mva.raw, out_raw) if a != b)
    print(f"  info  {diff} bytes differ from the input, out of {len(out_raw)}")
    return ok


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("mva", help="stock SC3 V22 .MVA (or any .MVA with --check)")
    p.add_argument("-o", "--output")
    p.add_argument("--check", action="store_true",
                   help="report whether an image is stock or patched, and change nothing")
    p.add_argument("--no-version-bump", action="store_true",
                   help="skip the temp_codeversion byte; see docs/patch.md")
    p.add_argument("--dry-run", action="store_true",
                   help="build and verify but write nothing")
    args = p.parse_args()
    if args.check:
        sys.exit(cmd_check(args.mva))
    cmd_build(args)


if __name__ == "__main__":
    main()
