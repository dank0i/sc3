"""Command line interface: ``python -m decrypt <command> ...``"""

from __future__ import annotations

import argparse
import hashlib
import math
import sys
from collections import Counter
from pathlib import Path

from . import cipher, container, image, labels


def _load(path):
    try:
        return container.load(path)
    except FileNotFoundError:
        sys.exit(f"error: no such file: {path}")
    except IsADirectoryError:
        sys.exit(f"error: {path} is a directory")
    except OSError as exc:
        sys.exit(f"error: cannot read {path}: {exc}")
    except container.MvaError as exc:
        sys.exit(f"error: {path} is not a usable MVA container: {exc}")


def _refuse_if_same_file(out, src, what="the input"):
    """Exit if `out` and `src` are the same file.

    `Path.resolve()` alone is not enough and the difference is not academic:
    it does not case-fold, so on macOS and Windows, the two platforms this runs
    on, `-o stock.MVA` against `Stock.MVA` sailed straight past it and
    overwrote the source. `samefile` compares st_dev/st_ino, so it also catches
    hard links and symlinks. Keep both checks: samefile needs the target to
    exist, resolve() covers the case where it does not yet.
    """
    out_p, src_p = Path(out), Path(src)
    try:
        same = out_p.exists() and out_p.samefile(src_p)
    except OSError:
        same = False
    if same or out_p.resolve() == src_p.resolve():
        sys.exit(
            f"error: --output is {what}. Refusing to overwrite it; "
            "for a patch build that is your only rollback if a flash goes wrong."
        )


def _write(path, data, what):
    try:
        Path(path).write_bytes(data)
    except OSError as exc:
        sys.exit(f"error: cannot write {path}: {exc}")
    print(f"wrote {len(data)} bytes of {what} to {path}")


# --------------------------------------------------------------------------


def cmd_info(args):
    mva = _load(args.mva)
    raw = mva.raw
    print(f"{args.mva}")
    print(f"  size        {len(raw)} bytes")
    print(f"  sha256      {hashlib.sha256(raw).hexdigest()}")
    print(f"  chip        {mva.chip:#04x}")
    print(f"  generation  {mva.generation:#04x}")
    print(f"  records     {len(mva.records)}")
    print()
    print(f"  {'type':>4}  {'name':<13} {'length':>9}  {'flash base':>10}  {'entropy':>7}")
    for rec in mva.records:
        base = rec.flash_base
        base_s = f"{base:#010x}" if base is not None else "-"
        ent = byte_entropy(rec.payload)
        note = ""
        if rec.type == container.TYPE_CODE:
            note = "  encrypted" if ent > 7.9 else "  plaintext"
        print(
            f"  {rec.type:>4}  {rec.type_name:<13} {len(rec.payload):>9}  {base_s:>10}"
            f"  {ent:>7.3f}{note}"
        )
    print()
    stored, computed = mva.stored_crc, mva.computed_crc
    print(f"  CRC16-CCITT stored {stored:#06x}  computed {computed:#06x}  "
          f"{'OK' if stored == computed else 'MISMATCH'}")

    if mva.has(container.TYPE_CODE):
        code = mva.record(container.TYPE_CODE)
        table = labels.find_for(code.payload)
        if table is None:
            print("  labels      none shipped for this code record")
        else:
            print(f"  labels      {table.name}")
            print(f"              {table.solved} solved, {table.passthrough} stored-plaintext, "
                  f"{table.unsolved} unsolved of {len(table)} words")

    if mva.has(container.TYPE_CONST):
        try:
            res = container.parse_mvub(mva.record(container.TYPE_CONST).body)
            print(f"  const       MVUB filesystem, {len(res)} resources")
        except container.MvaError as exc:
            print(f"  const       not an MVUB filesystem ({exc})")


def cmd_crc(args):
    mva = _load(args.mva)
    stored, computed = mva.stored_crc, mva.computed_crc
    print(f"stored   {stored:#06x}")
    print(f"computed {computed:#06x}   (CRC16-CCITT, poly 0x1021, MSB-first, init 0, no final XOR)")
    if stored != computed:
        sys.exit("CRC MISMATCH")
    print("OK")


def cmd_extract(args):
    mva = _load(args.mva)
    try:
        rec = mva.record(args.type)
    except container.MvaError as exc:
        sys.exit(f"error: {exc}")
    data = rec.body if args.strip_base else rec.payload
    out = args.output or f"record{args.type}_{rec.type_name}.bin"
    _refuse_if_same_file(out, args.mva, "the input firmware")
    _write(out, data, f"record type {args.type} ({rec.type_name})")


def cmd_resources(args):
    mva = _load(args.mva)
    try:
        body = mva.record(container.TYPE_CONST).body
        res = container.parse_mvub(body)
    except container.MvaError as exc:
        sys.exit(f"error: {exc}")

    if not args.output:
        print(f"{len(res)} resources in the Const record")
        print(f"  {'#':>3}  {'name':<10} {'offset':>10} {'size':>9}  first bytes")
        for i, r in enumerate(res):
            head = container.read_resource(body, r)[:4].hex(" ")
            print(f"  {i:>3}  {r.name:<10} {r.offset:#010x} {r.size:>9}  {head}")
        print("\npass -o DIR to write them out")
        return

    outdir = Path(args.output)
    try:
        outdir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        sys.exit(f"error: cannot create {outdir}: {exc}")
    for r in res:
        blob = container.read_resource(body, r)
        # Every SC3 resource is an MPEG frame stream; keep any others as .bin.
        # The layer is in the header's layer bits, and only ff fd is Layer II.
        # The SC3's own resources are all ff fd. ff fb and ff f3 are Layer III,
        # so lumping them in as .mp2 would be a worse label than .mp3, not a
        # better one.
        if blob[:2] == b"\xff\xfd":
            ext = ".mp2"
        elif blob[:2] in (b"\xff\xfb", b"\xff\xf3"):
            ext = ".mp3"
        else:
            ext = ".bin"
        (outdir / f"{r.name}{ext}").write_bytes(blob)
    print(f"wrote {len(res)} resources to {outdir}")


def cmd_decrypt(args):
    mva = _load(args.mva)
    try:
        table, exact = image.resolve_table(mva, args.labels, force=args.force)
        code = mva.record(container.TYPE_CODE)
        plain, stats = image.decrypt_code(
            code.payload, table, cipher.R_TABLES[args.r], strict=not args.allow_unsolved
        )
    except (image.DecryptError, container.MvaError) as exc:
        sys.exit(f"error: {exc}")
    except labels.LabelError as exc:
        sys.exit(f"error: label table: {exc}")
    except ValueError as exc:
        sys.exit(f"error: {exc}")
    except OSError as exc:
        sys.exit(f"error: {exc}")
    except ValueError as exc:
        sys.exit(f"error: {exc}")
    except OSError as exc:
        sys.exit(f"error: {exc}")

    print(f"label table: {table.name}{'' if exact else '   (FORCED - not this image)'}")
    if not exact:
        print("  WARNING: the label table was solved for a different code record.")
        print("  That is fine for an image you derived from it, and garbage otherwise.")
    print(f"  {stats['solved']} decrypted, {stats['passthrough']} stored-plaintext, "
          f"{stats['unsolved']} unsolved of {stats['words']} words")
    base = code.flash_base or 0
    print(f"  output is the flash image based at {base:#010x}")
    out = args.output or "code_plain.bin"
    _refuse_if_same_file(out, args.mva, "the input firmware")
    _write(out, plain, "plaintext")


def _parse_hex(text, what):
    """Parse a hex byte string, tolerating spaces and a 0x prefix."""
    cleaned = text.replace(" ", "").replace("_", "")
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    if not cleaned or len(cleaned) % 2:
        sys.exit(f"error: {what}: {text!r} is not a whole number of hex bytes")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        sys.exit(f"error: {what}: {text!r} is not hex")


def _parse_edit(text):
    """`ADDR:EXPECT:NEW` -> (addr, expect, new).

    EXPECT is not optional. It is the guard that stops a patch written for one
    build being applied to another, which is the single easiest way to brick a
    device with this tool.
    """
    parts = text.split(":")
    if len(parts) != 3:
        sys.exit(
            f"error: --edit {text!r} must be ADDR:EXPECT:NEW, for example\n"
            "  --edit 0x1ECA6:8006ae75:d5108000"
        )
    addr_text, expect_text, new_text = parts
    try:
        addr = int(addr_text, 0)
    except ValueError:
        sys.exit(f"error: --edit: {addr_text!r} is not an address")
    if addr < 0:
        sys.exit("error: --edit: address cannot be negative")
    expect = _parse_hex(expect_text, f"--edit {addr_text} EXPECT")
    new = _parse_hex(new_text, f"--edit {addr_text} NEW")
    if len(expect) != len(new):
        sys.exit(
            f"error: --edit {addr_text}: EXPECT is {len(expect)} bytes but NEW is "
            f"{len(new)}.\n"
            "  Patches must be length-neutral. Growing or shrinking code shifts\n"
            "  every branch target after it, and nothing here relinks. Pad the\n"
            "  replacement with no-ops instead."
        )
    return addr, expect, new


def cmd_patch(args):
    """Apply length-neutral edits to the decrypted code, then rebuild the .MVA.

    This is the generic form of what `patch/build_fader_patch.py` does for one
    specific patch. Everything it writes is verified before it reaches disk.
    """
    edits = [_parse_edit(e) for e in args.edit]
    if not edits:
        sys.exit("error: nothing to do; pass at least one --edit")

    # Overlapping edits would make the result depend on application order.
    spans = sorted((a, a + len(n)) for a, _, n in edits)
    for (a0, a1), (b0, _) in zip(spans, spans[1:]):
        if b0 < a1:
            sys.exit(
                f"error: edits overlap at {b0:#08x} (previous ends {a1:#08x}); "
                "merge them into one --edit"
            )

    # The input is the rollback image this documentation tells you to keep.
    # Writing over it removes the only recovery path, and it WOULD succeed
    # quietly because the output is already in memory by then.
    _refuse_if_same_file(args.output, args.mva, "the input firmware")

    mva = _load(args.mva)
    if not mva.crc_ok:
        sys.exit(
            f"error: input CRC16 is {mva.stored_crc:#06x} but the file computes "
            f"{mva.computed_crc:#06x}; this file is damaged, refusing to build from it"
        )
    try:
        table, exact = image.resolve_table(mva, args.labels, force=args.force)
        code = mva.record(container.TYPE_CODE)
        # strict=False so the unsolved-word check below is reachable. With the
        # default, decrypt_code raises first and the caller gets a generic
        # "pass strict=False to zero it" instead of the reason that matters here.
        plain, stats = image.decrypt_code(
            code.payload, table, cipher.R_TABLES[args.r], strict=False
        )
    except (image.DecryptError, container.MvaError) as exc:
        sys.exit(f"error: {exc}")
    except labels.LabelError as exc:
        sys.exit(f"error: label table: {exc}")
    except ValueError as exc:
        sys.exit(f"error: {exc}")
    except OSError as exc:
        sys.exit(f"error: {exc}")

    print(f"input : {args.mva}")
    print(f"  label table {table.name}{'' if exact else '   (FORCED)'}")
    if not exact:
        print("  WARNING: these labels were solved for a different code record.")
        print("  Correct for an image you derived from that one, garbage otherwise.")
    if stats["unsolved"]:
        sys.exit(
            f"error: {stats['unsolved']} words are unsolved. Re-encrypting an image\n"
            "  that did not fully decrypt would write garbage to the device."
        )

    # Refuse anything that is not exactly the code the caller says they expect.
    for addr, expect, new in edits:
        end = addr + len(expect)
        if end > len(plain):
            sys.exit(
                f"error: {addr:#08x}+{len(expect)} is past the end of the "
                f"{len(plain)}-byte image"
            )
        have = plain[addr:end]
        if have == new:
            sys.exit(f"error: {addr:#08x} already holds the replacement; already patched?")
        if have != expect:
            sys.exit(
                f"error: {addr:#08x} does not hold the expected bytes\n"
                f"  expected {expect.hex(' ')}\n"
                f"  found    {have.hex(' ')}\n"
                "  Refusing to patch an image this edit was not written for."
            )

    patched = bytearray(plain)
    for addr, _, new in edits:
        patched[addr:addr + len(new)] = new
        print(f"  patch {addr:#08x}  {len(new):>3} bytes  {new.hex(' ')}")
        # The header windows carry a CRC16 that nothing here can recompute, and
        # are stored unencrypted. Landing in one is occasionally intended (the
        # fader patch bumps the version byte at 0x0100BB) but is never routine.
        for lo, hi, what, plain in ((0xA4, 0xFF, "flashboot", True),
                                    (0x0100A4, 0x0100FF, "application", False)):
            if addr <= hi and addr + len(new) > lo:
                extra = ", and is stored unencrypted" if plain else ""
                print(
                    f"  WARNING  {addr:#08x} is in the {what} header window "
                    f"({lo:#08x}-{hi:#08x}). That window holds a CRC16 this tool "
                    f"cannot recompute{extra}. See docs/patch.md."
                )

    try:
        new_payload = image.encrypt_code(bytes(patched), code.payload, table,
                                         cipher.R_TABLES[args.r])
        out_raw = container.rebuild(mva, {container.TYPE_CODE: new_payload})
    except (image.DecryptError, container.MvaError) as exc:
        sys.exit(f"error: rebuild failed: {exc}")

    if not _verify_patch(mva, code, table, args.r, out_raw, bytes(patched), edits):
        sys.exit("error: verification failed; nothing was written")

    if args.dry_run:
        print("\ndry run: no file written")
        return
    _write(args.output, out_raw, "patched image")
    print("\nREAD docs/patch.md BEFORE FLASHING. A wrong write can end the device.")


def _verify_patch(mva, code, table, r_name, out_raw, want_plain, edits):
    """Prove the rebuilt image is what was intended, before it reaches disk."""
    print("\nverification")
    ok = True
    R = cipher.R_TABLES[r_name]

    new = container.parse(out_raw)
    back, _ = image.decrypt_code(new.record(container.TYPE_CODE).payload, table, R)

    same = back == want_plain
    print(f"  {'PASS' if same else 'FAIL'}  re-encrypted image decrypts back to the "
          "intended plaintext")
    ok &= same

    for addr, _, data in edits:
        good = back[addr:addr + len(data)] == data
        print(f"  {'PASS' if good else 'FAIL'}  {addr:#08x} reads back as intended")
        ok &= good

    # The point of a targeted patch: nothing outside it moved.
    old_ct, n = image.code_words(code.payload)
    new_ct, _ = image.code_words(new.record(container.TYPE_CODE).payload)
    changed = [i for i in range(n) if old_ct[i] != new_ct[i]]
    touched = {(addr + off) // 4 for addr, _, data in edits for off in range(len(data))}
    inside = all(i in touched for i in changed)
    print(f"  {'PASS' if inside else 'FAIL'}  {len(changed)} ciphertext words changed, "
          "all inside the patched region")
    print(f"        {n - len(changed)} of {n} words left byte-identical")
    ok &= inside

    print(f"  {'PASS' if new.crc_ok else 'FAIL'}  CRC16 trailer recomputed: "
          f"{new.stored_crc:#06x} (was {mva.stored_crc:#06x})")
    ok &= new.crc_ok
    return ok


def cmd_verify(args):
    """Decrypt then re-encrypt, and confirm the container comes back unchanged."""
    mva = _load(args.mva)
    try:
        table, _ = image.resolve_table(mva, args.labels, force=args.force)
        code = mva.record(container.TYPE_CODE)
        R = cipher.R_TABLES[args.r]
        plain, stats = image.decrypt_code(code.payload, table, R, strict=False)
        again = image.encrypt_code(plain, code.payload, table, R)
    except (image.DecryptError, container.MvaError, labels.LabelError) as exc:
        sys.exit(f"error: {exc}")
    except ValueError as exc:
        sys.exit(f"error: {exc}")
    except OSError as exc:
        sys.exit(f"error: {exc}")

    same = again == code.payload
    print(f"decrypt/encrypt round trip over {stats['words']} words: "
          f"{'IDENTICAL' if same else 'DIFFERS'}")
    if not same:
        bad = [i for i in range(len(code.payload)) if code.payload[i] != again[i]]
        print(f"  {len(bad)} bytes differ, first at payload offset {bad[0]:#x}")
        sys.exit(1)
    rebuilt = container.rebuild(mva, {container.TYPE_CODE: again})
    print(f"container rebuild: {'IDENTICAL' if rebuilt == mva.raw else 'DIFFERS'}")
    if rebuilt != mva.raw:
        sys.exit(1)


def cmd_selftest(args):
    """Exercise the cipher and container code with no firmware file."""
    fails = []

    def check(name, cond):
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
        if not cond:
            fails.append(name)

    print("cipher")
    check("bswap32 is an involution", all(
        cipher.bswap32(cipher.bswap32(x)) == x
        for x in (0, 1, 0x12345678, 0xFFFFFFFF, 0xDEADBEEF)))
    check("L(0x880) == 0x88000220", cipher.L(0x880) == 0x88000220)
    check("phi is 4 bits", all(0 <= cipher.phi(a) < 16 for a in range(0, 1 << 16, 7)))
    check("phi ignores address bits 0-1",
          all(cipher.phi(a) == cipher.phi(a | 3) for a in range(0, 1 << 14, 4)))
    check("phi is invariant under the 0x880 law",
          all(cipher.phi(a) == cipher.phi(a ^ 0x880) for a in range(0, 1 << 18, 4)))
    check("g = 0 exactly on the four documented (e, s) pairs",
          {es for es in cipher.ES_TABLE if cipher.g_of(*es) == 0} == cipher.G0_PAIRS)
    check("encrypt_word inverts decrypt_word", all(
        cipher.encrypt_word(cipher.decrypt_word(ct, a, e, s), a, e, s) == ct
        for ct in (0, 0x12345678, 0xFFFFFFFF)
        for a in (0, 4, 0x880, 0x1EC74)
        for e, s in cipher.ES_TABLE))
    check("0x880 law holds for every label", all(
        cipher.check_law_0x880(cipher.keystream(a, e, s), cipher.keystream(a ^ 0x880, e, s))
        for a in range(0, 1 << 16, 4)
        for e, s in ((0, 0), (1, 3), (1, 9))))
    check("the other two laws are constant per label", all(
        len({cipher.keystream(a, e, s) ^ cipher.keystream(a ^ d, e, s)
             for a in range(0, 1 << 15, 4)}) == 1
        for d in (0x110000, 0x110880)
        for e, s in ((0, 0), (1, 3), (1, 9))))
    check("14 candidates for a 9-word R, 15 for 10",
          len(list(cipher.candidates(0, 0, cipher.R_SY002))) == 14
          and len(list(cipher.candidates(0, 0, cipher.R_SC3))) == 15)

    print("container")
    check("CRC16-CCITT of b'123456789' is 0x31C3",
          container.crc16_ccitt(b"123456789") == 0x31C3)
    check("CRC16-CCITT of b'' is 0", container.crc16_ccitt(b"") == 0)
    check("bad magic is rejected", _raises(container.parse, b"XX" + bytes(16)))
    check("truncated record is rejected",
          _raises(container.parse, b"MV\xb1\x58\x01\x02\xff\xff\xff\xff" + bytes(8)))

    print("labels")
    tbl = labels.build("test", cipher.ES_TABLE, b"payload", bytes([0, 1, labels.PLAINTEXT, labels.UNSOLVED]))
    rt = labels.loads(labels.dumps(tbl))
    check("label table round trips",
          rt.name == "test" and rt.labels == tbl.labels and rt.es_table == tbl.es_table)
    check("label table binds to its image", rt.matches(b"payload") and not rt.matches(b"other"))
    shipped = labels.available()
    check(f"{len(shipped)} shipped label table(s) load", all(
        labels.load(p) is not None for p in shipped))

    print()
    if fails:
        sys.exit(f"{len(fails)} check(s) FAILED: {', '.join(fails)}")
    print("all checks passed")


def byte_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte.

    Encrypted AP82xx code records sit at 7.99+; plaintext ones at 6.28-7.28
    (measured over the 75 plaintext chip-0xB1 gen-0x58 records collected).
    That separation is clean enough to classify an unknown image, and it is how
    the unencrypted sibling corpus was identified in the first place.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _raises(fn, *a):
    try:
        fn(*a)
    except Exception:
        return True
    return False


# --------------------------------------------------------------------------


def build_parser():
    p = argparse.ArgumentParser(
        prog="python -m decrypt",
        description="Parse and decrypt MVsilicon .MVA firmware containers "
                    "(FIFINE SC3 and siblings).",
        epilog="This tool ships no firmware. Supply your own .MVA file.",
    )
    from . import __version__

    p.add_argument("--version", action="version", version=f"decrypt {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_mva(sp):
        sp.add_argument("mva", help="path to a .MVA firmware container")

    sp = sub.add_parser("info", help="summarise a container")
    add_mva(sp)
    sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("crc", help="check the CRC16 trailer")
    add_mva(sp)
    sp.set_defaults(func=cmd_crc)

    sp = sub.add_parser("extract", help="write one record out verbatim")
    add_mva(sp)
    sp.add_argument("--type", type=int, required=True,
                    help="record type: 1=Command 2=Code 3=FlashDriver 4=Const 5=Config")
    sp.add_argument("--strip-base", action="store_true",
                    help="drop the 4-byte flash base address prefix")
    sp.add_argument("-o", "--output")
    sp.set_defaults(func=cmd_extract)

    sp = sub.add_parser("resources", help="list or extract the Const record's MVUB resources")
    add_mva(sp)
    sp.add_argument("-o", "--output", help="directory to write the resources into")
    sp.set_defaults(func=cmd_resources)

    sp = sub.add_parser("decrypt", help="decrypt the Code record")
    add_mva(sp)
    sp.add_argument("-o", "--output")
    sp.add_argument("--labels", help="explicit label table (.labels.gz)")
    sp.add_argument("--r", choices=sorted(cipher.R_TABLES), default="sc3",
                    help="which R table to use (default: sc3)")
    sp.add_argument("--allow-unsolved", action="store_true",
                    help="zero-fill words the label table cannot account for")
    sp.add_argument("--force", action="store_true",
                    help="apply a label table whose image hash does not match "
                         "(use for images you derived yourself)")
    sp.set_defaults(func=cmd_decrypt)

    sp = sub.add_parser("verify", help="decrypt then re-encrypt and diff against the original")
    add_mva(sp)
    sp.add_argument("--labels")
    sp.add_argument("--r", choices=sorted(cipher.R_TABLES), default="sc3")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser(
        "patch",
        help="apply length-neutral edits to the code record and rebuild the .MVA",
        description=(
            "Apply edits to the DECRYPTED code, re-encrypt, and rebuild the "
            "container with a corrected CRC. Every edit must state the bytes it "
            "expects to find, and must not change length. Nothing is written "
            "until the rebuilt image has been decrypted again and checked."
        ),
        epilog=(
            "example:\n"
            "  python -m decrypt patch STOCK.MVA -o OUT.MVA \\\n"
            "      --edit 0x1ECA6:8006ae75:d5108000\n"
            "\n"
            "Read docs/patch.md before flashing anything this produces."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_mva(sp)
    sp.add_argument("--edit", action="append", default=[], metavar="ADDR:EXPECT:NEW",
                    help="repeatable; addresses are flash addresses in the decrypted image")
    sp.add_argument("-o", "--output", required=True, metavar="OUT.MVA")
    sp.add_argument("--dry-run", action="store_true",
                    help="verify everything, write nothing")
    sp.add_argument("--labels")
    sp.add_argument("--r", choices=sorted(cipher.R_TABLES), default="sc3")
    sp.add_argument("--force", action="store_true",
                    help="accept a label table solved for a different code record; "
                         "correct for an image you derived from that one, garbage otherwise")
    sp.set_defaults(func=cmd_patch)

    sp = sub.add_parser("selftest", help="check the cipher and container code, no firmware needed")
    sp.set_defaults(func=cmd_selftest)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
