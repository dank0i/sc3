#!/usr/bin/env python3
"""Read the SC3's ACP surface: effect nodes, system blocks, and node names.

READ ONLY.  Nothing here writes to the device.

    python tools/sc3_nodes.py dump          every effect node, 0x81..0xB6
    python tools/sc3_nodes.py system        the codec/system blocks, 0x00..0x0D
    python tools/sc3_nodes.py names         ask the device for its own effect names
    python tools/sc3_nodes.py watch         poll and print anything that changes
    python tools/sc3_nodes.py devices       list the SC3's HID interfaces

The node ceiling of 0xB6 and the dangerous-control set are enforced in acp.py.
Do not raise the ceiling to "see what happens": addresses above 0xB6 answer with
junk and then wedge the whole interface.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import acp  # noqa: E402
import effect_table  # noqa: E402


def cmd_devices(args):
    try:
        devs = acp.list_devices()
    except acp.AcpError as exc:
        sys.exit(f"error: {exc}")
    if not devs:
        sys.exit(f"no device with VID {acp.VID:#06x} PID {acp.PID:#06x} is connected")
    print(f"{len(devs)} SC3 HID interface(s):")
    for d in devs:
        print(f"  interface {d.get('interface_number')}  "
              f"usage_page={d.get('usage_page'):#06x} usage={d.get('usage'):#06x}  "
              f"{d.get('manufacturer_string')} / {d.get('product_string')}")
    print(f"\nACP lives on interface {acp.INTERFACE} (usage page 0xFF00, usage 0x55AA).")


def cmd_dump(args):
    with acp.open_default() as dev:
        names = effect_table.DeviceNames(dev)
        print(f"{'ACP':>5}  {'name':<26} {'status':>7} {'params':>6}  values")
        live = 0
        for addr in range(acp.NODE_MIN, acp.NODE_MAX + 1):
            got = dev.read_node(addr)
            name = names.get(addr) or "?"
            if got is None:
                print(f" {addr:#04x}  {name:<26} {'-':>7} {'-':>6}  (no reply)")
                continue
            live += 1
            status, params = got
            shown = " ".join(f"{v:>6}" for v in params[:8])
            more = f" ... (+{len(params) - 8})" if len(params) > 8 else ""
            print(f" {addr:#04x}  {name:<26} {status:>7} {len(params):>6}  {shown}{more}")
        print(f"\n{live} of {acp.NODE_COUNT} nodes answered.  reads: {dev.stats()}")


def cmd_system(args):
    with acp.open_default() as dev:
        print(f"{'ACP':>5}  {'block':<16} body")
        for ctrl in acp.SYSTEM_CONTROLS:
            body = dev.read(ctrl)
            label = SYSTEM_NAMES.get(ctrl, "?")
            if body is None:
                print(f" {ctrl:#04x}  {label:<16} (no reply)")
            else:
                print(f" {ctrl:#04x}  {label:<16} {body.hex(' ')}")
        print(f"\nreads: {dev.stats()}")


def cmd_names(args):
    """Control 0x80 with a one-byte index returns that effect's own name.

    With `--image`, cross-checks what the device says against the table in a
    decrypted firmware image.  Without it, just lists what the device reports:
    no name table is shipped with this repository.
    """
    table = None
    if args.image:
        try:
            plain = open(args.image, "rb").read()
            table = effect_table.names_from_image(plain)
        except (OSError, ValueError) as exc:
            sys.exit(f"error: {args.image}: {exc}")

    with acp.open_default() as dev:
        if table:
            print("index  ACP   device says                     image table")
        else:
            print("index  ACP   device says")
        for i in range(effect_table.NODE_COUNT):
            got = dev.effect_name(i)
            addr = effect_table.NODE_BASE + i
            if not table:
                print(f"  {i:>3}  {addr:#04x}  {str(got):<30}")
                continue
            want = table[i]
            same = got == want
            flag = "" if same else "  <- differs"
            print(f"  {i:>3}  {addr:#04x}  {str(got):<30} {want}{flag}")
        print(f"\nreads: {dev.stats()}")


def cmd_watch(args):
    with acp.open_default() as dev:
        names = effect_table.DeviceNames(dev)
        addrs = list(range(acp.NODE_MIN, acp.NODE_MAX + 1))
        print(f"baseline over {len(addrs)} nodes ...")
        base = {a: dev.read_node(a) for a in addrs}
        base = {a: v for a, v in base.items() if v is not None}
        print(f"{len(base)} nodes answered.  watching for {args.seconds}s - move things now.")
        sys.stdout.flush()
        t0 = time.time()
        changes = 0
        try:
            while time.time() - t0 < args.seconds:
                for a in addrs:
                    if a not in base:
                        continue
                    cur = dev.read_node(a)
                    if cur is not None and cur != base[a]:
                        name = names.get(a) or "?"
                        print(f"  t={time.time() - t0:6.1f}s  {a:#04x} {name:<26} "
                              f"{base[a][1]} -> {cur[1]}")
                        sys.stdout.flush()
                        base[a] = cur
                        changes += 1
        except KeyboardInterrupt:
            print("\ninterrupted")
        print(f"\n{changes} changes.  reads: {dev.stats()}")
        if dev.fail:
            print("NOTE: some reads failed. A silent-failure run looks identical to "
                  "'nothing changed', so treat a zero-change result with failures as void.")


SYSTEM_NAMES = {
    0x00: "version",
    0x01: "system",
    0x02: "query",
    0x03: "PGA0",
    0x04: "ADC0",
    0x05: "AGC0",
    0x06: "PGA1",
    0x07: "ADC1",
    0x08: "AGC1",
    0x09: "DAC0",
    0x0A: "DAC1",
    0x0B: "I2S0",
    0x0C: "I2S1",
    0x0D: "SPDIF",
}


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("devices", help="list SC3 HID interfaces").set_defaults(func=cmd_devices)
    sub.add_parser("dump", help="read every effect node").set_defaults(func=cmd_dump)
    sub.add_parser("system", help="read the codec/system blocks").set_defaults(func=cmd_system)
    sp = sub.add_parser("names", help="ask the device for its effect names")
    sp.add_argument("--image", metavar="DECRYPTED.bin",
                    help="cross-check against the table in a decrypted image")
    sp.set_defaults(func=cmd_names)
    sp = sub.add_parser("watch", help="poll nodes and report changes")
    sp.add_argument("-s", "--seconds", type=float, default=60.0)
    sp.set_defaults(func=cmd_watch)
    args = p.parse_args()
    try:
        args.func(args)
    except acp.AcpError as exc:
        sys.exit(f"error: {exc}")
    except KeyboardInterrupt:
        sys.exit("\ninterrupted")


if __name__ == "__main__":
    main()
