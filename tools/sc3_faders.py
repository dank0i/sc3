#!/usr/bin/env python3
"""Read the SC3's fader positions.  READ ONLY.

The SC3 digitises all four faders: each is a 12-bit SAR conversion, deadbanded
and quantised to a **32-position ladder** (step 0..31), rescaled to Q12 so the
reported gain is always `132 * step` with a full scale of 4092.  They are scanned
roughly every 40 ms.

    stock firmware   one fader is reachable: the LINE-IN fader, ACP node 0xB6.
                     (The firmware labels that node "Spdif In Gain"; the SC3 has
                     no SPDIF.  FIFINE reused an unused input-gain slot.)

    patched firmware all four are reachable at once through ACP 0xFC, which the
                     four-fader patch repurposes.  See docs/patch.md.

        request  A5 5A FC 00 16
        reply    A5 5A FC 05 FF s0 s1 s2 s3 16      each sN = 0..31

Usage:

    python tools/sc3_faders.py                read once and report
    python tools/sc3_faders.py --watch        follow changes until ctrl-C
    python tools/sc3_faders.py --source b6    force the stock single-fader path
    python tools/sc3_faders.py --raw          print raw ACP bodies too
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import acp  # noqa: E402

STEPS = 31          # positions are 0..31
GAIN_PER_STEP = 132  # 132 * 31 == 4092, the reported full scale
LINE_IN_NODE = 0xB6

#: What the unpatched 0xFC stub returns: four hardcoded constants.
STOCK_STUB = (1, 2, 3, 4)


def read_all_faders(dev):
    """Four positions 0..31 from patched firmware, or None."""
    body = dev.read(acp.SCRATCH)
    if body is None or len(body) < 5 or body[0] != 0xFF:
        return None
    return [min(STEPS, b) for b in body[1:5]]


def read_line_in(dev):
    """The line-in fader position 0..31 from stock firmware, or None."""
    gain = dev.read_gain(LINE_IN_NODE)
    if gain is None:
        return None
    return gain_to_step(gain)


def gain_to_step(gain: int) -> int:
    """Q12 gain -> ladder position.  Reported gains are exact multiples of 132."""
    return max(0, min(STEPS, round(gain / GAIN_PER_STEP)))


def pct(step: int) -> float:
    return 100.0 * step / STEPS


def describe_source(dev):
    """Decide which path to use, and say so honestly."""
    values = read_all_faders(dev)
    if values is None:
        return "b6", None
    if tuple(values) == STOCK_STUB:
        return "b6?", values
    return "fc", values


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--source", choices=("auto", "fc", "b6"), default="auto",
                   help="fc = patched four-fader path, b6 = stock line-in node")
    p.add_argument("--watch", action="store_true", help="follow changes until ctrl-C")
    p.add_argument("--interval", type=float, default=0.05)
    p.add_argument("--raw", action="store_true", help="also print raw ACP reply bodies")
    args = p.parse_args()

    dev = acp.open_default()
    try:
        source = args.source
        if source == "auto":
            source, values = describe_source(dev)
            if source == "fc":
                print("patched firmware detected: reading all four faders from ACP 0xFC")
            else:
                if values is not None:
                    print("ACP 0xFC returned the stock stub constants 01 02 03 04.")
                    print("  That is what unpatched firmware returns. If your faders really")
                    print("  are at 1/2/3/4 out of 31 this reading is ambiguous - move one")
                    print("  and re-run, or force --source fc.")
                print(f"falling back to the stock line-in node {LINE_IN_NODE:#04x}")
                source = "b6"

        if args.raw:
            body = dev.read(acp.SCRATCH if source == "fc" else LINE_IN_NODE)
            print(f"  raw body: {body.hex(' ') if body else '(no reply)'}")

        read = (lambda: read_all_faders(dev)) if source == "fc" else \
               (lambda: (lambda v: None if v is None else [v])(read_line_in(dev)))

        if not args.watch:
            v = read()
            if v is None:
                sys.exit(f"error: no reply. reads: {dev.stats()}")
            report(v, source)
            print(f"reads: {dev.stats()}")
            return

        print("watching - move the faders. ctrl-C to stop.")
        if source == "fc":
            print("(move ONE at a time the first time, to learn which index is which)")
        last = None
        try:
            while True:
                v = read()
                if v is not None and v != last:
                    stamp = time.strftime("%H:%M:%S")
                    cells = "  ".join(f"f{i}={s:>2}/31 {pct(s):5.1f}%"
                                      for i, s in enumerate(v))
                    print(f"  {stamp}  {cells}")
                    sys.stdout.flush()
                    last = v
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print(f"\nstopped. reads: {dev.stats()}")
    finally:
        dev.close()


def report(values, source):
    if source == "fc":
        print("all four faders (index -> physical fader mapping is device-specific,")
        print("move one at a time with --watch to learn it):")
    else:
        print(f"line-in fader (ACP {LINE_IN_NODE:#04x}):")
    for i, s in enumerate(values):
        bar = "#" * int(round(20 * s / STEPS))
        print(f"  fader {i}  {s:>2}/31  {pct(s):5.1f}%  |{bar:<20}|")


if __name__ == "__main__":
    try:
        main()
    except acp.AcpError as exc:
        sys.exit(f"error: {exc}")
