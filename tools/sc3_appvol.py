#!/usr/bin/env python3
"""Drive Windows per-application volume from the SC3's faders.  READ ONLY on the device.

A deej-equivalent that needs no extra hardware, no serial port and no driver: the
faders are read over the SC3's own vendor HID interface and applied straight to
Core Audio.

    python tools/sc3_appvol.py --show                 print live fader values
    python tools/sc3_appvol.py --map 0=master 3=discord.exe
    python tools/sc3_appvol.py --config mymap.txt

Config file format, one mapping per line (`#` starts a comment):

    0: master
    1: spotify.exe
    2: chrome.exe, msedge.exe
    3: discord.exe

Windows only: `pip install pycaw comtypes`.

THINGS THAT WILL LOOK LIKE BUGS AND ARE NOT
-------------------------------------------
* **An application's audio session only exists while it is producing sound.**  An
  idle app is simply absent from the session list, so a volume set silently
  matches nothing.  Re-apply when the session reappears rather than only on fader
  movement; this script re-applies on every change and reports what it matched.
* **Audio sessions are per-Windows-session.**  Running this as SYSTEM or from a
  service in session 0 shows only `svchost` and `Idle` and will never see the
  user's applications.  It must run in the interactive logon session.
  (`IAudioEndpointVolume` on the default endpoint, i.e. `master`, does work from
  session 0 - it is the per-app sessions that do not.)
* The fader resolution is **32 positions**, about 3.2% per step.  That is a
  hardware property and no software can improve it.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import acp  # noqa: E402
import sc3_faders  # noqa: E402

MASTER = "master"


def parse_map(items):
    out = {}
    for item in items:
        if "=" not in item:
            sys.exit(f"error: bad mapping {item!r}, expected INDEX=target[,target]")
        k, v = item.split("=", 1)
        try:
            idx = int(k)
        except ValueError:
            sys.exit(f"error: bad fader index {k!r}")
        out[idx] = [t.strip() for t in v.split(",") if t.strip()]
    return out


def load_config(path):
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as exc:
        sys.exit(f"error: cannot read {path}: {exc}")
    out = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            sys.exit(f"error: {path}:{lineno}: expected 'INDEX: target[, target]'")
        k, v = line.split(":", 1)
        try:
            idx = int(k.strip())
        except ValueError:
            sys.exit(f"error: {path}:{lineno}: bad fader index {k.strip()!r}")
        targets = [t.strip() for t in v.split(",") if t.strip()]
        if targets:
            out[idx] = targets
    if not out:
        sys.exit(f"error: {path} contains no mappings")
    return out


class WindowsVolume:
    """Thin wrapper over pycaw, imported lazily so the rest of the tool runs anywhere."""

    def __init__(self):
        if os.name != "nt":
            raise RuntimeError(
                "per-application volume control is Windows-only "
                "(this is Core Audio / pycaw). --show works everywhere."
            )
        try:
            from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume  # noqa: F401
            from comtypes import CLSCTX_ALL  # noqa: F401
        except ImportError:
            raise RuntimeError("pip install pycaw comtypes") from None
        from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
        from comtypes import CLSCTX_ALL
        self._AudioUtilities = AudioUtilities
        self._IAudioEndpointVolume = IAudioEndpointVolume
        self._CLSCTX_ALL = CLSCTX_ALL

    def set_master(self, frac: float):
        dev = self._AudioUtilities.GetSpeakers()
        iface = dev.Activate(self._IAudioEndpointVolume._iid_, self._CLSCTX_ALL, None)
        iface.QueryInterface(self._IAudioEndpointVolume).SetMasterVolumeLevelScalar(frac, None)
        return True

    def set_app(self, name: str, frac: float) -> bool:
        hit = False
        needle = name.lower()
        for s in self._AudioUtilities.GetAllSessions():
            proc = getattr(s, "Process", None)
            if proc is None:
                continue
            try:
                pname = (proc.name() or "").lower()
            except Exception:
                continue
            if needle in pname:
                s.SimpleAudioVolume.SetMasterVolume(frac, None)
                hit = True
        return hit

    def apply(self, targets, frac: float):
        frac = max(0.0, min(1.0, frac))
        matched, missed = [], []
        for t in targets:
            ok = self.set_master(frac) if t.lower() == MASTER else self.set_app(t, frac)
            (matched if ok else missed).append(t)
        return matched, missed


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--show", action="store_true",
                   help="only print fader values, change nothing")
    p.add_argument("--map", nargs="*", default=[], metavar="INDEX=TARGET",
                   help="inline mapping, e.g. 0=master 3=discord.exe")
    p.add_argument("--config", help="mapping file")
    p.add_argument("--source", choices=("auto", "fc", "b6"), default="auto")
    p.add_argument("--interval", type=float, default=0.05)
    args = p.parse_args()

    mapping = {}
    if args.config:
        mapping = load_config(args.config)
    if args.map:
        mapping.update(parse_map(args.map))
    if not args.show and not mapping:
        sys.exit("error: nothing to do. Pass --show, or --map / --config.")

    volume = None
    if not args.show:
        try:
            volume = WindowsVolume()
        except RuntimeError as exc:
            sys.exit(f"error: {exc}")

    dev = acp.open_default()
    try:
        source = args.source
        if source == "auto":
            source, _ = sc3_faders.describe_source(dev)
            source = "b6" if source != "fc" else "fc"
        elif source == "fc":
            # An explicit --source fc on STOCK firmware reads the dead stub's
            # constants 1 2 3 4 and would quietly set master to 1/31, i.e. 3%.
            # Silence there looks like a broken mixer, not a wrong flag.
            detected, _ = sc3_faders.describe_source(dev)
            if detected != "fc":
                sys.exit(
                    "error: --source fc was given, but this device is not running "
                    "the four-fader patch.\n"
                    "  Control 0xFC is returning the unpatched stub's constants, "
                    "which would set your volumes to 3, 6, 9 and 12 percent.\n"
                    "  Use --source b6 for stock firmware, or omit --source."
                )
        n = 4 if source == "fc" else 1
        print(f"reading {'all four faders (ACP 0xFC)' if n == 4 else 'the line-in fader (ACP 0xB6)'}")
        if mapping:
            for i in sorted(mapping):
                mark = "" if i < n else "   <- no such fader on this firmware"
                print(f"  fader {i} -> {', '.join(mapping[i])}{mark}")

        last = [None] * n
        try:
            while True:
                if source == "fc":
                    values = sc3_faders.read_all_faders(dev)
                else:
                    v = sc3_faders.read_line_in(dev)
                    values = None if v is None else [v]
                if values:
                    for i, step in enumerate(values):
                        if last[i] == step:
                            continue
                        last[i] = step
                        frac = step / sc3_faders.STEPS
                        if args.show:
                            print(f"  fader {i}: {step:>2}/31 = {100 * frac:5.1f}%")
                        elif i in mapping:
                            matched, missed = volume.apply(mapping[i], frac)
                            note = f"   not running: {', '.join(missed)}" if missed else ""
                            print(f"  fader {i}: {100 * frac:5.1f}%  -> "
                                  f"{', '.join(matched) if matched else '(nothing)'}{note}")
                        sys.stdout.flush()
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print(f"\nstopped. reads: {dev.stats()}")
    finally:
        dev.close()


if __name__ == "__main__":
    try:
        main()
    except acp.AcpError as exc:
        sys.exit(f"error: {exc}")
