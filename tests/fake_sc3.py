"""A fake SC3 that speaks ACP, so the tools can be exercised without hardware.

It reproduces the two transport behaviours that matter:

* replies are fetched with `get_input_report`, not pushed;
* an unrecognised control byte does NOT produce a reply, and the device re-serves
  the PREVIOUS reply instead.  Any client that does not match the reply's control
  byte against its request will read stale data and believe a dead control is
  alive.

Install it with `install()`, which puts a module named `hid` into sys.modules.
"""

from __future__ import annotations

import struct
import sys
import types

VID = 0x3142
PID = 0x0C33
REPORT_LEN = 257

EFFECT_COUNT = 54
NODE_MIN = 0x81
NODE_MAX = NODE_MIN + EFFECT_COUNT - 1  # 0xB6

GAIN_PER_STEP = 132


class FakeSC3:
    """State of a simulated device."""

    def __init__(self, patched: bool = False, faders=(0, 23, 0, 0), line_in_step=None):
        self.patched = patched
        self.faders = list(faders)
        self.line_in_step = self.faders[1] if line_in_step is None else line_in_step
        #: control -> reply body, for the simple static blocks
        self.system = {
            0x00: bytes.fromhex("310001010101 2105".replace(" ", "")),
            0x01: bytes(8),
            0x02: bytes.fromhex("ffbc00 0b01 004001 4001".replace(" ", "")),
            # 0x0E is deliberately absent: it has no dispatcher arm and the real
            # device never replies to it. Modelling it as 8 zero bytes baked in
            # a stale-cache reading and made the fake kinder than the hardware.
        }
        self.wedged = False
        self.writes = []

    # -- node model ---------------------------------------------------------

    def node_body(self, addr: int):
        if not NODE_MIN <= addr <= NODE_MAX:
            return None
        idx = addr - NODE_MIN
        if 0xA7 <= addr <= 0xB6:  # the 16 gain_control nodes
            if addr == 0xB6:
                gain = self.line_in_step * GAIN_PER_STEP
            elif addr == 0xB0:
                gain = 7284
            elif 0xB3 <= addr <= 0xB5:
                gain = 3254
            else:
                gain = 4096
            return b"\xff" + struct.pack("<hhh", 1, 0, gain)
        nparams = 52 if 0xA0 <= addr <= 0xA6 else (18 if 0x9D <= addr <= 0x9F else 2)
        return b"\xff" + struct.pack("<h", 1) + struct.pack("<%dh" % nparams,
                                                            *[idx] * nparams)

    def scratch_body(self):
        if self.patched:
            return bytes([0xFF] + [f & 0xFF for f in self.faders])
        return bytes([0xFF, 1, 2, 3, 4])

    # -- framing ------------------------------------------------------------

    def handle(self, frame: bytes):
        """frame is the report starting at the 0xA5.  Returns a reply body or None."""
        if len(frame) < 5 or frame[0] != 0xA5 or frame[1] != 0x5A:
            return None
        ctrl, length = frame[2], frame[3]
        body = frame[4 : 4 + length]
        self.writes.append((ctrl, bytes(body)))

        if ctrl in (0xFB, 0xFD, 0xFE):
            # A real device would act on these. The fake refuses to model them so
            # a test that sends one fails loudly rather than passing quietly.
            raise AssertionError(f"fake device was sent dangerous control {ctrl:#04x}")
        if ctrl > NODE_MAX and ctrl not in (0xFC,) and ctrl >= NODE_MIN:
            self.wedged = True
            return None
        if self.wedged:
            return None
        if ctrl == 0xFC:
            return self.scratch_body()
        if ctrl == 0x80:
            # Model the FIRMWARE, not the client. The index is 1-based and read
            # from body[0]; 0 and anything past the table bail with no reply.
            # The old fake read body[1] and was 0-based, which encoded the
            # client's mistaken convention and let a broken client pass.
            if len(body) >= 1 and body[0] != 0:
                want = body[0] - 1
                if want >= EFFECT_COUNT:
                    return None
                return bytes([body[0]]) + f"2:Fake Effect {want}".encode("ascii")
            return b"\x00effect list"
        if NODE_MIN <= ctrl <= NODE_MAX:
            return self.node_body(ctrl)
        return self.system.get(ctrl)


class _FakeDevice:
    def __init__(self, state: FakeSC3):
        self.state = state
        self.last_reply = bytes(REPORT_LEN)
        self.closed = False

    def open_path(self, path):
        if path != b"fake-sc3-mi04":
            raise OSError("no such device")

    def write(self, data):
        assert len(data) == REPORT_LEN, "reports must be exactly 257 bytes"
        body = self.state.handle(bytes(data[1:]))
        if body is None:
            return len(data)  # no reply; the previous one stays cached
        r = bytearray(REPORT_LEN)
        r[1] = 0xA5
        r[2] = 0x5A
        r[3] = data[3]
        r[4] = len(body)
        r[5 : 5 + len(body)] = body
        r[5 + len(body)] = 0x16
        self.last_reply = bytes(r)
        return len(data)

    def get_input_report(self, report_id, length):
        return list(self.last_reply[:length])

    def close(self):
        self.closed = True


def install(state: FakeSC3):
    """Put a fake `hid` module in sys.modules.  Returns the previous one, if any."""
    previous = sys.modules.get("hid")
    mod = types.ModuleType("hid")

    def enumerate_(vid=0, pid=0):
        if (vid, pid) not in ((0, 0), (VID, PID)):
            return []
        return [
            {"path": b"fake-sc3-mi00", "interface_number": 0, "usage_page": 0x0001,
             "usage": 0x0001, "manufacturer_string": "MV-SILICON",
             "product_string": "fifine SC3"},
            {"path": b"fake-sc3-mi03", "interface_number": 3, "usage_page": 0x000C,
             "usage": 0x0001, "manufacturer_string": "MV-SILICON",
             "product_string": "fifine SC3"},
            {"path": b"fake-sc3-mi04", "interface_number": 4, "usage_page": 0xFF00,
             "usage": 0x55AA, "manufacturer_string": "MV-SILICON",
             "product_string": "fifine SC3"},
        ]

    mod.enumerate = enumerate_
    mod.device = lambda: _FakeDevice(state)
    sys.modules["hid"] = mod
    return previous


def uninstall(previous):
    if previous is None:
        sys.modules.pop("hid", None)
    else:
        sys.modules["hid"] = previous
