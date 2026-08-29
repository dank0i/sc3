"""ACP client for the FIFINE SC3's vendor HID interface.

The SC3 exposes a vendor-defined HID interface (`MI_04`, usage page 0xFF00,
usage 0x55AA) carrying MVsilicon's ACP configuration protocol over 257-byte
reports:

    TX:  A5 5A [CTRL] [LEN] [body ...] 16        LEN = 0 means READ
    RX:  A5 5A [CTRL] [LEN] [body ...] 16

Report ID is 0 and the frame starts at `buf[1]`.  Sends use SetOutputReport,
receives use GetInputReport.

TWO TRANSPORT FACTS THAT WILL BITE YOU
--------------------------------------
1.  `GetInputReport` returns a **cached** report, not an event stream, and the
    device re-serves the previous reply when a control does not answer.  Every
    read here therefore requires `reply CTRL == request CTRL` before accepting
    the data.  A probe that skips that check reads stale data and cannot tell a
    dead control from a live one.
2.  Reads need settle time.  At `delay=0.006, retries=1` every read fails
    silently, and a watcher that does not report its failure count then looks
    exactly like a genuine negative result.  The defaults here are the values
    that were measured to work; `Acp` counts ok/fail and every tool prints it.

SAFETY
------
`DANGEROUS_CONTROLS` and `NODE_MAX` are refused on every frame, by raising
`AcpError`.  Deliberately not `assert`, which vanishes under `python -O`.
See the README for why.  Do not relax them.
"""

from __future__ import annotations

import struct
import sys
import time

VID = 0x3142
PID = 0x0C33
INTERFACE = 4
REPORT_LEN = 257

FRAME_START = 0xA5
FRAME_START2 = 0x5A
FRAME_END = 0x16

#: Control bytes that must never be transmitted.
#:
#: 0xFE  OTA trigger.  Its handler sets an upgrade counter and never reads the
#:       payload, so ANY frame including an empty one starts it; nothing in the
#:       vendor tree ever clears the counter, and when it expires the device
#:       boots to flashboot.  No gate, no abort except unplugging first.
#: 0xFB  unchecked length in the vendor source.  Measured inert on this
#:       particular build, which is not a reason to probe it.
#: 0xFD  excluded as a precaution.
DANGEROUS_CONTROLS = frozenset((0xFB, 0xFD, 0xFE))

#: Effect nodes live at 0x81 + index.  The SC3 has exactly 54 of them.  Reading
#: above 0xB6 makes the firmware index past its node array: the addresses
#: "answer" with junk and the whole ACP interface then stops responding until it
#: is reopened.
NODE_MIN = 0x81
NODE_MAX = 0xB6
NODE_COUNT = NODE_MAX - NODE_MIN + 1  # 54

#: Codec/system blocks that answer on the SC3.  0x05, 0x0E and 0x0F+ do not:
#: 0x0E has no dispatcher arm and measured 0 replies in 40 attempts at a timing
#: where 0x00, 0x04, 0x06 and 0x0D all answered 40/40.
#:
#: 0x80 is deliberately absent too.  A plain read sends LEN=0, which puts the
#: frame terminator exactly where the index byte belongs, so the device answers
#: with effect NAME 21 rather than the effect list.  Use `effect_types()`.
SYSTEM_CONTROLS = (0x00, 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08,
                   0x09, 0x0A, 0x0B, 0x0C, 0x0D)

#: Scratch area the four-fader firmware patch repurposes.  Safe to read.
SCRATCH = 0xFC


class AcpError(Exception):
    pass


def _require_hid():
    try:
        import hid  # noqa: F401
    except ImportError:
        raise AcpError(
            "the 'hidapi' package is not installed.\n"
            "  pip install hidapi"
        ) from None
    return sys.modules["hid"]


def check_control(ctrl: int) -> None:
    """Refuse anything that could wedge or reflash the device."""
    if not 0 <= ctrl <= 0xFF:
        raise AcpError(f"control byte {ctrl} out of range")
    if ctrl in DANGEROUS_CONTROLS:
        raise AcpError(
            f"refusing control {ctrl:#04x}: it is in DANGEROUS_CONTROLS "
            "(OTA / unchecked length). See the README."
        )
    # Note this also blocks 0xFF (the encryption lock), which the docs list as a
    # real control with its own handler. That is deliberate: it is one byte away
    # from 0xFE, nothing here needs it, and the cost of a slip is an OTA that
    # cannot be aborted. `ctrl >= NODE_MIN` is redundant given `ctrl > NODE_MAX`
    # and is kept only so the intent reads in one line.
    if ctrl > NODE_MAX and ctrl != SCRATCH:
        raise AcpError(
            f"refusing control {ctrl:#04x}: the SC3 has {NODE_COUNT} effect nodes "
            f"({NODE_MIN:#04x}..{NODE_MAX:#04x}). Reading above {NODE_MAX:#04x} "
            "wedges the ACP interface. 0xFF is blocked here too, on purpose."
        )


def list_devices():
    """Every SC3 HID interface currently enumerated."""
    hid = _require_hid()
    return list(hid.enumerate(VID, PID))


class Acp:
    """A connection to the SC3's ACP interface.

    Read-only by default.  Pass ``allow_writes=True`` only if you mean it; even
    then the dangerous-control and node-ceiling checks still apply.
    """

    def __init__(self, path=None, allow_writes: bool = False,
                 delay: float = 0.010, retries: int = 4):
        hid = _require_hid()
        if path is None:
            candidates = [d for d in hid.enumerate(VID, PID)
                          if d.get("interface_number") == INTERFACE]
            if not candidates:
                any_sc3 = hid.enumerate(VID, PID)
                if any_sc3:
                    raise AcpError(
                        f"SC3 found but interface {INTERFACE} is not available "
                        f"(saw interfaces {sorted({d.get('interface_number') for d in any_sc3})})"
                    )
                raise AcpError(
                    f"no SC3 found (VID {VID:#06x} PID {PID:#06x}). "
                    "Is it plugged in? On Linux you may need a udev rule."
                )
            path = candidates[0]["path"]
        self._dev = hid.device()
        try:
            self._dev.open_path(path)
        except OSError as exc:
            raise AcpError(f"cannot open the SC3 HID interface: {exc}") from None
        self.allow_writes = allow_writes
        self.delay = delay
        self.retries = retries
        self.ok = 0
        self.fail = 0

    def close(self):
        try:
            self._dev.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # -- framing ----------------------------------------------------------

    def _transact(self, ctrl: int, body: bytes):
        check_control(ctrl)
        if len(body) > 250:
            raise AcpError("body is too long for a 257-byte report")
        tx = bytearray(REPORT_LEN)
        tx[1] = FRAME_START
        tx[2] = FRAME_START2
        tx[3] = ctrl
        tx[4] = len(body)
        tx[5 : 5 + len(body)] = body
        tx[5 + len(body)] = FRAME_END

        for _ in range(self.retries + 1):
            try:
                self._dev.write(bytes(tx))
            except (OSError, ValueError) as exc:
                self.fail += 1
                raise AcpError(f"HID write failed: {exc}") from None
            time.sleep(self.delay)
            try:
                r = bytes(self._dev.get_input_report(0x00, REPORT_LEN))
            except (OSError, ValueError):
                continue
            # The device re-serves the previous reply, so the control byte match
            # is mandatory, not a nicety.
            if len(r) > 5 and r[1] == FRAME_START and r[2] == FRAME_START2 and r[3] == ctrl:
                self.ok += 1
                return r
        self.fail += 1
        return None

    def read(self, ctrl: int):
        """Read one control.  Returns the reply body, or None if it did not answer."""
        r = self._transact(ctrl, b"")
        if r is None:
            return None
        length = r[4]
        return r[5 : 5 + length]

    def write(self, ctrl: int, body: bytes):
        """Write one control.  Requires allow_writes=True.

        ACP writes land in live registers; a power cycle reverts them.  The
        frame shape for a single gain parameter is
        ``A5 5A <node> 03 02 <i16 LE> 16``, i.e. LEN=3 with a parameter index
        rather than the 0xFF "all parameters" selector.
        """
        if not self.allow_writes:
            raise AcpError("this Acp was opened read-only; pass allow_writes=True")
        return self._transact(ctrl, bytes(body))

    # -- decoding ---------------------------------------------------------

    @staticmethod
    def parse_node(body):
        """Decode an effect-node reply body.

        Layout: ``[selector:u8][status:i16 LE][param:i16 LE] ...``

        The leading byte is a **parameter selector**, not data: 0xFF means "all
        parameters", 0x00 the enable flag, 1..n one specific parameter.  A read
        with LEN=0 always comes back with 0xFF.

        Returns ``(status, [params])`` or None.
        """
        if not body:
            return None
        rest = body[1:] if body[0] == 0xFF else body
        n = len(rest) // 2
        if n < 1:
            return None
        vals = list(struct.unpack("<%dh" % n, rest[: 2 * n]))
        return vals[0], vals[1:]

    def read_node(self, addr: int):
        """Read one effect node.  Returns (status, [params]) or None."""
        if not NODE_MIN <= addr <= NODE_MAX:
            raise AcpError(f"node address {addr:#04x} is outside {NODE_MIN:#04x}..{NODE_MAX:#04x}")
        return self.parse_node(self.read(addr))

    def read_gain(self, addr: int):
        """The gain value of a gain_control node, or None.

        Gain nodes report ``status`` plus two parameters; the gain is the second,
        at raw report offset 10.  Values are linear Q12 with 4096 = unity, not
        the centi-dB the SDK descriptor implies.
        """
        got = self.read_node(addr)
        if not got or len(got[1]) < 2:
            return None
        return got[1][1]

    def effect_name(self, index: int):
        """Ask the device for effect `index`'s own name via control 0x80.

        Returns something like ``2:Music 3D Plus``; the digit before the colon
        is the chain id (1=Mic, 2=Music, 3=Guitar, 4=Rec).  `index` is 0-based
        here and is validated, because the firmware's index is 1-based and read
        from the first body byte.

        Three ways this goes wrong if you take a reply at face value, all three
        measured on hardware:

        * Sending a two-byte ``01 <index>`` body makes every request look like
          index 1, so the device answers with table entry 0 every time.
        * Past the end of the table the handler bails WITHOUT replying, and the
          device then re-serves the previous 0x80 reply.  Its control byte
          matches, so `_transact`'s check cannot see it: asking for 54 straight
          after 53 returned `2:Spdif In Gain` in 5 trials out of 5.
        * Firmware index 0 is not a name at all.  It returns the 54-entry
          node-type table, 110 bytes.  So an unvalidated `index` of -1 or 255
          wraps onto it and yields junk (measured: `'6'`).

        The echoed index in the reply is the only thing that distinguishes a
        real answer from a re-serve, so it is checked here.
        """
        if not 0 <= index < NODE_COUNT:
            return None
        want = index + 1
        r = self._transact(0x80, bytes([want]))
        if r is None:
            return None
        length = r[4]
        if length < 2 or r[5] != want:
            return None  # a stale re-serve, or the handler bailed
        raw = r[6 : 5 + length]
        text = bytes(b for b in raw if 32 <= b < 127).decode("ascii", "replace")
        return text.strip() or None

    def effect_types(self):
        """The 54-entry node-type table, in one read.

        Firmware index 0 of control 0x80 streams the table the registration
        loop builds in RAM at init.  Cheaper and far more reliable than reading
        54 names, and it is the direct evidence that the type table is not in
        flash.  Returns a list of ints, or None.
        """
        r = self._transact(0x80, bytes([0]))
        if r is None:
            return None
        length = r[4]
        if length < 2 or r[5] != 0:
            return None
        count = r[6]
        body = r[7 : 5 + length]
        if len(body) < count * 2:
            return None
        return [body[i * 2] | (body[i * 2 + 1] << 8) for i in range(count)]

    def stats(self) -> str:
        return f"{self.ok} ok, {self.fail} failed"


def open_default(**kw) -> Acp:
    """Open the SC3, or exit with a readable message."""
    try:
        return Acp(**kw)
    except AcpError as exc:
        sys.exit(f"error: {exc}")
