"""Test suite.  Needs no firmware file and no hardware.

    python -m unittest discover -s tests -v
    python tests/test_all.py
"""

from __future__ import annotations

import os
import struct
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pathlib  # noqa: E402

from decrypt import cipher, cli, container, image, labels  # noqa: E402
import fake_sc3  # noqa: E402


# ---------------------------------------------------------------- cipher

class TestCipher(unittest.TestCase):
    def test_bswap_involution(self):
        for x in (0, 1, 0x12345678, 0xFFFFFFFF, 0xDEADBEEF):
            self.assertEqual(cipher.bswap32(cipher.bswap32(x)), x)

    def test_L(self):
        self.assertEqual(cipher.L(0x880), 0x88000220)
        self.assertEqual(cipher.L(0), 0)

    def test_phi_is_nibble_fold_of_a_shifted(self):
        for a in range(0, 1 << 17, 4):
            b = a >> 2
            fold = 0
            while b:
                fold ^= b & 0xF
                b >>= 4
            self.assertEqual(cipher.phi(a), fold, hex(a))

    def test_phi_ignores_low_two_bits(self):
        for a in range(0, 1 << 14, 4):
            for k in (1, 2, 3):
                self.assertEqual(cipher.phi(a), cipher.phi(a | k))

    def test_g_rule(self):
        got = {es for es in cipher.ES_TABLE if cipher.g_of(*es) == 0}
        self.assertEqual(got, cipher.G0_PAIRS)

    def test_encrypt_inverts_decrypt(self):
        for ct in (0, 1, 0x12345678, 0xFFFFFFFF):
            for a in (0, 4, 0x880, 0x1EC74, 0x134414):
                for e, s in cipher.ES_TABLE:
                    pt = cipher.decrypt_word(ct, a, e, s)
                    self.assertEqual(cipher.encrypt_word(pt, a, e, s), ct)

    def test_law_0x880(self):
        for a in range(0, 1 << 16, 4):
            for e, s in ((0, 0), (0, 3), (1, 5), (1, 9)):
                k1 = cipher.keystream(a, e, s)
                k2 = cipher.keystream(a ^ 0x880, e, s)
                self.assertTrue(cipher.check_law_0x880(k1, k2), hex(a))

    def test_other_laws_are_constant(self):
        for d in (0x110000, 0x110880):
            for e, s in ((0, 0), (1, 3), (1, 9)):
                deltas = {cipher.keystream(a, e, s) ^ cipher.keystream(a ^ d, e, s)
                          for a in range(0, 1 << 15, 4)}
                self.assertEqual(len(deltas), 1, (hex(d), e, s))

    def test_law_partners_form_a_group(self):
        a = 0x12340
        partners = set(cipher.law_partners(a))
        self.assertEqual(len(partners), 3)
        self.assertNotIn(a, partners)
        # closed under XOR with the deltas
        for p in partners:
            self.assertIn(a, set(cipher.law_partners(p)) | {a})

    def test_candidate_count(self):
        self.assertEqual(len(list(cipher.candidates(0, 0, cipher.R_SC3))), 15)
        self.assertEqual(len(list(cipher.candidates(0, 0, cipher.R_SY002))), 14)

    def test_candidates_include_the_truth(self):
        for e, s in cipher.ES_TABLE:
            a, pt = 0x4000, 0xCAFEBABE
            ct = cipher.encrypt_word(pt, a, e, s)
            self.assertIn(pt, [c[2] for c in cipher.candidates(ct, a)])


# ------------------------------------------------------------- container

def build_mva(records, chip=0xB1, gen=0x58, crc=None):
    out = bytearray(b"MV")
    out.append(chip)
    out.append(gen)
    out.append(len(records))
    for rtype, payload in records:
        out.append(rtype)
        out += struct.pack("<I", len(payload))
        out += payload
    out += b"\0\0\0\0"
    value = container.crc16_ccitt(bytes(out[:-4])) if crc is None else crc
    out[-4:] = struct.pack("<HH", value, 0)
    return bytes(out)


class TestContainer(unittest.TestCase):
    def test_crc_reference_vectors(self):
        self.assertEqual(container.crc16_ccitt(b""), 0x0000)
        self.assertEqual(container.crc16_ccitt(b"123456789"), 0x31C3)
        self.assertEqual(container.crc16_ccitt(b"\x00"), 0x0000)
        self.assertEqual(container.crc16_ccitt(b"A"), 0x58E5)

    def test_roundtrip(self):
        raw = build_mva([(1, b"\x35\xba\x69"),
                         (3, b"\x00" * 8),
                         (2, struct.pack("<I", 0) + b"\x01\x02\x03\x04"),
                         (4, struct.pack("<I", 0x135000) + b"MVUB" + b"\x00" * 8)])
        mva = container.parse(raw)
        self.assertEqual(mva.chip, 0xB1)
        self.assertEqual(mva.generation, 0x58)
        self.assertEqual(len(mva.records), 4)
        self.assertTrue(mva.crc_ok)
        self.assertEqual(mva.record(2).flash_base, 0)
        self.assertEqual(mva.record(4).flash_base, 0x135000)
        self.assertIsNone(mva.record(1).flash_base)
        self.assertEqual(container.rebuild(mva, {}), raw)

    def test_rebuild_fixes_crc(self):
        raw = build_mva([(2, struct.pack("<I", 0) + b"\x01\x02\x03\x04")])
        mva = container.parse(raw)
        new = container.rebuild(mva, {2: struct.pack("<I", 0) + b"\x09\x09\x09\x09"})
        self.assertTrue(container.parse(new).crc_ok)
        self.assertNotEqual(new[-4:], raw[-4:])

    def test_rebuild_refuses_length_change(self):
        raw = build_mva([(2, struct.pack("<I", 0) + b"\x01\x02\x03\x04")])
        mva = container.parse(raw)
        with self.assertRaises(container.MvaError):
            container.rebuild(mva, {2: b"short"})

    def test_bad_magic(self):
        with self.assertRaises(container.MvaError):
            container.parse(b"XX" + bytes(32))

    def test_truncated_record(self):
        bad = b"MV\xb1\x58\x01\x02\xff\xff\xff\xff" + bytes(8)
        with self.assertRaises(container.MvaError):
            container.parse(bad)

    def test_trailing_garbage(self):
        raw = bytearray(build_mva([(2, struct.pack("<I", 0) + b"\x01\x02\x03\x04")]))
        raw[4:5] = b"\x00"  # claim zero records, leaving the payload unaccounted
        with self.assertRaises(container.MvaError):
            container.parse(bytes(raw))

    def test_mvub(self):
        entries = b""
        blobs = b""
        names = ["kaiji", "guanji"]
        base = 0x1000
        table = bytearray(b"MVUB" + struct.pack("<I", 0) + bytes([len(names)]))
        offset = base
        for n in names:
            payload = b"\xff\xfd" + n.encode() * 4
            table += n.encode().ljust(8, b" ") + struct.pack("<II", offset, len(payload))
            blobs += payload
            offset += len(payload)
        body = bytes(table).ljust(base, b"\x00") + blobs
        res = container.parse_mvub(body)
        self.assertEqual([r.name for r in res], names)
        self.assertEqual(container.read_resource(body, res[0])[:2], b"\xff\xfd")

    def test_mvub_rejects_out_of_range(self):
        body = (b"MVUB" + struct.pack("<I", 0) + bytes([1])
                + b"x".ljust(8, b" ") + struct.pack("<II", 0x1000, 999999))
        with self.assertRaises(container.MvaError):
            container.parse_mvub(body)


# ---------------------------------------------------------------- labels

class TestLabels(unittest.TestCase):
    def test_roundtrip(self):
        payload = b"code-record"
        lab = bytes([0, 1, 2, labels.PLAINTEXT, labels.UNSOLVED])
        t = labels.build("unit test", cipher.ES_TABLE, payload, lab)
        rt = labels.loads(labels.dumps(t))
        self.assertEqual(rt.name, "unit test")
        self.assertEqual(rt.labels, lab)
        self.assertEqual(rt.es_table, cipher.ES_TABLE)
        self.assertTrue(rt.matches(payload))
        self.assertFalse(rt.matches(b"something else"))
        self.assertEqual((rt.solved, rt.passthrough, rt.unsolved), (3, 1, 1))
        self.assertEqual(rt.label(0), (0, 0))
        self.assertEqual(rt.label(3), labels.PLAINTEXT)

    def test_shipped_tables_load(self):
        shipped = labels.available()
        self.assertTrue(shipped, "no label table is shipped")
        for path in shipped:
            t = labels.load(path)
            self.assertGreater(len(t), 0)
            self.assertEqual(len(t.sha256), 32)
            self.assertEqual(t.unsolved, 0, f"{path.name} has unsolved words")

    def test_rejects_corrupt(self):
        with self.assertRaises(Exception):
            labels.loads(b"not gzip at all")


# ----------------------------------------------------------------- image

class TestImage(unittest.TestCase):
    """Round-trip a synthetic image through the real encrypt/decrypt path."""

    def setUp(self):
        self.n = 64
        self.plain = bytes(range(256)) * (self.n // 64)
        pt = struct.unpack("<%dI" % self.n, self.plain)
        self.lab = bytes((i * 7) % len(cipher.ES_TABLE) for i in range(self.n))
        ct = [cipher.encrypt_word(pt[i], 4 * i, *cipher.ES_TABLE[self.lab[i]])
              for i in range(self.n)]
        self.payload = struct.pack("<I", 0) + struct.pack("<%dI" % self.n, *ct)
        self.table = labels.build("synthetic", cipher.ES_TABLE, self.payload, self.lab)

    def test_decrypt(self):
        out, stats = image.decrypt_code(self.payload, self.table)
        self.assertEqual(out, self.plain)
        self.assertEqual(stats["solved"], self.n)
        self.assertEqual(stats["unsolved"], 0)

    def test_encrypt_is_the_inverse(self):
        out, _ = image.decrypt_code(self.payload, self.table)
        self.assertEqual(image.encrypt_code(out, self.payload, self.table), self.payload)

    def test_passthrough_words_are_not_decrypted(self):
        lab = bytearray(self.lab)
        lab[5] = labels.PLAINTEXT
        table = labels.build("pt", cipher.ES_TABLE, self.payload, bytes(lab))
        out, stats = image.decrypt_code(self.payload, table)
        self.assertEqual(stats["passthrough"], 1)
        self.assertEqual(out[20:24], self.payload[24:28])

    def test_unsolved_is_strict_by_default(self):
        lab = bytearray(self.lab)
        lab[9] = labels.UNSOLVED
        table = labels.build("u", cipher.ES_TABLE, self.payload, bytes(lab))
        with self.assertRaises(image.DecryptError):
            image.decrypt_code(self.payload, table)
        out, stats = image.decrypt_code(self.payload, table, strict=False)
        self.assertEqual(stats["unsolved"], 1)
        self.assertEqual(out[36:40], b"\x00\x00\x00\x00")

    def test_wrong_size_table_is_rejected(self):
        table = labels.build("short", cipher.ES_TABLE, self.payload, self.lab[:10])
        with self.assertRaises(image.DecryptError):
            image.decrypt_code(self.payload, table)

    def test_resolve_table_rejects_a_foreign_label_file(self):
        raw = build_mva([(2, self.payload)])
        mva = container.parse(raw)
        with self.assertRaises(image.DecryptError):
            image.resolve_table(mva)


# ------------------------------------------------------------------- ACP

class AcpTestCase(unittest.TestCase):
    patched = False

    def setUp(self):
        self.state = fake_sc3.FakeSC3(patched=self.patched)
        self._prev = fake_sc3.install(self.state)
        for mod in ("acp", "sc3_faders", "sc3_appvol", "effect_table"):
            sys.modules.pop(mod, None)
        global acp, sc3_faders
        import acp  # noqa: F811
        import sc3_faders  # noqa: F811
        self.acp = acp
        self.sc3_faders = sc3_faders
        self.dev = acp.Acp(delay=0.0, retries=1)

    def tearDown(self):
        self.dev.close()
        fake_sc3.uninstall(self._prev)


class TestAcpSafety(AcpTestCase):
    def test_dangerous_controls_are_refused(self):
        for ctrl in (0xFB, 0xFD, 0xFE):
            with self.assertRaises(self.acp.AcpError):
                self.dev.read(ctrl)
        self.assertEqual(self.state.writes, [], "a dangerous frame reached the device")

    def test_node_ceiling_is_enforced(self):
        for ctrl in (0xB7, 0xBA, 0xFA):
            with self.assertRaises(self.acp.AcpError):
                self.dev.read(ctrl)
        self.assertFalse(self.state.wedged)

    def test_read_node_rejects_out_of_range(self):
        with self.assertRaises(self.acp.AcpError):
            self.dev.read_node(0xB7)
        with self.assertRaises(self.acp.AcpError):
            self.dev.read_node(0x80)

    def test_writes_are_refused_unless_enabled(self):
        with self.assertRaises(self.acp.AcpError):
            self.dev.write(0xB6, b"\x02\x00\x10")

    def test_write_frame_shape(self):
        dev = self.acp.Acp(allow_writes=True, delay=0.0, retries=1)
        dev.write(0xB6, bytes([0x02, 0x00, 0x10]))
        self.assertEqual(self.state.writes[-1], (0xB6, bytes([0x02, 0x00, 0x10])))
        dev.close()


class TestAcpReads(AcpTestCase):
    def test_node_dump(self):
        seen = 0
        for addr in range(self.acp.NODE_MIN, self.acp.NODE_MAX + 1):
            got = self.dev.read_node(addr)
            self.assertIsNotNone(got, hex(addr))
            seen += 1
        self.assertEqual(seen, 54)
        self.assertEqual(self.dev.fail, 0)

    def test_eq_nodes_have_52_params(self):
        for addr in range(0xA0, 0xA7):
            status, params = self.dev.read_node(addr)
            self.assertEqual(len(params), 52, hex(addr))

    def test_gain_nodes(self):
        self.assertEqual(self.dev.read_gain(0xA7), 4096)
        self.assertEqual(self.dev.read_gain(0xB0), 7284)
        self.assertEqual(self.dev.read_gain(0xB6), 23 * 132)

    def test_stale_reply_is_not_accepted(self):
        """0x05 does not answer; the device re-serves the previous reply."""
        self.assertIsNotNone(self.dev.read(0x00))
        before = self.dev.fail
        self.assertIsNone(self.dev.read(0x05))
        self.assertEqual(self.dev.fail, before + 1)

    def test_effect_name(self):
        self.assertIn("Fake Effect 21", self.dev.effect_name(21) or "")

    def test_parse_node_selector(self):
        self.assertEqual(self.acp.Acp.parse_node(bytes.fromhex("ff01000000fc0f")),
                         (1, [0, 4092]))
        self.assertIsNone(self.acp.Acp.parse_node(b""))


class TestFadersStock(AcpTestCase):
    patched = False

    def test_scratch_is_the_stub(self):
        self.assertEqual(self.sc3_faders.read_all_faders(self.dev),
                         list(self.sc3_faders.STOCK_STUB))

    def test_line_in(self):
        self.assertEqual(self.sc3_faders.read_line_in(self.dev), 23)

    def test_source_detection_falls_back(self):
        source, _ = self.sc3_faders.describe_source(self.dev)
        self.assertEqual(source, "b6?")


class TestFadersPatched(AcpTestCase):
    patched = True

    def test_all_four(self):
        self.assertEqual(self.sc3_faders.read_all_faders(self.dev), [0, 23, 0, 0])

    def test_source_detection(self):
        source, values = self.sc3_faders.describe_source(self.dev)
        self.assertEqual(source, "fc")
        self.assertEqual(values, [0, 23, 0, 0])

    def test_step_conversion(self):
        for gain, step in ((0, 0), (528, 4), (2376, 18), (3960, 30), (4092, 31)):
            self.assertEqual(self.sc3_faders.gain_to_step(gain), step)
        self.assertAlmostEqual(self.sc3_faders.pct(31), 100.0)
        self.assertAlmostEqual(self.sc3_faders.pct(0), 0.0)


class TestMismatchedRTable(unittest.TestCase):
    """The SC3's labels use s=9; the SY002 and ONOORUS R tables have nine
    entries. That combination used to raise a bare IndexError from deep inside
    keystream(), which said nothing about which two things disagreed."""

    def test_s_outside_r_raises_a_readable_error(self):
        for name in ("sy002", "onoorus"):
            R = cipher.R_TABLES[name]
            with self.assertRaises(ValueError) as ctx:
                cipher.keystream(0x1000, 1, 9, R)
            msg = str(ctx.exception)
            self.assertIn("different images", msg)
            self.assertIn(str(len(R)), msg)

    def test_valid_s_still_works(self):
        self.assertIsInstance(cipher.keystream(0x1000, 1, 0, cipher.R_SC3), int)
        self.assertIsInstance(cipher.keystream(0x1000, 1, 9, cipher.R_SC3), int)


class TestPatchEndToEnd(unittest.TestCase):
    """`decrypt patch` builds images that get flashed to hardware, so its guards
    are the highest-consequence code here. This drives the real CLI against a
    synthetic image and label table: no firmware, no device.
    """

    PLAIN = bytes(range(256)) * 8  # 2048 bytes, 512 words

    def setUp(self):
        import tempfile
        from decrypt import cipher, image as img

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = pathlib.Path(self.tmp.name)

        # Label every word with the first realised (e, s) pair, then encrypt the
        # chosen plaintext under it, so the image genuinely round-trips.
        self.es = (1, 0)
        payload = struct.pack("<I", 0)
        for i in range(len(self.PLAIN) // 4):
            a = i * 4
            pt = struct.unpack_from("<I", self.PLAIN, a)[0]
            ct = cipher.encrypt_word(pt, a, *self.es)
            payload += struct.pack("<I", ct)

        self.mva_path = d / "STOCK.MVA"
        self.mva_path.write_bytes(build_mva([(1, b"\x35\xba\x69"), (2, payload)]))

        code = container.parse(self.mva_path.read_bytes()).record(container.TYPE_CODE)
        table = labels.build(
            "synthetic", (self.es,), code.payload, bytes([0] * (len(self.PLAIN) // 4))
        )
        self.labels_path = d / "synthetic.labels.gz"
        labels.save(table, self.labels_path)

        # Confirm the fixture actually decrypts to PLAIN before testing on it.
        got, _ = img.decrypt_code(code.payload, table, cipher.R_SC3)
        self.assertEqual(got[: len(self.PLAIN)], self.PLAIN, "fixture is not self-consistent")

        self.out = d / "OUT.MVA"

    def run_patch(self, *args):
        """Run the real CLI. Returns the SystemExit message, or None on success.

        The CLI prints a verification block on every run; swallow it so the test
        log stays readable. Failures still surface through the return value.
        """
        import contextlib
        import io

        argv = ["patch", str(self.mva_path), "-o", str(self.out),
                "--labels", str(self.labels_path), *args]
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                cli.main(argv)
        except SystemExit as exc:
            return str(exc.code) if exc.code else None
        return None

    def stock_hex(self, addr, n):
        return self.PLAIN[addr : addr + n].hex()

    def test_a_correct_edit_produces_a_valid_image(self):
        err = self.run_patch("--edit", f"0x40:{self.stock_hex(0x40, 4)}:aabbccdd")
        self.assertIsNone(err, err)
        self.assertTrue(self.out.exists())
        rebuilt = container.parse(self.out.read_bytes())
        self.assertTrue(rebuilt.crc_ok, "rebuilt container CRC must be recomputed")

        from decrypt import cipher, image as img
        table = labels.load(self.labels_path)
        plain, _ = img.decrypt_code(
            rebuilt.record(container.TYPE_CODE).payload, table, cipher.R_SC3
        )
        self.assertEqual(plain[0x40:0x44], bytes.fromhex("aabbccdd"))
        # Everything outside the edit must be untouched.
        self.assertEqual(plain[:0x40], self.PLAIN[:0x40])
        self.assertEqual(plain[0x44 : len(self.PLAIN)], self.PLAIN[0x44 : len(self.PLAIN)])

    def test_wrong_expect_is_refused_and_writes_nothing(self):
        err = self.run_patch("--edit", "0x40:deadbeef:aabbccdd")
        self.assertIn("does not hold the expected bytes", err or "")
        self.assertFalse(self.out.exists(), "a refused patch must not write a file")

    def test_already_patched_is_detected(self):
        want = self.stock_hex(0x40, 4)
        err = self.run_patch("--edit", f"0x40:{want}:{want}")
        self.assertIn("already holds the replacement", err or "")

    def test_overlapping_edits_are_refused(self):
        err = self.run_patch("--edit", f"0x40:{self.stock_hex(0x40, 4)}:aabbccdd",
                             "--edit", f"0x42:{self.stock_hex(0x42, 4)}:11223344")
        self.assertIn("overlap", (err or "").lower())
        self.assertFalse(self.out.exists())

    def test_edit_past_the_end_is_refused(self):
        err = self.run_patch("--edit", "0x900000:0011:2233")
        self.assertIn("past the end", err or "")

    def test_output_may_not_be_the_input(self):
        argv = ["patch", str(self.mva_path), "-o", str(self.mva_path),
                "--labels", str(self.labels_path), "--edit", "0x40:0011:2233"]
        before = self.mva_path.read_bytes()
        with self.assertRaises(SystemExit) as ctx:
            cli.main(argv)
        self.assertIn("only rollback", str(ctx.exception.code))
        self.assertEqual(self.mva_path.read_bytes(), before, "input must be untouched")

    def test_dry_run_verifies_but_writes_nothing(self):
        err = self.run_patch("--edit", f"0x40:{self.stock_hex(0x40, 4)}:aabbccdd",
                             "--dry-run")
        self.assertIsNone(err, err)
        self.assertFalse(self.out.exists())

    def test_damaged_input_is_refused(self):
        bad = pathlib.Path(self.tmp.name) / "BAD.MVA"
        raw = bytearray(self.mva_path.read_bytes())
        raw[-4] ^= 0xFF
        bad.write_bytes(bytes(raw))
        argv = ["patch", str(bad), "-o", str(self.out),
                "--labels", str(self.labels_path), "--edit", "0x40:0011:2233"]
        with self.assertRaises(SystemExit) as ctx:
            cli.main(argv)
        self.assertIn("damaged", str(ctx.exception.code))


class TestEffectNameConvention(AcpTestCase):
    """The 0x80 index is 1-based and read from body[0].

    Shipping the wrong convention here is invisible: every reply is well formed
    and every node just reports table entry 0. Confirmed on hardware.
    """

    def test_distinct_indices_give_distinct_names(self):
        names = [self.dev.effect_name(i) for i in (0, 1, 5, 20, 53)]
        self.assertEqual(len(set(names)), len(names), f"all indices returned {names}")

    def test_index_zero_maps_to_the_first_table_entry(self):
        self.assertEqual(self.dev.effect_name(0), "2:Fake Effect 0")
        self.assertEqual(self.dev.effect_name(5), "2:Fake Effect 5")

    def test_echoed_index_byte_is_stripped(self):
        # From index 32 up the echoed byte is printable ASCII, so a filter that
        # only drops control characters leaves a digit glued to the name.
        for i in (32, 40, 53):
            got = self.dev.effect_name(i)
            self.assertEqual(got, f"2:Fake Effect {i}", f"index {i} came back as {got!r}")

    def test_past_the_table_does_not_answer(self):
        # Must prime the cache first. With a cold cache the stale frame fails
        # the A5 5A check and this passes for the wrong reason; primed the way
        # real use primes it, the device re-serves the last name with a MATCHING
        # control byte, which only the echoed-index check can reject. Measured
        # on hardware: asking 54 straight after 53 returned '2:Spdif In Gain'
        # in 5 trials out of 5.
        self.assertEqual(self.dev.effect_name(53), "2:Fake Effect 53")
        self.assertIsNone(self.dev.effect_name(54))

    def test_a_lost_read_does_not_return_the_previous_node_name(self):
        """The case the echoed-index check exists for.

        A dropped read inside the valid range makes the device re-serve the
        previous 0x80 reply, whose control byte matches, so the transport's own
        check cannot see it. At the measured 17% loss rate this is the common
        failure, not an edge case. Without the check, node 21 silently reports
        node 20's name.
        """
        self.state.drop_name_indices = {21}
        self.assertEqual(self.dev.effect_name(20), "2:Fake Effect 20")
        self.assertIsNone(
            self.dev.effect_name(21),
            "a lost read returned the previous node's name instead of None",
        )

    def test_out_of_range_indices_do_not_wrap_onto_the_type_table(self):
        # index+1 with no range check maps 255 and -1 onto firmware index 0,
        # which streams the node-type table. On hardware that decoded to '6'.
        self.assertEqual(self.dev.effect_name(53), "2:Fake Effect 53")
        for bad in (54, 255, -1, 1000):
            self.assertIsNone(self.dev.effect_name(bad), f"index {bad} answered")

    def test_effect_types_reads_the_node_type_table(self):
        types = self.dev.effect_types()
        self.assertIsNotNone(types)
        self.assertEqual(len(types), 54)


class TestPatchArgumentGuards(unittest.TestCase):
    """Every guard here exists to stop a bad image reaching a device. They are
    tested at the parser level so they hold without any firmware present."""

    def setUp(self):
        from decrypt import cli
        self.cli = cli

    def _edit_fails(self, text, needle):
        with self.assertRaises(SystemExit) as ctx:
            self.cli._parse_edit(text)
        self.assertIn(needle, str(ctx.exception).lower())

    def test_well_formed_edit_parses(self):
        addr, expect, new = self.cli._parse_edit("0x4420A:04:01")
        self.assertEqual(addr, 0x4420A)
        self.assertEqual(expect, b"\x04")
        self.assertEqual(new, b"\x01")

    def test_hex_may_be_spaced_or_prefixed(self):
        _, expect, new = self.cli._parse_edit("0x10:80 06 ae 75:0xd5108000")
        self.assertEqual(expect, bytes([0x80, 0x06, 0xAE, 0x75]))
        self.assertEqual(new, bytes([0xD5, 0x10, 0x80, 0x00]))

    def test_expect_is_not_optional(self):
        # Without it, a patch written for one build silently applies to another.
        self._edit_fails("0x4420A:01", "addr:expect:new")

    def test_length_changing_edit_is_refused(self):
        # Growing or shrinking code shifts every later branch target.
        self._edit_fails("0x4420A:04:0102", "length-neutral")

    def test_odd_and_non_hex_are_refused(self):
        self._edit_fails("0x4420A:4:01", "hex bytes")
        self._edit_fails("0x4420A:zz:01", "not hex")

    def test_bad_address_is_refused(self):
        self._edit_fails("nowhere:04:01", "not an address")
        self._edit_fails("-4:04:01", "negative")


class TestEffectTable(unittest.TestCase):
    """The name table is derived at runtime, never shipped, so the parser and
    the device reader are the things that have to be right."""

    def setUp(self):
        import effect_table
        self.et = effect_table

    def _image(self, names, count=None):
        """Build a synthetic decrypted image carrying an effect table."""
        count = len(names) if count is None else count
        buf = bytearray(self.et.TABLE_FLASH_ADDR + count * self.et.TABLE_STRIDE)
        for i, n in enumerate(names):
            off = self.et.TABLE_FLASH_ADDR + i * self.et.TABLE_STRIDE
            buf[off:off + len(n)] = n.encode()
        return bytes(buf)

    def test_parses_names_at_the_documented_stride(self):
        names = tuple(f"2:Node {i}" for i in range(self.et.NODE_COUNT))
        got = self.et.names_from_image(self._image(names))
        self.assertEqual(got, names)

    def test_short_image_raises_rather_than_returning_junk(self):
        with self.assertRaises(ValueError):
            self.et.names_from_image(b"\x00" * 1024)

    def test_empty_entry_raises(self):
        # A wrong image decrypts to zeros here; that must not read as 54 blanks.
        img = self._image(("1:Mic Thing",), count=self.et.NODE_COUNT)
        with self.assertRaises(ValueError):
            self.et.names_from_image(img)

    def test_address_indexing_bounds(self):
        self.assertEqual(self.et.index_for(self.et.NODE_BASE), 0)
        self.assertEqual(self.et.index_for(0xB6), 53)
        self.assertIsNone(self.et.index_for(0xB7))
        self.assertIsNone(self.et.index_for(0x80))

    def test_chain_parsing(self):
        self.assertEqual(self.et.chain_for("2:Music Delay"), 2)
        self.assertEqual(self.et.chain_for("1:Mic Echo"), 1)
        # The superscript is not academic: str.isdigit() accepts it and int()
        # rejects it, so the old guard raised ValueError on a garbled name.
        for bad in (None, "", "x", "Music Delay", ":Music", "\u00b2:x", "\u2075:y"):
            self.assertIsNone(self.et.chain_for(bad))

    def test_device_names_asks_once_per_address(self):
        class Counting:
            def __init__(self):
                self.calls = 0

            def effect_name(self, i):
                self.calls += 1
                return f"2:Node {i}"

        dev = Counting()
        names = self.et.DeviceNames(dev)
        self.assertEqual(names.get(0x81), "2:Node 0")
        self.assertEqual(names.get(0x81), "2:Node 0")
        self.assertEqual(names.get(0x82), "2:Node 1")
        # Cached: a watch loop must not re-read a node it has already named.
        self.assertEqual(dev.calls, 2)

    def test_device_names_out_of_range_is_none_without_a_read(self):
        class Exploding:
            def effect_name(self, i):
                raise AssertionError("must not read an out-of-range node")

        names = self.et.DeviceNames(Exploding())
        self.assertIsNone(names.get(0xB7))


if __name__ == "__main__":
    unittest.main(verbosity=2)
