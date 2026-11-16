import os
import unittest

from ddes.cipher import DynamicDES
from ddes.hardened import (D4_ROW_PERMS, FIELDS_H, STATIC_HARDENED, WORD_BITS_H,
                           HardenedControlSchedule, HardenedControlWord, HardenedDES,
                           hardened_sbox, hardened_sbox_trace)
from ddes.p3_lfsr import FibonacciLFSR, seed_from_bits
from ddes.p5_analysis import sbox_function
from ddes.p5_sboxes import STATIC_CONTROL, dynamic_sbox
from ddes.p4_control import ControlWord
from ddes.security import (avalanche_progression, compare_sbox_quality,
                           hamming_isometry_row_perms, hardened_distinct_functions,
                           lat_max, reach_ddt, sac_matrix, verify_hardened_invariants)
from ddes.p4_control import ROW_PERMS

KEY = "133457799BBCDFF1"
SEED = seed_from_bits("1100 1010 1011 0011")


class TestControlWord(unittest.TestCase):
    def test_layout_is_12_bits_with_uniform_fields(self):
        self.assertEqual(WORD_BITS_H, 12)
        self.assertEqual([w for _, w in FIELDS_H], [3, 3, 4, 2])

    def test_bijection_over_all_4096_words(self):
        for v in range(1 << 12):
            w = HardenedControlWord.from_int(v)
            self.assertEqual(w.to_int(), v)

    def test_validation(self):
        for args in [(8, 0, 0, 0), (0, 8, 0, 0), (0, 0, 16, 0), (0, 0, 0, 4), (-1, 0, 0, 0)]:
            with self.assertRaises(ValueError):
                HardenedControlWord(*args)
        with self.assertRaises(ValueError):
            HardenedControlWord.from_int(1 << 12)

    def test_schedule_is_consecutive_12_bit_stream_chunks(self):
        bits = "".join(map(str, FibonacciLFSR(SEED).bits(12 * 16)))
        s = HardenedControlSchedule.from_seed(SEED)
        for i, w in enumerate(s.words):
            self.assertEqual(w.to_bits(grouped=False), bits[12 * i:12 * i + 12])
        self.assertEqual(s.bits_consumed, 192)


class TestD4(unittest.TestCase):
    def test_d4_matches_security_module_and_is_a_group(self):
        self.assertEqual(len(D4_ROW_PERMS), 8)
        self.assertEqual([ROW_PERMS[i] for i in hamming_isometry_row_perms()], list(D4_ROW_PERMS))
        group = set(D4_ROW_PERMS)
        for p in group:
            for q in group:
                self.assertIn(tuple(p[q[i]] for i in range(4)), group)      # closure
        self.assertEqual(D4_ROW_PERMS[0], (0, 1, 2, 3))


class TestSbox(unittest.TestCase):
    def test_static_equals_des_sbox(self):
        for box in range(8):
            for six in range(64):
                self.assertEqual(hardened_sbox(six, box, STATIC_HARDENED),
                                 dynamic_sbox(six, box, STATIC_CONTROL))

    def test_offset_selects_genuine_des_sbox(self):
        for six in range(64):
            self.assertEqual(hardened_sbox(six, 2, HardenedControlWord(3, 0, 0, 0)),
                             dynamic_sbox(six, 5, STATIC_CONTROL))

    def test_trace_matches_fast_path(self):
        for six in range(0, 64, 3):
            c = HardenedControlWord(six % 8, (six * 3) % 8, six % 16, six % 4)
            self.assertEqual(hardened_sbox_trace(six, six % 8, c).out,
                             hardened_sbox(six, six % 8, c))

    def test_every_hardened_function_has_unchanged_quality_metrics(self):
        r = verify_hardened_invariants(boxes=[0, 4])
        self.assertEqual(r["functions_checked"], 2 * 8 * 16 * 4)
        self.assertEqual(r["functions_with_changed_metrics"], 0)

    def test_lat_reference_value_and_original_design_can_be_worse(self):
        base = lat_max(sbox_function(4, ControlWord(0, 0, 0, 0)))
        self.assertGreater(base, 0)
        worse = [lat_max(sbox_function(4, ControlWord(t, 0, 0, 0))) for t in range(1, 8)]
        self.assertTrue(any(w != base for w in worse))     # relabelled tables change the LAT

    def test_original_design_degrades_often_hardened_never(self):
        r = compare_sbox_quality(samples=25)
        self.assertGreater(r["violates_single_bit_criterion"], 0.5)
        self.assertGreater(r["worse_differential"], 0.2)

    def test_distinct_function_count(self):
        d = hardened_distinct_functions(0)
        self.assertEqual(d["configs"], 4096)
        self.assertGreater(d["distinct_functions"], 1000)


class TestCipher(unittest.TestCase):
    def test_static_mode_is_standard_des(self):
        for key, pt, ct in [("133457799BBCDFF1", 0x0123456789ABCDEF, 0x85E813540F0AB405),
                            ("0101010101010101", 0x8000000000000000, 0x95F8A5E5DD31D900),
                            ("8001010101010101", 0x0, 0x95A8D72813DAA94D)]:
            d = HardenedDES.from_hex(key, None, static=True, reject_weak=False)
            self.assertEqual(d.encrypt_block(pt), ct)
            self.assertEqual(d.decrypt_block(ct), pt)

    def test_roundtrip_and_differs_from_standard_and_original(self):
        d = HardenedDES.from_hex(KEY, "CAB3")
        for _ in range(100):
            m = int.from_bytes(os.urandom(8), "big")
            self.assertEqual(d.decrypt_block(d.encrypt_block(m)), m)
        m = 0x0123456789ABCDEF
        self.assertNotEqual(d.encrypt_block(m), 0x85E813540F0AB405)
        self.assertNotEqual(d.encrypt_block(m), DynamicDES.from_hex(KEY, "CAB3").encrypt_block(m))

    def test_wrong_seed_or_order_fails(self):
        d = HardenedDES.from_hex(KEY, "CAB3")
        c = d.encrypt_block(0x1122334455667788)
        self.assertNotEqual(HardenedDES.from_hex(KEY, "CAB2").decrypt_block(c), 0x1122334455667788)

    def test_inherits_modes_and_authentication(self):
        d = HardenedDES.from_hex(KEY, "CAB3")
        for n in (0, 5, 8, 21):
            m = os.urandom(n)
            self.assertEqual(d.decrypt_cbc(d.encrypt_cbc(m)), m)
            self.assertEqual(d.decrypt_ctr(d.encrypt_ctr(m)), m)
        sealed = d.seal(b"payload", b"mac key")
        self.assertEqual(d.open(sealed, b"mac key"), b"payload")
        with self.assertRaises(ValueError):
            d.open(sealed[:-1] + bytes([sealed[-1] ^ 1]), b"mac key")

    def test_input_validation(self):
        with self.assertRaises(ValueError):
            HardenedDES.from_hex(KEY, None)
        with self.assertRaises(ValueError):
            HardenedDES.from_hex("0101010101010101", "CAB3")
        d = HardenedDES.from_hex(KEY, "CAB3")
        with self.assertRaises(ValueError):
            d.trace_sbox(0, 0, 0)

    def test_trace_consistency(self):
        d = HardenedDES.from_hex(KEY, "CAB3")
        t = d.trace_block(0x0123456789ABCDEF)
        self.assertEqual(t.output, d.encrypt_block(0x0123456789ABCDEF))
        self.assertEqual(len(t.rounds), 16)
        self.assertEqual(d.trace_block(t.output, decrypt=True).output, 0x0123456789ABCDEF)
        self.assertEqual(d.trace_sbox(t.rounds[0].sixes[0], 0, 1).out, t.rounds[0].sbox_outs[0])

    def test_diffusion_and_sac(self):
        d = HardenedDES.from_hex(KEY, "CAB3")
        prog = avalanche_progression(d, samples=120)
        self.assertTrue(all(28 <= p <= 36 for p in prog[8:]), prog)
        r = sac_matrix(d, samples_per_bit=40)
        self.assertAlmostEqual(r["mean_probability"], 0.5, delta=0.01)
        self.assertLess(r["fraction_beyond_3.5_sigma"], 0.01)


if __name__ == "__main__":
    unittest.main()
