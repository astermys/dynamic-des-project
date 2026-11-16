import os
import unittest

from ddes.bitops import join
from ddes.p1_input_ip import apply_ip, final_permutation
from ddes.p2_key_schedule import generate_key_schedule
from ddes.p3_lfsr import seed_from_bits
from ddes.p4_control import ControlSchedule, ControlWord, RowPermPolicy
from ddes.p5_analysis import (ddt_max, distinct_function_stats, rows_are_bijective,
                              sbox_function)
from ddes.p5_round import expand, feistel_round, round_function, run_rounds
from ddes.p5_sboxes import (STATIC_CONTROL, TABLE_SETS, dynamic_sbox,
                            dynamic_sbox_trace, split_six, value_permutation)
from ddes.tables import DES_SBOXES

KEY = bytes.fromhex("133457799BBCDFF1")
SEED = seed_from_bits("1100 1010 1011 0011")
PLAIN = 0x0123456789ABCDEF
STATIC16 = [STATIC_CONTROL] * 16


def crypt(block, keys, controls, policy=RowPermPolicy.MOD24):
    ip = apply_ip(block)
    res = run_rounds(ip.l0, ip.r0, keys, controls, policy)
    return final_permutation(res.preoutput)


class TestTables(unittest.TestCase):
    def test_table_set_structure(self):
        self.assertEqual(TABLE_SETS[0], DES_SBOXES)
        self.assertEqual(len({ts for ts in TABLE_SETS}), 8)         # all sets differ
        for ts in TABLE_SETS:
            for box in ts:
                for row in box:
                    self.assertEqual(sorted(row), list(range(16)))

    def test_value_permutations_deterministic(self):
        self.assertEqual(value_permutation(0), tuple(range(16)))
        self.assertEqual(value_permutation(3), value_permutation(3))
        for k in range(8):
            self.assertEqual(sorted(value_permutation(k)), list(range(16)))


class TestDynamicSbox(unittest.TestCase):
    def test_row_col_extraction(self):
        self.assertEqual(split_six(0b011011), (1, 13))
        self.assertEqual(split_six(0b011000), (0, 12))
        self.assertEqual(split_six(0b100001), (3, 0))

    def test_static_matches_des_known_values(self):
        self.assertEqual(dynamic_sbox(0b011000, 0, STATIC_CONTROL), 0b0101)   # classic S1 example
        self.assertEqual(dynamic_sbox(0b011011, 0, STATIC_CONTROL), 5)

    def test_each_stage_in_isolation(self):
        base = DES_SBOXES[0]
        six = 0b011011                                  # row 1, col 13
        self.assertEqual(dynamic_sbox(six, 0, ControlWord(0, 0, 3, 0)), base[1][(13 + 3) % 16])
        self.assertEqual(dynamic_sbox(six, 0, ControlWord(0, 0, 0, 2)),
                         ((base[1][13] << 2) | (base[1][13] >> 2)) & 0xF)
        self.assertEqual(dynamic_sbox(six, 0, ControlWord(0, 1, 0, 0)), base[1][13])  # perm 1 swaps rows 2,3 only
        self.assertEqual(dynamic_sbox(0b100001, 0, ControlWord(0, 1, 0, 0)), base[2][0])
        self.assertEqual(dynamic_sbox(six, 0, ControlWord(1, 0, 0, 0)),
                         TABLE_SETS[1][0][1][13])

    def test_trace_agrees_with_fast_path(self):
        for t in range(8):
            for six in range(0, 64, 5):
                c = ControlWord(t, (six * 7) % 32, six % 16, six % 4)
                self.assertEqual(dynamic_sbox_trace(six, six % 8, c).out,
                                 dynamic_sbox(six, six % 8, c))

    def test_reject_policy_refuses_code_24(self):
        with self.assertRaises(ValueError):
            dynamic_sbox(0, 0, ControlWord(0, 24, 0, 0), RowPermPolicy.REJECT)


class TestRoundAgainstKnownDES(unittest.TestCase):
    """Worked example: key 133457799BBCDFF1, plaintext 0123456789ABCDEF."""

    def test_round1_intermediates(self):
        ks = generate_key_schedule(KEY)
        ip = apply_ip(PLAIN)
        self.assertEqual(expand(ip.r0), 0x7A15557A1555)
        l, r, t = feistel_round(ip.l0, ip.r0, ks.round_key(1), STATIC_CONTROL, index=1)
        self.assertEqual(t.xored, 0x6117BA866527)
        self.assertEqual(t.s_out, 0x5C82B597)
        self.assertEqual(t.f_out, 0x234AA9BB)
        self.assertEqual((l, r), (0xF0AAF0AA, 0xEF4A6544))

    def test_full_static_cipher_matches_des_kat(self):
        ks = generate_key_schedule(KEY)
        self.assertEqual(crypt(PLAIN, ks.round_keys, STATIC16), 0x85E813540F0AB405)

    def test_static_decrypt_matches_kat(self):
        ks = generate_key_schedule(KEY)
        self.assertEqual(crypt(0x85E813540F0AB405, ks.decryption_order, STATIC16), PLAIN)


class TestDynamicCipher(unittest.TestCase):
    def setUp(self):
        self.ks = generate_key_schedule(KEY)
        self.cs = ControlSchedule.from_seed(SEED)

    def test_roundtrip_random_blocks(self):
        for _ in range(100):
            m = int.from_bytes(os.urandom(8), "big")
            c = crypt(m, self.ks.round_keys, self.cs.words)
            self.assertEqual(crypt(c, self.ks.decryption_order, self.cs.decryption_order), m)

    def test_roundtrip_reject_policy(self):
        cs = ControlSchedule.from_seed(SEED, policy=RowPermPolicy.REJECT)
        m = 0xDEADBEEFCAFEF00D
        c = crypt(m, self.ks.round_keys, cs.words, RowPermPolicy.REJECT)
        self.assertEqual(crypt(c, self.ks.decryption_order, cs.decryption_order,
                               RowPermPolicy.REJECT), m)

    def test_dynamic_differs_from_standard(self):
        self.assertNotEqual(crypt(PLAIN, self.ks.round_keys, self.cs.words), 0x85E813540F0AB405)

    def test_wrong_control_order_fails(self):
        c = crypt(PLAIN, self.ks.round_keys, self.cs.words)
        self.assertNotEqual(crypt(c, self.ks.decryption_order, self.cs.words), PLAIN)

    def test_wrong_seed_fails(self):
        c = crypt(PLAIN, self.ks.round_keys, self.cs.words)
        other = ControlSchedule.from_seed(SEED ^ 0x0100)
        self.assertNotEqual(crypt(c, self.ks.decryption_order, other.decryption_order), PLAIN)

    def test_avalanche_plaintext_bit(self):
        total = 0
        for bit in range(64):
            a = crypt(PLAIN, self.ks.round_keys, self.cs.words)
            b = crypt(PLAIN ^ (1 << bit), self.ks.round_keys, self.cs.words)
            total += bin(a ^ b).count("1")
        self.assertTrue(26 <= total / 64 <= 38, total / 64)

    def test_round_function_matches_feistel_round(self):
        ip = apply_ip(PLAIN)
        k, c = self.ks.round_key(2), self.cs.for_round(2)
        _, r, _ = feistel_round(ip.l0, ip.r0, k, c)
        self.assertEqual(r, ip.l0 ^ round_function(ip.r0, k, c))

    def test_traces_kept(self):
        ip = apply_ip(PLAIN)
        res = run_rounds(ip.l0, ip.r0, self.ks.round_keys, self.cs.words, keep_traces=True)
        self.assertEqual(len(res.traces), 16)
        self.assertEqual(res.traces[0].l_in, ip.l0)
        with self.assertRaises(ValueError):
            run_rounds(0, 0, self.ks.round_keys, self.cs.words[:5])


class TestConfigurationSpace(unittest.TestCase):
    def test_rows_stay_bijective_for_every_config_sample(self):
        for t in range(8):
            for rp in range(0, 24, 5):
                for cs in range(0, 16, 5):
                    for ro in range(4):
                        f = sbox_function(2, ControlWord(t, rp, cs, ro))
                        self.assertTrue(rows_are_bijective(f))

    def test_standard_sbox_ddt_max_is_16(self):
        self.assertEqual(ddt_max(sbox_function(0, STATIC_CONTROL)), 16)

    def test_distinct_functions_nontrivial(self):
        s = distinct_function_stats(0)
        self.assertEqual(s["configs"], 12288)
        self.assertGreater(s["distinct_functions"], 4000)


if __name__ == "__main__":
    unittest.main()
