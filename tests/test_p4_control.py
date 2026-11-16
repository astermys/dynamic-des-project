import unittest
from collections import Counter

from ddes.p3_lfsr import FibonacciLFSR, seed_from_bits
from ddes.p4_analysis import (config_entropy_per_round, empirical_field_report,
                              min_entropy, probability_standard_config,
                              row_perm_distribution, shannon_entropy,
                              tv_distance_from_uniform)
from ddes.p4_control import (ROW_PERMS, WORD_BITS, ControlSchedule, ControlWord,
                             ControlWordGenerator, RowPermPolicy, row_permutation)

SEED = seed_from_bits("1100 1010 1011 0011")
MOD24, REJECT = RowPermPolicy.MOD24, RowPermPolicy.REJECT


class TestControlWord(unittest.TestCase):
    def test_image_round1_example(self):
        w = ControlWord.from_bits("101 10101 0110 10")
        self.assertEqual((w.table, w.row_perm, w.col_shift, w.out_rot), (5, 21, 6, 2))
        self.assertEqual(w.to_bits(), "101 10101 0110 10")
        self.assertTrue(w.describe().startswith("T5 + RowPerm#21"))

    def test_bijection_over_all_14_bit_words(self):
        for v in range(1 << WORD_BITS):
            w = ControlWord.from_int(v)
            self.assertEqual(w.to_int(), v)
            self.assertEqual(ControlWord.from_bits(w.to_bits()), w)

    def test_field_bit_positions(self):
        self.assertEqual(ControlWord(7, 0, 0, 0).to_int(), 0b111_00000_0000_00)
        self.assertEqual(ControlWord(0, 31, 0, 0).to_int(), 0b000_11111_0000_00)
        self.assertEqual(ControlWord(0, 0, 15, 0).to_int(), 0b000_00000_1111_00)
        self.assertEqual(ControlWord(0, 0, 0, 3).to_int(), 0b000_00000_0000_11)

    def test_validation(self):
        for args in [(8, 0, 0, 0), (0, 32, 0, 0), (0, 0, 16, 0), (0, 0, 0, 4), (-1, 0, 0, 0)]:
            with self.assertRaises(ValueError):
                ControlWord(*args)
        with self.assertRaises(ValueError):
            ControlWord.from_int(1 << 14)
        with self.assertRaises(ValueError):
            ControlWord.from_bits("101")


class TestRowPermPolicy(unittest.TestCase):
    def test_24_distinct_permutations(self):
        self.assertEqual(len(ROW_PERMS), 24)
        self.assertEqual(len(set(ROW_PERMS)), 24)
        self.assertTrue(all(sorted(p) == [0, 1, 2, 3] for p in ROW_PERMS))
        self.assertEqual(ROW_PERMS[0], (0, 1, 2, 3))

    def test_mod24_aliasing(self):
        for c in range(8):
            self.assertEqual(row_permutation(c, MOD24), row_permutation(c + 24, MOD24))
        self.assertEqual(Counter(row_permutation(c, MOD24) for c in range(32)).most_common(1)[0][1], 2)

    def test_reject_policy_refuses_high_codes(self):
        with self.assertRaises(ValueError):
            row_permutation(24, REJECT)
        self.assertEqual(row_permutation(23, REJECT), ROW_PERMS[23])


class TestGenerator(unittest.TestCase):
    def test_mod24_words_are_consecutive_14_bit_chunks(self):
        bits = "".join(map(str, FibonacciLFSR(SEED).bits(14 * 16)))
        sched = ControlSchedule.from_seed(SEED)
        for i, w in enumerate(sched.words):
            self.assertEqual(w.to_bits(grouped=False), bits[14 * i:14 * i + 14])
        self.assertEqual(sched.bits_consumed, 14 * 16)

    def test_round1_for_diagram_seed(self):
        w = ControlSchedule.from_seed(SEED).for_round(1)
        self.assertEqual(w.to_bits(grouped=False), "11001010101100")   # first 14 stream bits

    def test_deterministic_and_seed_dependent(self):
        a = ControlSchedule.from_seed(SEED)
        self.assertEqual(a, ControlSchedule.from_seed(SEED))
        self.assertNotEqual(a.words, ControlSchedule.from_seed(SEED ^ 1).words)

    def test_decryption_order_reversed(self):
        s = ControlSchedule.from_seed(SEED)
        self.assertEqual(s.decryption_order[0], s.for_round(16))
        self.assertEqual(s.decryption_order[-1], s.for_round(1))
        with self.assertRaises(IndexError):
            s.for_round(0)
        with self.assertRaises(IndexError):
            s.for_round(17)

    def test_reject_policy_codes_valid_and_consumption_variable(self):
        s = ControlSchedule.from_seed(SEED, rounds=500, policy=REJECT)
        self.assertTrue(all(w.row_perm < 24 for w in s.words))
        self.assertGreater(s.bits_consumed, 14 * 500)              # extra bits for redraws

    def test_zero_seed_rejected(self):
        with self.assertRaises(ValueError):
            ControlWordGenerator(0)


class TestAnalysis(unittest.TestCase):
    def test_entropy_numbers(self):
        d = row_perm_distribution(MOD24)
        self.assertAlmostEqual(sum(d.values()), 1.0)
        self.assertAlmostEqual(shannon_entropy(d), 4.5, places=9)
        self.assertAlmostEqual(min_entropy(d), 4.0, places=9)
        self.assertAlmostEqual(tv_distance_from_uniform(d), 1 / 6, places=9)
        du = row_perm_distribution(REJECT)
        self.assertAlmostEqual(tv_distance_from_uniform(du), 0.0)
        self.assertAlmostEqual(config_entropy_per_round(MOD24), 13.5)

    def test_standard_config_probability(self):
        self.assertAlmostEqual(probability_standard_config(MOD24), 1 / 8192)
        self.assertAlmostEqual(probability_standard_config(REJECT), 1 / 12288)

    def test_empirical_fields_consistent_with_expectation(self):
        for policy in (MOD24, REJECT):
            rep = empirical_field_report(SEED, 4000, policy)
            for name in ("table", "row_perm", "col_shift", "out_rot"):
                stat, df, p = rep[name]
                self.assertGreater(p, 0.001, (policy, name, stat, df, p))


if __name__ == "__main__":
    unittest.main()
