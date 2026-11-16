import unittest

from ddes.cipher import DynamicDES
from ddes.p3_lfsr import seed_from_bits
from ddes.security import (avalanche_progression, configuration_audit,
                           hamming_isometry_row_perms, key_seed_avalanche,
                           recover_seed, reach_ddt, sac_matrix,
                           seed_schedule_injectivity, seed_search_rate,
                           verify_property_preserving_knobs)
from ddes.p4_control import ControlWord
from ddes.p5_analysis import sbox_function

KEY = "133457799BBCDFF1"
SEED = seed_from_bits("1100 1010 1011 0011")


class TestDiffusion(unittest.TestCase):
    def test_avalanche_progression_reaches_full_diffusion(self):
        for des in (DynamicDES.from_hex(KEY, None, static=True),
                    DynamicDES.from_hex(KEY, "CAB3")):
            prog = avalanche_progression(des, samples=120)
            self.assertEqual(len(prog), 16)
            self.assertLess(prog[0], prog[3])
            self.assertLess(prog[3], prog[7])
            self.assertTrue(all(28 <= p <= 36 for p in prog[8:]), prog)

    def test_sac_no_gross_bias(self):
        for des in (DynamicDES.from_hex(KEY, None, static=True),
                    DynamicDES.from_hex(KEY, "CAB3")):
            r = sac_matrix(des, samples_per_bit=40)
            self.assertAlmostEqual(r["mean_probability"], 0.5, delta=0.01)
            self.assertLess(r["fraction_beyond_3.5_sigma"], 0.01, r)

    def test_key_and_seed_sensitivity(self):
        r = key_seed_avalanche(KEY, SEED, samples=6)
        self.assertTrue(28 <= r["mean_bits_changed_per_key_bit_flip"] <= 36)
        self.assertTrue(28 <= r["mean_bits_changed_per_seed_bit_flip"] <= 36)


class TestSeed(unittest.TestCase):
    def test_distinct_seeds_give_distinct_schedules(self):
        tried, distinct = seed_schedule_injectivity(limit=2000)
        self.assertEqual(tried, distinct)

    def test_known_key_seed_recovery(self):
        key = bytes.fromhex(KEY)
        pt = 0x0123456789ABCDEF
        ct = DynamicDES(key, SEED).encrypt_block(pt)
        hits = recover_seed(key, pt, ct, candidates=range(SEED - 60, SEED + 60))
        self.assertEqual(hits, [SEED])

    def test_search_rate_sane(self):
        r = seed_search_rate(bytes.fromhex(KEY), trials=30)
        self.assertGreater(r["seconds_per_candidate"], 0)


class TestConfigurationAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = configuration_audit()

    def test_static_reference_values(self):
        self.assertEqual(self.audit["static_reach_per_box"], [14, 16, 14, 16, 16, 16, 16, 16])
        self.assertEqual(reach_ddt(sbox_function(0, ControlWord(0, 0, 0, 0))), 14)

    def test_counts(self):
        a = self.audit
        self.assertEqual(a["configs"], 3072)
        self.assertEqual(sum(a["worst_box_histogram"].values()), 3072)
        self.assertEqual(len(a["criterion_ok"]), 16)

    def test_only_t0_with_shift_0_or_8_keeps_criterion(self):
        a = self.audit
        self.assertEqual(a["criterion_ok_tables"], [0])
        self.assertEqual(a["criterion_ok_shifts"], [0, 8])

    def test_criterion_preserving_row_perms_are_the_square_automorphisms(self):
        self.assertEqual(self.audit["criterion_ok_row_perms"], hamming_isometry_row_perms())
        self.assertEqual(len(hamming_isometry_row_perms()), 8)

    def test_property_preserving_knobs_do_not_degrade_any_sbox(self):
        r = verify_property_preserving_knobs()
        self.assertEqual(r["functions_checked"], 8 * 8 * 16 * 4)
        self.assertEqual(r["functions_degraded"], 0)


if __name__ == "__main__":
    unittest.main()
