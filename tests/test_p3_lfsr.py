import unittest

from ddes.p3_analysis import (berlekamp_massey, golomb_report, nist_monobit,
                              nist_runs, predict_from_recurrence)
from ddes.p3_lfsr import (DEFAULT_POLY, PERIOD, ControlStream, FibonacciLFSR,
                          GaloisLFSR, Polynomial, derive_seed, seed_from_bits,
                          validate_seed)

SEED = seed_from_bits("1100 1010 1011 0011")     # example seed from the diagram


class TestPolynomial(unittest.TestCase):
    def test_default_poly_is_primitive(self):
        self.assertTrue(DEFAULT_POLY.is_primitive())
        self.assertTrue(DEFAULT_POLY.reciprocal().is_primitive())
        self.assertEqual(str(DEFAULT_POLY), "x^16 + x^14 + x^13 + x^11 + 1")

    def test_non_primitive_detected(self):
        self.assertFalse(Polynomial((16, 0)).is_primitive())       # x^16 + 1
        self.assertFalse(Polynomial((4, 2, 0)).is_primitive())     # (x^2+x+1)^2

    def test_known_small_primitive(self):
        self.assertTrue(Polynomial((4, 1, 0)).is_primitive())

    def test_validation(self):
        with self.assertRaises(ValueError):
            Polynomial((16, 14, 13, 11))          # missing constant term
        with self.assertRaises(ValueError):
            Polynomial((11, 13, 14, 16, 0))       # not descending


class TestSeed(unittest.TestCase):
    def test_seed_validation(self):
        for bad in (0, 1 << 16, -5):
            with self.assertRaises(ValueError):
                validate_seed(bad)
        with self.assertRaises(ValueError):
            seed_from_bits("1010")
        self.assertEqual(SEED, 0xCAB3)

    def test_derive_seed_deterministic_nonzero(self):
        a = derive_seed(b"\x01" * 8)
        self.assertEqual(a, derive_seed(b"\x01" * 8))
        self.assertNotEqual(a, derive_seed(b"\x02" * 8))
        self.assertTrue(1 <= a <= 0xFFFF)


class TestLFSR(unittest.TestCase):
    def test_first_16_outputs_equal_seed(self):
        bits = FibonacciLFSR(SEED).bits(16)
        self.assertEqual(int("".join(map(str, bits)), 2), SEED)

    def test_maximal_period(self):
        self.assertEqual(FibonacciLFSR(SEED).measure_period(), PERIOD)
        self.assertEqual(FibonacciLFSR(1).measure_period(), PERIOD)

    def test_deterministic_and_seed_sensitive(self):
        self.assertEqual(FibonacciLFSR(SEED).bits(200), FibonacciLFSR(SEED).bits(200))
        self.assertNotEqual(FibonacciLFSR(SEED).bits(200), FibonacciLFSR(SEED ^ 1).bits(200))

    def test_clone_independent(self):
        a = FibonacciLFSR(SEED)
        a.bits(10)
        b = a.clone()
        self.assertEqual(a.bits(50), b.bits(50))

    def test_recurrence_polynomial_is_reciprocal(self):
        self.assertEqual(FibonacciLFSR(SEED).recurrence_polynomial(), DEFAULT_POLY.reciprocal())

    def test_galois_is_cyclic_shift_of_fibonacci(self):
        f = FibonacciLFSR(SEED).bits(PERIOD)
        g = GaloisLFSR(SEED).bits(64)
        fs = "".join(map(str, f * 2))
        self.assertIn("".join(map(str, g)), fs)
        self.assertEqual(GaloisLFSR(SEED).bits(PERIOD).count(1), 32768)


class TestStatistics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.period_bits = FibonacciLFSR(SEED).bits(PERIOD)

    def test_golomb_balance_runs_autocorrelation(self):
        r = golomb_report(self.period_bits, autocorr_step=61)
        self.assertEqual(r["ones"], 32768)
        self.assertEqual(r["zeros"], 32767)
        self.assertEqual(r["total_runs"], 32768)
        rl = r["runs_by_length"]
        for k in range(1, 15):                 # 2^(n-k-1) runs of each length k
            self.assertEqual(rl[k], 2 ** (15 - k), k)
        self.assertEqual(rl[15], 1)
        self.assertEqual(rl[16], 1)
        self.assertEqual(r["autocorrelation_values"], [-1])

    def test_nist_subset_passes(self):
        sample = self.period_bits[:20000]
        self.assertGreater(nist_monobit(sample), 0.01)
        self.assertGreater(nist_runs(sample), 0.01)

    def test_nist_rejects_biased_stream(self):
        self.assertLess(nist_monobit([1] * 900 + [0] * 100), 0.01)


class TestLinearComplexity(unittest.TestCase):
    def test_bm_recovers_degree_16(self):
        bits = FibonacciLFSR(SEED).bits(200)
        L, C = berlekamp_massey(bits)
        self.assertEqual(L, 16)

    def test_32_bits_predict_the_whole_stream(self):
        bits = FibonacciLFSR(SEED).bits(1000)
        L, C = berlekamp_massey(bits[:32])
        self.assertEqual(L, 16)
        self.assertEqual(predict_from_recurrence(bits[:32], C, 968), bits[32:])

    def test_bm_on_period_4_sequence(self):
        # 1,0,0,1,1,0,0,1,... follows s[n] = s[n-1] ^ s[n-2] ... verified by prediction
        seq = [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0]
        L, C = berlekamp_massey(seq)
        self.assertEqual(predict_from_recurrence(seq[:2 * L], C, len(seq) - 2 * L),
                         seq[2 * L:])

    def test_constant_zero_has_complexity_zero(self):
        self.assertEqual(berlekamp_massey([0] * 20)[0], 0)


class TestControlStream(unittest.TestCase):
    def test_sequential_consumption(self):
        a, b = ControlStream(SEED), FibonacciLFSR(SEED)
        self.assertEqual(a.read_bits(14), "".join(map(str, b.bits(14))))
        self.assertEqual(a.consumed, 14)
        self.assertEqual(a.read_int(14), int("".join(map(str, b.bits(14))), 2))

    def test_reset_and_snapshot(self):
        s = ControlStream(SEED)
        first = s.read_bits(30)
        s.reset()
        self.assertEqual(s.read_bits(30), first)
        snap = s.snapshot()
        x = s.read_bits(20)
        s.restore(snap)
        self.assertEqual(s.read_bits(20), x)


if __name__ == "__main__":
    unittest.main()
