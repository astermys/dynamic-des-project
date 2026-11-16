import os
import unittest

from ddes.bitops import from_bits, mask
from ddes.p2_key_schedule import (SEMI_WEAK_KEYS, WEAK_KEYS, generate_key_schedule,
                                  has_odd_parity, is_semi_weak_key, is_weak_key,
                                  round_keys, set_odd_parity)
from ddes.tables import PC1, PC2

KEY = bytes.fromhex("133457799BBCDFF1")


class TestProcess2(unittest.TestCase):
    def test_known_vector_intermediates(self):
        ks = generate_key_schedule(KEY)
        self.assertEqual(ks.k_plus, from_bits(
            "1111000 0110011 0010101 0101111 0101010 1011001 1001111 0001111"))
        self.assertEqual(ks.c[0], from_bits("1111000011001100101010101111"))
        self.assertEqual(ks.d[0], from_bits("0101010101100110011110001111"))
        self.assertEqual(ks.c[1], from_bits("1110000110011001010101011111"))
        self.assertEqual(ks.d[1], from_bits("1010101011001100111100011110"))

    def test_known_vector_round_keys(self):
        ks = generate_key_schedule(KEY)
        self.assertEqual(ks.round_key(1), 0x1B02EFFC7072)
        self.assertEqual(ks.round_key(16), 0xCB3D8B0E17F5)
        self.assertEqual(len(ks.round_keys), 16)
        self.assertTrue(all(0 <= k <= mask(48) for k in ks.round_keys))

    def test_total_rotation_returns_to_start(self):
        ks = generate_key_schedule(os.urandom(8))
        self.assertEqual(ks.c[16], ks.c[0])
        self.assertEqual(ks.d[16], ks.d[0])

    def test_complementation_property(self):
        for _ in range(50):
            k = int.from_bytes(os.urandom(8), "big")
            a = generate_key_schedule(k).round_keys
            b = generate_key_schedule(k ^ mask(64)).round_keys
            self.assertTrue(all(x ^ y == mask(48) for x, y in zip(a, b)))

    def test_parity_bits_do_not_affect_schedule(self):
        for _ in range(50):
            k = int.from_bytes(os.urandom(8), "big")
            flipped = k ^ 0x0101010101010101
            self.assertEqual(round_keys(k), round_keys(flipped))

    def test_parity_helpers(self):
        self.assertTrue(has_odd_parity(KEY))
        fixed = set_odd_parity(bytes(8))
        self.assertTrue(has_odd_parity(fixed))
        self.assertEqual(set_odd_parity(KEY), KEY)
        with self.assertRaises(ValueError):
            generate_key_schedule(bytes(8), require_odd_parity=True)

    def test_weak_keys_have_identical_round_keys(self):
        for w in WEAK_KEYS:
            self.assertTrue(is_weak_key(w))
            ks = generate_key_schedule(w).round_keys
            self.assertEqual(len(set(ks)), 1)
            with self.assertRaises(ValueError):
                generate_key_schedule(w, reject_weak=True)
        self.assertFalse(is_weak_key(KEY))

    def test_semi_weak_pairs_reverse_each_other(self):
        for i in range(0, len(SEMI_WEAK_KEYS), 2):
            a, b = SEMI_WEAK_KEYS[i], SEMI_WEAK_KEYS[i + 1]
            self.assertTrue(is_semi_weak_key(a))
            ka = generate_key_schedule(a).round_keys
            kb = generate_key_schedule(b).round_keys
            self.assertEqual(ka, kb[::-1])

    def test_key_bit_usage_in_expected_range(self):
        usage = generate_key_schedule(KEY).key_bit_usage()
        self.assertEqual(len(usage), 56)
        self.assertTrue(all(12 <= u <= 15 for u in usage.values()), usage)

    def test_pc2_drops_eight_bits(self):
        self.assertEqual(set(range(1, 57)) - set(PC2),
                         {9, 18, 22, 25, 35, 38, 43, 54})

    def test_bad_keys(self):
        with self.assertRaises(ValueError):
            generate_key_schedule(b"short")
        with self.assertRaises(ValueError):
            generate_key_schedule(1 << 64)


if __name__ == "__main__":
    unittest.main()
