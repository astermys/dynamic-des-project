import os
import unittest

from ddes.bitops import from_bits
from ddes.p1_input_ip import (apply_ip, final_permutation, initial_permutation,
                              ip_bit_map, pkcs7_pad, pkcs7_unpad,
                              process_input, to_blocks, undo_ip)
from ddes.tables import FP, IP


class TestProcess1(unittest.TestCase):
    def test_known_vector(self):
        # Standard worked DES example: M = 0123456789ABCDEF
        r = apply_ip(0x0123456789ABCDEF)
        self.assertEqual(r.permuted, 0xCC00CCFFF0AAF0AA)
        self.assertEqual(r.l0, 0xCC00CCFF)
        self.assertEqual(r.r0, 0xF0AAF0AA)

    def test_ip_fp_are_inverse_permutations(self):
        for _ in range(500):
            x = int.from_bytes(os.urandom(8), "big")
            self.assertEqual(final_permutation(initial_permutation(x)), x)
            self.assertEqual(initial_permutation(final_permutation(x)), x)
            self.assertEqual(undo_ip(apply_ip(x)), x)

    def test_ip_is_linear_over_xor(self):
        for _ in range(100):
            a, b = (int.from_bytes(os.urandom(8), "big") for _ in range(2))
            self.assertEqual(initial_permutation(a ^ b),
                             initial_permutation(a) ^ initial_permutation(b))

    def test_single_bit_moves_to_mapped_position(self):
        for src, out in ip_bit_map().items():
            p = initial_permutation(1 << (64 - src))
            self.assertEqual(p, 1 << (64 - out))

    def test_edge_values(self):
        self.assertEqual(initial_permutation(0), 0)
        self.assertEqual(initial_permutation((1 << 64) - 1), (1 << 64) - 1)
        with self.assertRaises(ValueError):
            initial_permutation(1 << 64)
        with self.assertRaises(ValueError):
            initial_permutation(-1)

    def test_padding_and_blocks(self):
        for n in range(0, 25):
            d = os.urandom(n)
            p = pkcs7_pad(d)
            self.assertEqual(len(p) % 8, 0)
            self.assertEqual(pkcs7_unpad(p), d)
        self.assertEqual(len(pkcs7_pad(b"12345678")), 16)
        with self.assertRaises(ValueError):
            to_blocks(b"short")
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"\x00" * 8)

    def test_process_input_pipeline(self):
        res = process_input(b"hello dynamic des")
        self.assertEqual(len(res), 3)           # 17 bytes + padding -> 24 bytes
        self.assertEqual(undo_ip(res[0]), int.from_bytes(b"hello dy", "big"))

    def test_tables_exposed_are_consistent(self):
        self.assertEqual(len(IP), 64)
        self.assertEqual(len(FP), 64)


if __name__ == "__main__":
    unittest.main()
