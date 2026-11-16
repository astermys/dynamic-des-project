import unittest
from ddes.hardened import HardenedDES

class TestMine(unittest.TestCase):

    def test_roundtrip(self):
        d = HardenedDES.from_hex('133457799BBCDFF1', 'BEEF')

        self.assertEqual(
            d.decrypt_block(d.encrypt_block(42)),
            42
        )

if __name__ == '__main__':
    unittest.main()