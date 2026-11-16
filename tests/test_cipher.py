import contextlib
import io
import os
import unittest

from ddes.cipher import DynamicDES
from ddes.cli import main as cli_main
from ddes.p4_control import RowPermPolicy

KEY = "133457799BBCDFF1"
SEED = "CAB3"


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli_main(list(argv))
    return code, out.getvalue().strip(), err.getvalue().strip()


class TestKnownAnswers(unittest.TestCase):
    def test_standard_des_vectors(self):
        vectors = [
            ("133457799BBCDFF1", 0x0123456789ABCDEF, 0x85E813540F0AB405),
            ("0101010101010101", 0x8000000000000000, 0x95F8A5E5DD31D900),   # NBS VarTxt #1
            ("8001010101010101", 0x0000000000000000, 0x95A8D72813DAA94D),   # NBS VarKey #1
        ]
        for key, pt, ct in vectors:
            des = DynamicDES.from_hex(key, None, static=True, reject_weak=False)
            self.assertEqual(des.encrypt_block(pt), ct)
            self.assertEqual(des.decrypt_block(ct), pt)


class TestDynamicBlock(unittest.TestCase):
    def setUp(self):
        self.des = DynamicDES.from_hex(KEY, SEED)

    def test_roundtrip(self):
        for _ in range(100):
            m = int.from_bytes(os.urandom(8), "big")
            self.assertEqual(self.des.decrypt_block(self.des.encrypt_block(m)), m)

    def test_trace_consistent_with_fast_path(self):
        m = 0x0123456789ABCDEF
        t = self.des.trace_block(m)
        self.assertEqual(t.output, self.des.encrypt_block(m))
        self.assertEqual(len(t.rounds), 16)
        self.assertIn("Process 10", t.describe())
        self.assertEqual(self.des.trace_block(t.output, decrypt=True).output, m)

    def test_requires_seed_unless_static(self):
        with self.assertRaises(ValueError):
            DynamicDES.from_hex(KEY, None)
        with self.assertRaises(ValueError):
            DynamicDES.from_hex(KEY, "0")

    def test_weak_key_rejected_by_default(self):
        with self.assertRaises(ValueError):
            DynamicDES.from_hex("0101010101010101", SEED)

    def test_reject_policy_roundtrip(self):
        d = DynamicDES.from_hex(KEY, SEED, policy=RowPermPolicy.REJECT)
        m = 0xFEDCBA9876543210
        self.assertEqual(d.decrypt_block(d.encrypt_block(m)), m)

    def test_sbox_trace_matches_round_inputs(self):
        m = 0x0123456789ABCDEF
        t = self.des.trace_block(m).rounds[0]
        st = self.des.trace_sbox(t.sixes[0], 0, 1)
        self.assertEqual(st.out, t.sbox_outs[0])
        with self.assertRaises(ValueError):
            self.des.trace_sbox(0, 0, 17)


class TestModes(unittest.TestCase):
    def setUp(self):
        self.des = DynamicDES.from_hex(KEY, SEED)

    def test_cbc_roundtrip_all_small_lengths(self):
        for n in range(0, 41):
            m = os.urandom(n)
            self.assertEqual(self.des.decrypt_cbc(self.des.encrypt_cbc(m)), m)

    def test_ctr_roundtrip_and_length_preserved(self):
        for n in range(0, 41):
            m = os.urandom(n)
            blob = self.des.encrypt_ctr(m)
            self.assertEqual(len(blob), 8 + n)
            self.assertEqual(self.des.decrypt_ctr(blob), m)

    def test_iv_controls_determinism(self):
        iv = bytes(range(8))
        m = b"same message"
        self.assertEqual(self.des.encrypt_cbc(m, iv), self.des.encrypt_cbc(m, iv))
        self.assertNotEqual(self.des.encrypt_cbc(m), self.des.encrypt_cbc(m))   # random IVs

    def test_cbc_bit_flip_malleability(self):
        # Textbook CBC property: flipping a ciphertext bit garbles that block
        # and flips the same bit in the NEXT plaintext block. Hence seal().
        m = b"A" * 32
        blob = bytearray(self.des.encrypt_cbc(m, bytes(8)))
        blob[8 + 3] ^= 0x01
        pt = self.des.decrypt_cbc(bytes(blob))
        self.assertNotEqual(pt[:8], m[:8])
        expected = bytearray(m[8:16])
        expected[3] ^= 0x01
        self.assertEqual(pt[8:16], bytes(expected))
        self.assertEqual(pt[16:], m[16:])

    def test_bad_inputs(self):
        with self.assertRaises(ValueError):
            self.des.decrypt_cbc(b"short")
        with self.assertRaises(ValueError):
            self.des.encrypt_cbc(b"x", b"123")
        with self.assertRaises(ValueError):
            self.des.encrypt(b"x", mode="ecb")

    def test_wrong_seed_or_key_does_not_recover_plaintext(self):
        m = b"secret message!!"
        blob = self.des.encrypt_cbc(m)
        for other in (DynamicDES.from_hex(KEY, "CAB2"), DynamicDES.from_hex("0123456789ABCDEF"[::-1], SEED)):
            try:
                self.assertNotEqual(other.decrypt_cbc(blob), m)
            except ValueError:
                pass

    def test_seal_open_and_tamper(self):
        mk = b"independent mac key"
        sealed = self.des.seal(b"authenticated payload", mk)
        self.assertEqual(self.des.open(sealed, mk), b"authenticated payload")
        bad = bytearray(sealed)
        bad[10] ^= 1
        with self.assertRaises(ValueError):
            self.des.open(bytes(bad), mk)
        with self.assertRaises(ValueError):
            self.des.open(sealed, b"wrong key")
        s = self.des.seal(b"x" * 13, mk, "ctr")
        self.assertEqual(self.des.open(s, mk, "ctr"), b"x" * 13)


class TestCLI(unittest.TestCase):
    def test_block_static_kat(self):
        code, out, _ = run_cli("block", "--key", KEY, "--static", "--plain", "0123456789ABCDEF")
        self.assertEqual((code, out), (0, "85E813540F0AB405"))

    def test_dynamic_block_roundtrip(self):
        _, ct, _ = run_cli("block", "--key", KEY, "--seed", SEED, "--plain", "0123456789ABCDEF")
        _, pt, _ = run_cli("block", "--key", KEY, "--seed", SEED, "--plain", ct, "--decrypt")
        self.assertEqual(pt, "0123456789ABCDEF")

    def test_enc_dec_roundtrip(self):
        for mode in ("cbc", "ctr"):
            _, ct, _ = run_cli("enc", "--key", KEY, "--seed", SEED, "--text", "hello dynamic des", "--mode", mode)
            code, pt, _ = run_cli("dec", "--key", KEY, "--seed", SEED, "--hex", ct, "--mode", mode)
            self.assertEqual((code, pt), (0, "hello dynamic des"))

    def test_controls_and_sbox_and_trace(self):
        code, out, _ = run_cli("controls", "--seed", SEED)
        self.assertEqual(code, 0)
        self.assertEqual(len(out.splitlines()), 17)
        code, out, _ = run_cli("sbox", "--key", KEY, "--seed", SEED, "--round", "1", "--box", "1", "--six", "011000")
        self.assertEqual(code, 0)
        self.assertIn("S1:", out)
        code, out, _ = run_cli("block", "--key", KEY, "--seed", SEED, "--plain", "0123456789ABCDEF", "--trace")
        self.assertEqual(code, 0)
        self.assertIn("Round 16", out)

    def test_errors_return_code_2(self):
        code, _, err = run_cli("block", "--key", "0101010101010101", "--seed", SEED, "--plain", "00" * 8)
        self.assertEqual(code, 2)
        self.assertIn("weak", err)
        code, _, _ = run_cli("controls", "--seed", "0")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
