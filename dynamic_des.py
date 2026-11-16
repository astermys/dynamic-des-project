"""
Dynamic DES with LFSR-generated S-box configuration (educational prototype).

Pipeline (matches the block diagram):
  Plaintext -> IP -> 16 Feistel rounds -> swap -> IP^-1 -> Ciphertext
  Each round: E(R) XOR Ki -> 8 dynamic S-boxes -> P -> XOR L
  Dynamic S-box: select table (3 bits) -> permute rows (5 bits)
                 -> shift columns (4 bits) -> lookup -> rotate output (2 bits)
  The 14 control bits per round come from a 16-bit LFSR (x^16+x^14+x^13+x^11+1).

NOT for real-world security. The extra tables/permutations are design
assumptions and have had no cryptanalysis.
"""

import os
from dataclasses import dataclass
from itertools import permutations

# --------------------------------------------------------------------------
# Step 1: Standard DES constant tables (1-indexed, MSB-first bit numbering)
# --------------------------------------------------------------------------
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# Each S-box: 4 rows x 16 columns
DES_SBOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]


# --------------------------------------------------------------------------
# Step 2: Bit helpers
# --------------------------------------------------------------------------
def permute(value: int, table, in_bits: int) -> int:
    """Apply a DES-style permutation table (1-indexed, MSB = position 1)."""
    out = 0
    for pos in table:
        out = (out << 1) | ((value >> (in_bits - pos)) & 1)
    return out


def rotl(value: int, n: int, bits: int) -> int:
    n %= bits
    mask = (1 << bits) - 1
    return ((value << n) | (value >> (bits - n))) & mask


# --------------------------------------------------------------------------
# Step 3: DES key schedule (K1..K16, 48 bits each)
# --------------------------------------------------------------------------
def key_schedule(key64: int):
    cd = permute(key64, PC1, 64)          # 64 -> 56 bits (drops parity)
    c, d = cd >> 28, cd & 0xFFFFFFF
    subkeys = []
    for s in SHIFTS:
        c, d = rotl(c, s, 28), rotl(d, s, 28)
        subkeys.append(permute((c << 28) | d, PC2, 56))
    return subkeys


# --------------------------------------------------------------------------
# Step 4: LFSR and per-round control bits (14 bits = 3 + 5 + 4 + 2)
# --------------------------------------------------------------------------
class LFSR16:
    """Fibonacci LFSR, polynomial x^16 + x^14 + x^13 + x^11 + 1."""
    TAPS = (16, 14, 13, 11)

    def __init__(self, seed: int):
        seed &= 0xFFFF
        if seed == 0:
            raise ValueError("LFSR seed must be non-zero")
        self.state = seed

    def next_bit(self) -> int:
        out = (self.state >> 15) & 1
        fb = 0
        for t in self.TAPS:
            fb ^= (self.state >> (t - 1)) & 1
        self.state = ((self.state << 1) | fb) & 0xFFFF
        return out

    def next_bits(self, n: int) -> int:
        v = 0
        for _ in range(n):
            v = (v << 1) | self.next_bit()
        return v


@dataclass(frozen=True)
class Control:
    table: int       # 3 bits -> table set T0..T7
    row_perm: int    # 5 bits -> row permutation number 0..31
    col_shift: int   # 4 bits -> column shift 0..15
    out_rot: int     # 2 bits -> output left-rotation 0..3


def generate_controls(seed: int, rounds: int = 16):
    lfsr = LFSR16(seed)
    controls = []
    for _ in range(rounds):
        bits = lfsr.next_bits(14)
        controls.append(Control(
            table=(bits >> 11) & 0x7,
            row_perm=(bits >> 6) & 0x1F,
            col_shift=(bits >> 2) & 0xF,
            out_rot=bits & 0x3,
        ))
    return controls


# --------------------------------------------------------------------------
# Step 5: Dynamic tables, row permutations
# --------------------------------------------------------------------------
def _xorshift32(x: int) -> int:
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= x >> 17
    x ^= (x << 5) & 0xFFFFFFFF
    return x & 0xFFFFFFFF


def _value_perm(k: int):
    """Fixed public permutation of 0..15 for table set k (k=0 is identity)."""
    perm = list(range(16))
    if k == 0:
        return perm
    x = (0xA5A5A5A5 + k * 0x01234567) & 0xFFFFFFFF
    for i in range(15, 0, -1):
        x = _xorshift32(x)
        j = x % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def build_table_sets():
    """T0 = standard DES. T1..T7 = DES S-boxes rotated among positions and
    with output values relabelled by a fixed public permutation. Each row
    stays a permutation of 0..15, as in DES."""
    sets = []
    for k in range(8):
        vp = _value_perm(k)
        sets.append([
            [[vp[v] for v in row] for row in DES_SBOXES[(j + k) % 8]]
            for j in range(8)
        ])
    return sets


TABLE_SETS = build_table_sets()
# 4 rows have 24 orderings; 5 control bits give 32 values, so use number mod 24.
ROW_PERMS = list(permutations(range(4)))


# --------------------------------------------------------------------------
# Step 6: Dynamic S-box and round function
# --------------------------------------------------------------------------
def dynamic_sbox(six: int, box: int, c: Control) -> int:
    row = ((six >> 4) & 2) | (six & 1)       # outer bits
    col = (six >> 1) & 0xF                   # middle 4 bits
    row = ROW_PERMS[c.row_perm % 24][row]    # row permutation
    col = (col + c.col_shift) % 16           # column shift
    val = TABLE_SETS[c.table][box][row][col] # table lookup
    return rotl(val, c.out_rot, 4)           # output rotation


def feistel_f(r32: int, subkey: int, c: Control) -> int:
    x = permute(r32, E, 32) ^ subkey
    out = 0
    for j in range(8):
        six = (x >> (42 - 6 * j)) & 0x3F
        out = (out << 4) | dynamic_sbox(six, j, c)
    return permute(out, P, 32)


# --------------------------------------------------------------------------
# Step 7: Block encrypt / decrypt
# --------------------------------------------------------------------------
def _crypt_block(block: int, subkeys, controls) -> int:
    b = permute(block, IP, 64)
    l, r = b >> 32, b & 0xFFFFFFFF
    for k, c in zip(subkeys, controls):
        l, r = r, l ^ feistel_f(r, k, c)
    return permute((r << 32) | l, FP, 64)


class DynamicDES:
    def __init__(self, key: bytes, lfsr_seed: int, static: bool = False):
        """static=True disables dynamic behaviour (control = all zeros),
        which makes this identical to standard DES (useful for testing)."""
        if len(key) != 8:
            raise ValueError("key must be 8 bytes")
        self.subkeys = key_schedule(int.from_bytes(key, "big"))
        if static:
            self.controls = [Control(0, 0, 0, 0)] * 16
        else:
            self.controls = generate_controls(lfsr_seed)

    def encrypt_block(self, block: int) -> int:
        return _crypt_block(block, self.subkeys, self.controls)

    def decrypt_block(self, block: int) -> int:
        # Same network, with round keys AND control words in reverse order.
        return _crypt_block(block, self.subkeys[::-1], self.controls[::-1])

    # ---- Step 8: CBC mode with PKCS#7 padding for arbitrary-length data ----
    def encrypt(self, data: bytes, iv: bytes = None) -> bytes:
        iv = iv or os.urandom(8)
        pad = 8 - len(data) % 8
        data += bytes([pad]) * pad
        prev = int.from_bytes(iv, "big")
        out = bytearray(iv)
        for i in range(0, len(data), 8):
            blk = int.from_bytes(data[i:i + 8], "big") ^ prev
            prev = self.encrypt_block(blk)
            out += prev.to_bytes(8, "big")
        return bytes(out)

    def decrypt(self, blob: bytes) -> bytes:
        if len(blob) < 16 or len(blob) % 8:
            raise ValueError("bad ciphertext length")
        prev = int.from_bytes(blob[:8], "big")
        out = bytearray()
        for i in range(8, len(blob), 8):
            c = int.from_bytes(blob[i:i + 8], "big")
            out += (self.decrypt_block(c) ^ prev).to_bytes(8, "big")
            prev = c
        pad = out[-1]
        if not 1 <= pad <= 8 or out[-pad:] != bytes([pad]) * pad:
            raise ValueError("bad padding (wrong key or LFSR seed?)")
        return bytes(out[:-pad])


# --------------------------------------------------------------------------
# Step 9: Command line interface
# --------------------------------------------------------------------------
def _main():
    import argparse
    ap = argparse.ArgumentParser(description="Dynamic DES (LFSR S-box) demo")
    ap.add_argument("mode", choices=["enc", "dec", "controls"])
    ap.add_argument("--key", default="133457799BBCDFF1", help="16 hex chars")
    ap.add_argument("--seed", default="CAB3", help="16-bit LFSR seed, hex")
    ap.add_argument("--text", help="plaintext (enc)")
    ap.add_argument("--hex", help="ciphertext hex incl. IV (dec)")
    a = ap.parse_args()

    seed = int(a.seed, 16)
    if a.mode == "controls":
        for i, c in enumerate(generate_controls(seed), 1):
            print(f"Round {i:2d}: {c}")
        return
    des = DynamicDES(bytes.fromhex(a.key), seed)
    if a.mode == "enc":
        print(des.encrypt(a.text.encode()).hex())
    else:
        print(des.decrypt(bytes.fromhex(a.hex)).decode())


if __name__ == "__main__":
    _main()
