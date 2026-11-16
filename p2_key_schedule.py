"""Process 2: DES Key Schedule (16 round keys of 48 bits).

key (64 bits, 8 parity) -> PC-1 -> (C0, D0)
   -> for i in 1..16: Ci = rotl(Ci-1, s_i), Di = rotl(Di-1, s_i), Ki = PC-2(Ci||Di)
"""
from __future__ import annotations

from dataclasses import dataclass

from .bitops import bytes_to_int, join, permute, popcount, rotl, split, to_bits
from .tables import PC1, PC2, SHIFTS

ROUNDS = 16

WEAK_KEYS = tuple(bytes.fromhex(h) for h in (
    "0101010101010101", "FEFEFEFEFEFEFEFE",
    "E0E0E0E0F1F1F1F1", "1F1F1F1F0E0E0E0E"))

SEMI_WEAK_KEYS = tuple(bytes.fromhex(h) for h in (
    "01FE01FE01FE01FE", "FE01FE01FE01FE01",
    "1FE01FE00EF10EF1", "E01FE01FF10EF10E",
    "01E001E001F101F1", "E001E001F101F101",
    "1FFE1FFE0EFE0EFE", "FE1FFE1FFE0EFE0E",
    "011F011F010E010E", "1F011F010E010E01",
    "E0FEE0FEF1FEF1FE", "FEE0FEE0FEF1FEF1"))

_PARITY_MASK = 0xFEFEFEFEFEFEFEFE        # ignore the 8 parity bits


# ---- key validation ---------------------------------------------------------
def _coerce_key(key: bytes | int) -> int:
    if isinstance(key, int):
        if not 0 <= key < 1 << 64:
            raise ValueError("integer key must fit in 64 bits")
        return key
    if len(key) != 8:
        raise ValueError(f"DES key must be 8 bytes, got {len(key)}")
    return bytes_to_int(key)


def has_odd_parity(key: bytes | int) -> bool:
    k = _coerce_key(key)
    return all(popcount((k >> (8 * i)) & 0xFF) % 2 == 1 for i in range(8))


def set_odd_parity(key: bytes | int) -> bytes:
    """Return the key with each byte's low bit set to give odd parity."""
    k = _coerce_key(key)
    out = bytearray()
    for i in range(7, -1, -1):
        byte = (k >> (8 * i)) & 0xFE
        if popcount(byte) % 2 == 0:
            byte |= 1
        out.append(byte)
    return bytes(out)


def is_weak_key(key: bytes | int) -> bool:
    k = _coerce_key(key) & _PARITY_MASK
    return any(bytes_to_int(w) & _PARITY_MASK == k for w in WEAK_KEYS)


def is_semi_weak_key(key: bytes | int) -> bool:
    k = _coerce_key(key) & _PARITY_MASK
    return any(bytes_to_int(w) & _PARITY_MASK == k for w in SEMI_WEAK_KEYS)


# ---- schedule ----------------------------------------------------------------
@dataclass(frozen=True)
class KeySchedule:
    key: int
    k_plus: int                      # 56-bit PC-1 output
    c: tuple[int, ...]               # C0..C16 (28 bits each)
    d: tuple[int, ...]               # D0..D16
    round_keys: tuple[int, ...]      # K1..K16 (48 bits each)

    def round_key(self, i: int) -> int:
        """1-indexed, matching the K1..K16 notation."""
        if not 1 <= i <= ROUNDS:
            raise IndexError("round index must be 1..16")
        return self.round_keys[i - 1]

    @property
    def decryption_order(self) -> tuple[int, ...]:
        return self.round_keys[::-1]

    def key_bit_usage(self) -> dict[int, int]:
        """Research aid: how many round keys each of the 56 PC-1 key bits
        (identified by its position in the original 64-bit key) feeds."""
        usage = {}
        for p in PC1:
            single = 1 << (64 - p)
            ks = generate_key_schedule(single)
            base = generate_key_schedule(0)
            usage[p] = sum(a != b for a, b in zip(ks.round_keys, base.round_keys))
        return usage

    def trace(self) -> str:
        lines = [f"Key          : 0x{self.key:016X}",
                 f"K+ (PC-1)    : {to_bits(self.k_plus, 56, 7)}",
                 f"C0           : {to_bits(self.c[0], 28, 4)}",
                 f"D0           : {to_bits(self.d[0], 28, 4)}"]
        for i in range(1, ROUNDS + 1):
            lines.append(f"Round {i:2d}  shift={SHIFTS[i-1]}  "
                         f"C={to_bits(self.c[i], 28, 4)}  D={to_bits(self.d[i], 28, 4)}")
            lines.append(f"          K{i:<2d} = {to_bits(self.round_keys[i-1], 48, 6)}"
                         f"  (0x{self.round_keys[i-1]:012X})")
        return "\n".join(lines)


def generate_key_schedule(key: bytes | int, *, require_odd_parity: bool = False,
                          reject_weak: bool = False) -> KeySchedule:
    k = _coerce_key(key)
    if require_odd_parity and not has_odd_parity(k):
        raise ValueError("key does not have odd parity on every byte")
    if reject_weak and (is_weak_key(k) or is_semi_weak_key(k)):
        raise ValueError("weak or semi-weak DES key rejected")

    k_plus = permute(k, PC1, 64)
    c0, d0 = split(k_plus, 56)
    cs, ds, rks = [c0], [d0], []
    for shift in SHIFTS:
        c, d = rotl(cs[-1], shift, 28), rotl(ds[-1], shift, 28)
        cs.append(c)
        ds.append(d)
        rks.append(permute(join(c, d, 28), PC2, 56))
    return KeySchedule(k, k_plus, tuple(cs), tuple(ds), tuple(rks))


def round_keys(key: bytes | int) -> list[int]:
    return list(generate_key_schedule(key).round_keys)
