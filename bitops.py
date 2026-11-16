"""Bit-level helpers. All bit strings/positions are MSB-first (DES convention)."""
from __future__ import annotations


def mask(n: int) -> int:
    return (1 << n) - 1


def check_width(value: int, width: int, name: str = "value") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value < 0 or value >> width:
        raise ValueError(f"{name}=0x{value:X} does not fit in {width} bits")
    return value


def permute(value: int, table: tuple[int, ...], in_bits: int) -> int:
    """Generic DES permutation/selection. Table entries are 1-indexed input
    bit positions (position 1 = MSB). Output width is len(table)."""
    check_width(value, in_bits)
    out = 0
    for pos in table:
        if not 1 <= pos <= in_bits:
            raise ValueError(f"table position {pos} outside 1..{in_bits}")
        out = (out << 1) | ((value >> (in_bits - pos)) & 1)
    return out


def rotl(value: int, n: int, bits: int) -> int:
    check_width(value, bits)
    n %= bits
    return ((value << n) | (value >> (bits - n))) & mask(bits)


def split(value: int, width: int) -> tuple[int, int]:
    """Split a bit string into (high half, low half)."""
    half = width // 2
    check_width(value, width)
    return value >> half, value & mask(half)


def join(hi: int, lo: int, half: int) -> int:
    check_width(hi, half, "hi")
    check_width(lo, half, "lo")
    return (hi << half) | lo


def popcount(value: int) -> int:
    return bin(value).count("1")


def to_bits(value: int, width: int, group: int = 0) -> str:
    s = format(check_width(value, width), f"0{width}b")
    if group:
        s = " ".join(s[i:i + group] for i in range(0, width, group))
    return s


def from_bits(s: str) -> int:
    return int(s.replace(" ", ""), 2)


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def int_to_bytes(v: int, length: int) -> bytes:
    return check_width(v, 8 * length).to_bytes(length, "big")
