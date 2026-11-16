"""Process 1: Input and Initial Permutation.

plaintext bytes -> (optional PKCS#7 padding) -> 64-bit blocks
                -> IP -> (L0, R0)
"""
from __future__ import annotations

from dataclasses import dataclass

from .bitops import bytes_to_int, join, permute, split, to_bits
from .tables import FP, IP

BLOCK_BYTES = 8


# ---- input handling -------------------------------------------------------
def pkcs7_pad(data: bytes, block: int = BLOCK_BYTES) -> bytes:
    n = block - len(data) % block
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block: int = BLOCK_BYTES) -> bytes:
    if not data or len(data) % block:
        raise ValueError("invalid padded length")
    n = data[-1]
    if not 1 <= n <= block or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-n]


def to_blocks(data: bytes) -> list[int]:
    """Split bytes (length must be a multiple of 8) into 64-bit integers."""
    if len(data) % BLOCK_BYTES:
        raise ValueError("data length must be a multiple of 8 bytes; pad first")
    return [bytes_to_int(data[i:i + BLOCK_BYTES])
            for i in range(0, len(data), BLOCK_BYTES)]


# ---- permutations ---------------------------------------------------------
def initial_permutation(block: int) -> int:
    return permute(block, IP, 64)


def final_permutation(block: int) -> int:
    return permute(block, FP, 64)


@dataclass(frozen=True)
class IPResult:
    block: int      # input 64-bit block
    permuted: int   # IP(block)
    l0: int         # left 32 bits
    r0: int         # right 32 bits

    def trace(self) -> str:
        return "\n".join([
            f"Input block : {to_bits(self.block, 64, 8)}  (0x{self.block:016X})",
            f"After IP    : {to_bits(self.permuted, 64, 8)}  (0x{self.permuted:016X})",
            f"L0          : {to_bits(self.l0, 32, 8)}  (0x{self.l0:08X})",
            f"R0          : {to_bits(self.r0, 32, 8)}  (0x{self.r0:08X})",
        ])


def apply_ip(block: int) -> IPResult:
    p = initial_permutation(block)
    l0, r0 = split(p, 64)
    return IPResult(block, p, l0, r0)


def process_input(plaintext: bytes, pad: bool = True) -> list[IPResult]:
    """Full Process 1: bytes in, list of (L0, R0) results out."""
    data = pkcs7_pad(plaintext) if pad else plaintext
    return [apply_ip(b) for b in to_blocks(data)]


def undo_ip(result: IPResult) -> int:
    """Re-join L0||R0 and apply IP^-1 (used to verify IP is invertible)."""
    return final_permutation(join(result.l0, result.r0, 32))


def ip_bit_map() -> dict[int, int]:
    """Research aid: input bit position -> output bit position under IP."""
    return {src: out for out, src in enumerate(IP, start=1)}
