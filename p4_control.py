"""Process 4: Control bits per round (14 bits = 3 + 5 + 4 + 2).

ControlStream (process 3) -> for each round: 14 bits, grouped as
    table select    3 bits  -> table set T0..T7
    row permutation 5 bits  -> row-permutation code 0..31
    column shift    4 bits  -> shift 0..15
    output rotation 2 bits  -> rotate left 0..3
Bits are consumed MSB-first in exactly that order.

Design problem handled here: 5 bits give 32 codes but 4 rows have only 4! = 24
orderings. RowPermPolicy makes the resolution explicit:
  MOD24   code -> permutation (code mod 24). Fixed 14 bits/round, but codes
          0..7 alias 24..31, so those 8 permutations are twice as likely.
  REJECT  redraw the 5-bit field until code < 24. Exactly uniform over the 24
          permutations, but bit consumption per round becomes variable.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from itertools import permutations

from .p3_lfsr import DEFAULT_POLY, ControlStream, Polynomial, validate_seed

FIELDS = (("table", 3), ("row_perm", 5), ("col_shift", 4), ("out_rot", 2))
WORD_BITS = sum(w for _, w in FIELDS)            # 14
ROUNDS = 16

ROW_PERMS: tuple[tuple[int, ...], ...] = tuple(permutations(range(4)))   # lexicographic
N_ROW_PERMS = len(ROW_PERMS)                     # 24


class RowPermPolicy(Enum):
    MOD24 = "mod24"
    REJECT = "reject"


def row_permutation(code: int, policy: RowPermPolicy = RowPermPolicy.MOD24) -> tuple[int, ...]:
    """Resolve a 5-bit code to a permutation: result[original_row] = new_row."""
    if not 0 <= code < 32:
        raise ValueError("row-permutation code must be 0..31")
    if policy is RowPermPolicy.REJECT and code >= N_ROW_PERMS:
        raise ValueError("code >= 24 is invalid under the REJECT policy")
    return ROW_PERMS[code % N_ROW_PERMS]


@dataclass(frozen=True)
class ControlWord:
    table: int
    row_perm: int
    col_shift: int
    out_rot: int

    def __post_init__(self):
        for name, width in FIELDS:
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < (1 << width):
                raise ValueError(f"{name} must be an int in 0..{(1 << width) - 1}, got {v!r}")

    # ---- encoding -------------------------------------------------------------
    @classmethod
    def from_int(cls, value: int) -> "ControlWord":
        if not 0 <= value < (1 << WORD_BITS):
            raise ValueError(f"control word must fit in {WORD_BITS} bits")
        vals, shift = {}, WORD_BITS
        for name, width in FIELDS:
            shift -= width
            vals[name] = (value >> shift) & ((1 << width) - 1)
        return cls(**vals)

    @classmethod
    def from_bits(cls, s: str) -> "ControlWord":
        s = s.replace(" ", "")
        if len(s) != WORD_BITS or set(s) - {"0", "1"}:
            raise ValueError(f"need exactly {WORD_BITS} binary digits")
        return cls.from_int(int(s, 2))

    def to_int(self) -> int:
        v = 0
        for name, width in FIELDS:
            v = (v << width) | getattr(self, name)
        return v

    def to_bits(self, grouped: bool = True) -> str:
        parts = [format(getattr(self, n), f"0{w}b") for n, w in FIELDS]
        return " ".join(parts) if grouped else "".join(parts)

    def describe(self, policy: RowPermPolicy = RowPermPolicy.MOD24) -> str:
        perm = row_permutation(self.row_perm, policy)
        return (f"T{self.table} + RowPerm#{self.row_perm} {perm} "
                f"+ Shift {self.col_shift} + Rotate {self.out_rot}")

    def resolved_row_perm(self, policy: RowPermPolicy = RowPermPolicy.MOD24) -> tuple[int, ...]:
        return row_permutation(self.row_perm, policy)


# ---- generation ---------------------------------------------------------------
class ControlWordGenerator:
    def __init__(self, seed: int, policy: RowPermPolicy = RowPermPolicy.MOD24,
                 poly: Polynomial = DEFAULT_POLY):
        self.policy = policy
        self.stream = ControlStream(validate_seed(seed), poly)

    @property
    def bits_consumed(self) -> int:
        return self.stream.consumed

    def next_word(self) -> ControlWord:
        table = self.stream.read_int(3)
        row = self.stream.read_int(5)
        if self.policy is RowPermPolicy.REJECT:
            while row >= N_ROW_PERMS:
                row = self.stream.read_int(5)
        col = self.stream.read_int(4)
        rot = self.stream.read_int(2)
        return ControlWord(table, row, col, rot)


@dataclass(frozen=True)
class ControlSchedule:
    seed: int
    policy: RowPermPolicy
    words: tuple[ControlWord, ...]
    bits_consumed: int

    @classmethod
    def from_seed(cls, seed: int, rounds: int = ROUNDS,
                  policy: RowPermPolicy = RowPermPolicy.MOD24) -> "ControlSchedule":
        gen = ControlWordGenerator(seed, policy)
        words = tuple(gen.next_word() for _ in range(rounds))
        return cls(seed, policy, words, gen.bits_consumed)

    def for_round(self, i: int) -> ControlWord:
        """1-indexed, matching Round 1..16."""
        if not 1 <= i <= len(self.words):
            raise IndexError(f"round must be 1..{len(self.words)}")
        return self.words[i - 1]

    @property
    def decryption_order(self) -> tuple[ControlWord, ...]:
        return self.words[::-1]

    def trace(self) -> str:
        lines = [f"LFSR seed 0x{self.seed:04X}, policy={self.policy.value}, "
                 f"bits consumed={self.bits_consumed}"]
        for i, w in enumerate(self.words, 1):
            lines.append(f"Round {i:2d}: {w.to_bits()}  ->  {w.describe(self.policy)}")
        return "\n".join(lines)
