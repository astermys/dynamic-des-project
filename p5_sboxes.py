"""Dynamic S-boxes (process 5, stages 6.1-6.6 of the diagram).

For each 6-bit block and the round's ControlWord:
  6.2  select table set T0..T7                  (3 control bits)
  6.3  permute the 4 rows                        (5 control bits)
  6.4  shift columns by s, mod 16                (4 control bits)
  6.5  look the value up in the S-box table
  6.6  rotate the 4-bit result left              (2 control bits)

Table sets: T0 is the unmodified DES S-box set. T1..T7 are DERIVED (a design
assumption, since the source diagram does not define them): T_k[j] is DES
S-box (j+k) mod 8 with its output values relabelled by a fixed public
permutation of 0..15. Every row therefore stays a permutation of 0..15.
"""
from __future__ import annotations

from dataclasses import dataclass

from .bitops import rotl
from .p4_control import ControlWord, RowPermPolicy, row_permutation
from .tables import DES_SBOXES

NUM_TABLE_SETS = 8
NUM_SBOXES = 8


def _xorshift32(x: int) -> int:
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= x >> 17
    x ^= (x << 5) & 0xFFFFFFFF
    return x & 0xFFFFFFFF


def value_permutation(k: int) -> tuple[int, ...]:
    """Fixed public permutation of 0..15 for table set k (identity for k=0)."""
    perm = list(range(16))
    if k == 0:
        return tuple(perm)
    x = (0xA5A5A5A5 + k * 0x01234567) & 0xFFFFFFFF
    for i in range(15, 0, -1):
        x = _xorshift32(x)
        j = x % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return tuple(perm)


def build_table_sets() -> tuple:
    sets = []
    for k in range(NUM_TABLE_SETS):
        vp = value_permutation(k)
        sets.append(tuple(
            tuple(tuple(vp[v] for v in row) for row in DES_SBOXES[(j + k) % NUM_SBOXES])
            for j in range(NUM_SBOXES)))
    return tuple(sets)


TABLE_SETS = build_table_sets()
assert TABLE_SETS[0] == DES_SBOXES
assert all(sorted(r) == list(range(16)) for ts in TABLE_SETS for b in ts for r in b)


def split_six(six: int) -> tuple[int, int]:
    """6-bit block b1..b6 -> (row = b1b6, col = b2b3b4b5)."""
    if not 0 <= six < 64:
        raise ValueError("S-box input must be 6 bits")
    return ((six >> 4) & 2) | (six & 1), (six >> 1) & 0xF


def dynamic_sbox(six: int, box: int, ctrl: ControlWord,
                 policy: RowPermPolicy = RowPermPolicy.MOD24) -> int:
    row, col = split_six(six)
    row = row_permutation(ctrl.row_perm, policy)[row]
    col = (col + ctrl.col_shift) & 0xF
    return rotl(TABLE_SETS[ctrl.table][box][row][col], ctrl.out_rot, 4)


@dataclass(frozen=True)
class SboxTrace:
    six: int
    box: int
    row: int
    col: int
    table: int
    row_perm: tuple[int, ...]
    row_after: int
    col_after: int
    looked_up: int
    out: int

    def describe(self) -> str:
        return (f"S{self.box + 1}: in={self.six:06b} row={self.row} col={self.col} | "
                f"T{self.table} rows->{self.row_perm} => row {self.row_after}, "
                f"col {self.col_after} | lookup={self.looked_up:04b} "
                f"| rotated={self.out:04b}")


def dynamic_sbox_trace(six: int, box: int, ctrl: ControlWord,
                       policy: RowPermPolicy = RowPermPolicy.MOD24) -> SboxTrace:
    row, col = split_six(six)
    perm = row_permutation(ctrl.row_perm, policy)
    row2, col2 = perm[row], (col + ctrl.col_shift) & 0xF
    val = TABLE_SETS[ctrl.table][box][row2][col2]
    return SboxTrace(six, box, row, col, ctrl.table, perm, row2, col2,
                     val, rotl(val, ctrl.out_rot, 4))


STATIC_CONTROL = ControlWord(0, 0, 0, 0)      # reduces the cipher to standard DES
