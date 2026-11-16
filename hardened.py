"""Hardened Dynamic DES: only 'free' S-box knobs (see security.py, section F).

The original design's modular column shift, arbitrary row permutations and
relabelled tables T1..T7 degrade DES S-box quality. This variant keeps ONLY
transformations that are affine equivalences of a genuine DES S-box, which
leave its difference and linear tables unchanged (up to relabelling):

    box_offset  3 bits  S-box at position j is DES S-box (j + offset) mod 8
    row_d4      3 bits  row order from the 8 symmetries of the 2-bit row square
    col_xor     4 bits  column index XOR mask  (input translation)
    rot         2 bits  output rotate left     (output bit permutation)

12 bits per round. All four fields have power-of-two ranges, so the control
word is exactly uniform: no MOD24 aliasing, no rejection sampling.
Static controls (all zero) give standard DES.
"""
from __future__ import annotations

from dataclasses import dataclass

from .bitops import check_width, permute, popcount, rotl, to_bits
from .cipher import BlockTrace
from .modes import BlockModesMixin
from .p1_input_ip import apply_ip, final_permutation
from .p2_key_schedule import generate_key_schedule
from .p3_lfsr import ControlStream, validate_seed
from .p4_control import ROW_PERMS
from .p5_round import RoundTrace, expand
from .p5_sboxes import split_six
from .tables import DES_SBOXES, P

FIELDS_H = (("box_offset", 3), ("row_d4", 3), ("col_xor", 4), ("rot", 2))
WORD_BITS_H = sum(w for _, w in FIELDS_H)          # 12
ROUNDS = 16

D4_ROW_INDICES = tuple(
    i for i, p in enumerate(ROW_PERMS)
    if all(popcount(p[a] ^ p[b]) == popcount(a ^ b) for a in range(4) for b in range(4)))
D4_ROW_PERMS = tuple(ROW_PERMS[i] for i in D4_ROW_INDICES)
assert len(D4_ROW_PERMS) == 8 and D4_ROW_PERMS[0] == (0, 1, 2, 3)


@dataclass(frozen=True)
class HardenedControlWord:
    box_offset: int
    row_d4: int
    col_xor: int
    rot: int

    def __post_init__(self):
        for name, width in FIELDS_H:
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < (1 << width):
                raise ValueError(f"{name} must be an int in 0..{(1 << width) - 1}, got {v!r}")

    @classmethod
    def from_int(cls, value: int) -> "HardenedControlWord":
        if not 0 <= value < (1 << WORD_BITS_H):
            raise ValueError(f"control word must fit in {WORD_BITS_H} bits")
        vals, shift = {}, WORD_BITS_H
        for name, width in FIELDS_H:
            shift -= width
            vals[name] = (value >> shift) & ((1 << width) - 1)
        return cls(**vals)

    def to_int(self) -> int:
        v = 0
        for name, width in FIELDS_H:
            v = (v << width) | getattr(self, name)
        return v

    def to_bits(self, grouped: bool = True) -> str:
        parts = [format(getattr(self, n), f"0{w}b") for n, w in FIELDS_H]
        return (" " if grouped else "").join(parts)

    def describe(self) -> str:
        return (f"offset {self.box_offset} + rows {D4_ROW_PERMS[self.row_d4]} "
                f"+ col XOR {self.col_xor:04b} + rotate {self.rot}")


STATIC_HARDENED = HardenedControlWord(0, 0, 0, 0)


@dataclass(frozen=True)
class HardenedControlSchedule:
    seed: int
    words: tuple[HardenedControlWord, ...]

    @classmethod
    def from_seed(cls, seed: int, rounds: int = ROUNDS) -> "HardenedControlSchedule":
        stream = ControlStream(validate_seed(seed))
        words = tuple(HardenedControlWord(*(stream.read_int(w) for _, w in FIELDS_H))
                      for _ in range(rounds))
        return cls(seed, words)

    @property
    def bits_consumed(self) -> int:
        return WORD_BITS_H * len(self.words)

    def trace(self) -> str:
        lines = [f"LFSR seed 0x{self.seed:04X}, hardened layout, {self.bits_consumed} bits"]
        for i, w in enumerate(self.words, 1):
            lines.append(f"Round {i:2d}: {w.to_bits()}  ->  {w.describe()}")
        return "\n".join(lines)


# ---- hardened S-box and round --------------------------------------------------------
def hardened_sbox(six: int, box: int, c: HardenedControlWord) -> int:
    base = DES_SBOXES[(box + c.box_offset) % 8]
    row, col = split_six(six)
    return rotl(base[D4_ROW_PERMS[c.row_d4][row]][col ^ c.col_xor], c.rot, 4)


@dataclass(frozen=True)
class HardenedSboxTrace:
    six: int
    box: int
    base_box: int
    row: int
    col: int
    row_after: int
    col_after: int
    looked_up: int
    out: int

    def describe(self) -> str:
        return (f"S{self.box + 1}: in={self.six:06b} row={self.row} col={self.col} | "
                f"uses DES S{self.base_box + 1}, row->{self.row_after}, col->{self.col_after} "
                f"| lookup={self.looked_up:04b} | rotated={self.out:04b}")


def hardened_sbox_trace(six: int, box: int, c: HardenedControlWord) -> HardenedSboxTrace:
    base_idx = (box + c.box_offset) % 8
    row, col = split_six(six)
    r2, c2 = D4_ROW_PERMS[c.row_d4][row], col ^ c.col_xor
    val = DES_SBOXES[base_idx][r2][c2]
    return HardenedSboxTrace(six, box, base_idx, row, col, r2, c2, val, rotl(val, c.rot, 4))


def _feistel(l: int, r: int, subkey: int, c: HardenedControlWord, index: int):
    expanded = expand(r)
    xored = expanded ^ subkey
    sixes = tuple((xored >> (42 - 6 * j)) & 0x3F for j in range(8))
    outs = tuple(hardened_sbox(s, j, c) for j, s in enumerate(sixes))
    s_out = 0
    for o in outs:
        s_out = (s_out << 4) | o
    f = permute(s_out, P, 32)
    return r, l ^ f, RoundTrace(index, l, r, expanded, xored, sixes, outs, s_out, f, r, l ^ f, c)


class HardenedDES(BlockModesMixin):
    def __init__(self, key: bytes | int, lfsr_seed: int | None, *, static: bool = False,
                 reject_weak: bool = True, require_odd_parity: bool = False):
        self.static = static
        self.key_schedule = generate_key_schedule(
            key, require_odd_parity=require_odd_parity, reject_weak=reject_weak)
        if static:
            self.control_schedule = None
            self._controls: tuple[HardenedControlWord, ...] = (STATIC_HARDENED,) * ROUNDS
        else:
            if lfsr_seed is None:
                raise ValueError("lfsr_seed is required unless static=True")
            self.control_schedule = HardenedControlSchedule.from_seed(lfsr_seed)
            self._controls = self.control_schedule.words
        self._enc = (self.key_schedule.round_keys, self._controls)
        self._dec = (self.key_schedule.decryption_order, self._controls[::-1])

    @classmethod
    def from_hex(cls, key_hex: str, seed_hex: str | None, **kw) -> "HardenedDES":
        return cls(bytes.fromhex(key_hex), None if seed_hex is None else int(seed_hex, 16), **kw)

    def _crypt(self, block: int, keys, controls, keep_traces: bool = False):
        check_width(block, 64, "block")
        ip = apply_ip(block)
        l, r, traces = ip.l0, ip.r0, []
        for i, (k, c) in enumerate(zip(keys, controls), start=1):
            l, r, t = _feistel(l, r, k, c, i)
            if keep_traces:
                traces.append(t)
        pre = (r << 32) | l
        return ip, tuple(traces), pre, final_permutation(pre)

    def encrypt_block(self, block: int) -> int:
        return self._crypt(block, *self._enc)[3]

    def decrypt_block(self, block: int) -> int:
        return self._crypt(block, *self._dec)[3]

    def trace_block(self, block: int, decrypt: bool = False) -> BlockTrace:
        ip, traces, pre, out = self._crypt(block, *(self._dec if decrypt else self._enc), True)
        return BlockTrace(block, ip, traces, pre, out)

    def trace_sbox(self, six: int, box: int, round_no: int) -> HardenedSboxTrace:
        if not 1 <= round_no <= ROUNDS:
            raise ValueError("round must be 1..16")
        return hardened_sbox_trace(six, box, self._controls[round_no - 1])
