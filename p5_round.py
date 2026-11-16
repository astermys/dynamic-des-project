"""Process 5: DES round structure with dynamic S-boxes.

Round i:  F = P( S_dyn( E(R_{i-1}) XOR K_i ; control_i ) )
          L_i = R_{i-1};   R_i = L_{i-1} XOR F
"""
from __future__ import annotations

from dataclasses import dataclass

from .bitops import check_width, join, permute, to_bits
from .p4_control import ControlWord, RowPermPolicy
from .p5_sboxes import NUM_SBOXES, dynamic_sbox
from .tables import E, P


def expand(r32: int) -> int:
    return permute(r32, E, 32)


def substitute(x48: int, ctrl: ControlWord,
               policy: RowPermPolicy = RowPermPolicy.MOD24) -> tuple[int, tuple, tuple]:
    """Split 48 bits into eight 6-bit blocks (MSB first), apply the dynamic
    S-boxes, return (32-bit value, six-bit blocks, four-bit outputs)."""
    check_width(x48, 48, "S-box input")
    sixes = tuple((x48 >> (42 - 6 * j)) & 0x3F for j in range(NUM_SBOXES))
    outs = tuple(dynamic_sbox(s, j, ctrl, policy) for j, s in enumerate(sixes))
    value = 0
    for o in outs:
        value = (value << 4) | o
    return value, sixes, outs


def round_function(r32: int, subkey: int, ctrl: ControlWord,
                   policy: RowPermPolicy = RowPermPolicy.MOD24) -> int:
    x = expand(r32) ^ check_width(subkey, 48, "subkey")
    s_out, _, _ = substitute(x, ctrl, policy)
    return permute(s_out, P, 32)


@dataclass(frozen=True)
class RoundTrace:
    index: int
    l_in: int
    r_in: int
    expanded: int
    xored: int
    sixes: tuple[int, ...]
    sbox_outs: tuple[int, ...]
    s_out: int
    f_out: int
    l_out: int
    r_out: int
    control: ControlWord

    def describe(self) -> str:
        return "\n".join([
            f"--- Round {self.index} ---  control: {self.control.to_bits()}",
            f"R(i-1)       {to_bits(self.r_in, 32, 8)}",
            f"E(R)         {to_bits(self.expanded, 48, 6)}",
            f"E(R) ^ Ki    {to_bits(self.xored, 48, 6)}",
            "6-bit blocks " + " ".join(f"{s:06b}" for s in self.sixes),
            "4-bit outs   " + " ".join(f"{o:04b}" for o in self.sbox_outs),
            f"P(S-out)=F   {to_bits(self.f_out, 32, 8)}  (0x{self.f_out:08X})",
            f"L_i = R(i-1) 0x{self.l_out:08X}",
            f"R_i          0x{self.r_out:08X}",
        ])


def feistel_round(l: int, r: int, subkey: int, ctrl: ControlWord,
                  policy: RowPermPolicy = RowPermPolicy.MOD24,
                  index: int = 0) -> tuple[int, int, RoundTrace]:
    expanded = expand(r)
    xored = expanded ^ subkey
    s_out, sixes, outs = substitute(xored, ctrl, policy)
    f = permute(s_out, P, 32)
    new_r = l ^ f
    return r, new_r, RoundTrace(index, l, r, expanded, xored, sixes, outs,
                                s_out, f, r, new_r, ctrl)


@dataclass(frozen=True)
class RoundsResult:
    l16: int
    r16: int
    traces: tuple[RoundTrace, ...]

    @property
    def preoutput(self) -> int:
        """R16 || L16 (the final swap, input to IP^-1)."""
        return join(self.r16, self.l16, 32)


def run_rounds(l0: int, r0: int, round_keys, controls,
               policy: RowPermPolicy = RowPermPolicy.MOD24,
               keep_traces: bool = False) -> RoundsResult:
    if len(round_keys) != len(controls):
        raise ValueError("need one control word per round key")
    l, r, traces = l0, r0, []
    for i, (k, c) in enumerate(zip(round_keys, controls), start=1):
        l, r, t = feistel_round(l, r, k, c, policy, i)
        if keep_traces:
            traces.append(t)
    return RoundsResult(l, r, tuple(traces))
