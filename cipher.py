"""Processes 6-10 assembled: the complete Dynamic DES cipher.

  1  plaintext -> IP -> (L0, R0)                          p1_input_ip
  2  DES key schedule K1..K16                             p2_key_schedule
  3  LFSR control stream                                  p3_lfsr
  4  14 control bits per round                            p4_control
  5  round structure + dynamic S-boxes                    p5_round / p5_sboxes
  6  detailed single S-box example                        DynamicDES.trace_sbox
  7  after all 8 S-boxes: 8 x 4 bits = 32 bits -> P       p5_round.substitute / P
  8  Feistel combine  R_i = L_{i-1} XOR F                 p5_round.feistel_round
  9  repeat for 16 rounds (new control word each round)   p5_round.run_rounds
 10  final permutation IP^-1 -> ciphertext                this module

Decryption = same network with round keys AND control words in reverse order.
Same key + same LFSR seed + same configuration rules -> correct decryption.

Modes: CBC (PKCS#7) and CTR. Neither authenticates; use seal()/open() for
encrypt-then-MAC. Research prototype, not for protecting real data.
"""
from __future__ import annotations

from dataclasses import dataclass

from .bitops import check_width, to_bits
from .p1_input_ip import IPResult, apply_ip, final_permutation
from .modes import MAC_BYTES, BlockModesMixin  # noqa: F401  (re-exported)
from .p2_key_schedule import generate_key_schedule
from .p3_lfsr import validate_seed
from .p4_control import ControlSchedule, ControlWord, RowPermPolicy
from .p5_round import RoundTrace, run_rounds
from .p5_sboxes import STATIC_CONTROL, SboxTrace, dynamic_sbox_trace


@dataclass(frozen=True)
class BlockTrace:
    block: int
    ip: IPResult
    rounds: tuple[RoundTrace, ...]
    preoutput: int
    output: int

    def describe(self, full: bool = False) -> str:
        lines = ["=== Process 1: IP ===", self.ip.trace(), "", "=== Processes 5/8/9: 16 rounds ==="]
        for t in self.rounds:
            if full:
                lines.append(t.describe())
            else:
                lines.append(f"Round {t.index:2d}  ctrl={t.control.to_bits()}  "
                             f"F=0x{t.f_out:08X}  L=0x{t.l_out:08X}  R=0x{t.r_out:08X}")
        lines += ["", "=== Process 10: final permutation ===",
                  f"R16||L16 : {to_bits(self.preoutput, 64, 8)}",
                  f"IP^-1    : {to_bits(self.output, 64, 8)}  (0x{self.output:016X})"]
        return "\n".join(lines)


class DynamicDES(BlockModesMixin):
    def __init__(self, key: bytes | int, lfsr_seed: int | None, *,
                 policy: RowPermPolicy = RowPermPolicy.MOD24, static: bool = False,
                 reject_weak: bool = True, require_odd_parity: bool = False):
        """static=True fixes every round to the standard DES S-boxes (seed
        ignored); the cipher is then ordinary DES, useful for validation."""
        self.policy = policy
        self.static = static
        self.key_schedule = generate_key_schedule(
            key, require_odd_parity=require_odd_parity, reject_weak=reject_weak)
        if static:
            self.control_schedule = None
            self._controls: tuple[ControlWord, ...] = (STATIC_CONTROL,) * 16
        else:
            if lfsr_seed is None:
                raise ValueError("lfsr_seed is required unless static=True")
            self.control_schedule = ControlSchedule.from_seed(
                validate_seed(lfsr_seed), policy=policy)
            self._controls = self.control_schedule.words
        self._enc = (self.key_schedule.round_keys, self._controls)
        self._dec = (self.key_schedule.decryption_order, self._controls[::-1])

    @classmethod
    def from_hex(cls, key_hex: str, seed_hex: str | None, **kw) -> "DynamicDES":
        return cls(bytes.fromhex(key_hex), None if seed_hex is None else int(seed_hex, 16), **kw)

    # ---- single block -------------------------------------------------------
    def _crypt(self, block: int, keys, controls, keep_traces: bool = False):
        check_width(block, 64, "block")
        ip = apply_ip(block)
        res = run_rounds(ip.l0, ip.r0, keys, controls, self.policy, keep_traces)
        return ip, res, final_permutation(res.preoutput)

    def encrypt_block(self, block: int) -> int:
        return self._crypt(block, *self._enc)[2]

    def decrypt_block(self, block: int) -> int:
        return self._crypt(block, *self._dec)[2]

    def trace_block(self, block: int, decrypt: bool = False) -> BlockTrace:
        ip, res, out = self._crypt(block, *(self._dec if decrypt else self._enc), keep_traces=True)
        return BlockTrace(block, ip, res.traces, res.preoutput, out)

    def trace_sbox(self, six: int, box: int, round_no: int) -> SboxTrace:
        """Process 6: stage-by-stage trace of one S-box in a given round (1..16)."""
        if not 1 <= round_no <= 16:
            raise ValueError("round must be 1..16")
        return dynamic_sbox_trace(six, box, self._controls[round_no - 1], self.policy)
