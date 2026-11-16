"""How much does the dynamic configuration really change the S-boxes?"""
from __future__ import annotations

import random
from itertools import product

from .p4_control import ControlWord, N_ROW_PERMS, RowPermPolicy
from .p5_sboxes import STATIC_CONTROL, dynamic_sbox


def sbox_function(box: int, ctrl: ControlWord,
                  policy: RowPermPolicy = RowPermPolicy.MOD24) -> tuple[int, ...]:
    return tuple(dynamic_sbox(x, box, ctrl, policy) for x in range(64))


def all_configs():
    """Every distinct configuration (24 distinct row orderings)."""
    for t, rp, cs, ro in product(range(8), range(N_ROW_PERMS), range(16), range(4)):
        yield ControlWord(t, rp, cs, ro)


def distinct_function_stats(box: int) -> dict:
    seen: dict[tuple, int] = {}
    for c in all_configs():
        f = sbox_function(box, c)
        seen[f] = seen.get(f, 0) + 1
    return {"configs": 8 * N_ROW_PERMS * 16 * 4, "distinct_functions": len(seen),
            "max_multiplicity": max(seen.values())}


def ddt_max(f: tuple[int, ...]) -> int:
    """Largest non-trivial entry of the difference distribution table (DES: 16)."""
    best = 0
    for dx in range(1, 64):
        counts = [0] * 16
        for x in range(64):
            counts[f[x] ^ f[x ^ dx]] += 1
        best = max(best, max(counts))
    return best


def min_single_bit_output_change(f: tuple[int, ...]) -> int:
    """DES design criterion: flipping one input bit changes >= 2 output bits."""
    return min(bin(f[x] ^ f[x ^ (1 << b)]).count("1") for x in range(64) for b in range(6))


def rows_are_bijective(f: tuple[int, ...]) -> bool:
    """Fixing the outer bits (b1,b6) must give a bijection on the 4 middle bits."""
    for row in range(4):
        vals = {f[((row & 2) << 4) | (c << 1) | (row & 1)] for c in range(16)}
        if len(vals) != 16:
            return False
    return True


def property_report(box: int, samples: int = 200, seed: int = 1) -> dict:
    rng = random.Random(seed)
    cfgs = list(all_configs())
    pick = rng.sample(cfgs, samples)
    base = sbox_function(box, STATIC_CONTROL)
    ddts = [ddt_max(sbox_function(box, c)) for c in pick]
    crit = [min_single_bit_output_change(sbox_function(box, c)) >= 2 for c in pick]
    bij = [rows_are_bijective(sbox_function(box, c)) for c in pick]
    return {"box": box + 1, "samples": samples,
            "standard_ddt_max": ddt_max(base),
            "dynamic_ddt_max_min": min(ddts), "dynamic_ddt_max_mean": sum(ddts) / len(ddts),
            "dynamic_ddt_max_max": max(ddts),
            "frac_meeting_1bit_criterion": sum(crit) / samples,
            "frac_rows_bijective": sum(bij) / samples}
