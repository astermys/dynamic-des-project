"""Security evaluation of Dynamic DES (empirical; not a proof of anything).

A. avalanche_progression  - diffusion round by round, static DES vs dynamic
B. sac_matrix             - strict avalanche criterion over the full cipher
C. key_seed_avalanche     - sensitivity to key bits and LFSR-seed bits
D. seed_schedule_injectivity, recover_seed, seed_search_rate
                          - the 16-bit seed as a brute-forceable secret
E. configuration_audit    - differential / single-bit criterion of every
                            (table, row-perm, column-shift) configuration
F. verify_property_preserving_knobs
                          - which knob types are 'free' for S-box quality
"""
from __future__ import annotations

import math
import random
import time
from collections import Counter

from .bitops import popcount, rotl
from .cipher import DynamicDES
from .p3_lfsr import validate_seed
from .p4_control import N_ROW_PERMS, ROW_PERMS, ControlSchedule, ControlWord
from .p5_analysis import min_single_bit_output_change, sbox_function
from .p5_sboxes import split_six
from .tables import DES_SBOXES


# ---- A. diffusion by round -------------------------------------------------------
def avalanche_progression(des: DynamicDES, samples: int = 300, seed: int = 1) -> list[float]:
    """Mean number of differing bits (of 64) in the (L,R) state after round r,
    for r = 1..16, when one random plaintext bit is flipped."""
    rng = random.Random(seed)
    totals = [0] * 16
    for _ in range(samples):
        m = rng.getrandbits(64)
        m2 = m ^ (1 << rng.randrange(64))
        a = des.trace_block(m).rounds
        b = des.trace_block(m2).rounds
        for r in range(16):
            sa = (a[r].l_out << 32) | a[r].r_out
            sb = (b[r].l_out << 32) | b[r].r_out
            totals[r] += popcount(sa ^ sb)
    return [t / samples for t in totals]


# ---- B. strict avalanche criterion ------------------------------------------------
def sac_matrix(des: DynamicDES, samples_per_bit: int = 100, seed: int = 2) -> dict:
    """P(output bit i flips | input bit j flips) for all 64x64 pairs. Under SAC
    each probability is 1/2; sampling noise has sigma = 0.5/sqrt(N)."""
    rng = random.Random(seed)
    n = samples_per_bit
    probs = []
    for j in range(64):
        counts = [0] * 64
        for _ in range(n):
            m = rng.getrandbits(64)
            d = des.encrypt_block(m) ^ des.encrypt_block(m ^ (1 << j))
            for i in range(64):
                counts[i] += (d >> i) & 1
        probs.append([c / n for c in counts])
    flat = [p for row in probs for p in row]
    sigma = 0.5 / math.sqrt(n)
    return {"samples_per_bit": n, "sigma": sigma,
            "mean_probability": sum(flat) / len(flat),
            "max_abs_deviation": max(abs(p - 0.5) for p in flat),
            "fraction_beyond_3.5_sigma": sum(abs(p - 0.5) > 3.5 * sigma for p in flat) / len(flat)}


# ---- C. key / seed sensitivity ------------------------------------------------------
_PARITY_BITS = {8 * i for i in range(8)}          # bit positions (LSB=0) of parity


def key_seed_avalanche(key_hex: str, seed: int, samples: int = 40, rng_seed: int = 3,
                       cipher_cls=DynamicDES) -> dict:
    rng = random.Random(rng_seed)
    base_key = bytes.fromhex(key_hex)
    base = cipher_cls(base_key, seed, reject_weak=False)
    key_total = key_n = seed_total = seed_n = 0
    for bit in range(64):
        if bit in _PARITY_BITS:
            continue
        k = bytearray(base_key)
        k[7 - bit // 8] ^= 1 << (bit % 8)
        variant = cipher_cls(bytes(k), seed, reject_weak=False)
        for _ in range(samples):
            m = rng.getrandbits(64)
            key_total += popcount(base.encrypt_block(m) ^ variant.encrypt_block(m))
            key_n += 1
    for bit in range(16):
        s2 = seed ^ (1 << bit)
        if s2 == 0:
            continue
        variant = cipher_cls(base_key, s2, reject_weak=False)
        for _ in range(samples):
            m = rng.getrandbits(64)
            seed_total += popcount(base.encrypt_block(m) ^ variant.encrypt_block(m))
            seed_n += 1
    return {"mean_bits_changed_per_key_bit_flip": key_total / key_n,
            "mean_bits_changed_per_seed_bit_flip": seed_total / seed_n}


# ---- D. the seed as a secret ---------------------------------------------------------
def seed_schedule_injectivity(limit: int | None = None) -> tuple[int, int]:
    """(#seeds tried, #distinct 16-round control schedules). Equal numbers mean
    every seed yields a different schedule, so the seed space is not collapsed."""
    top = 65535 if limit is None else limit
    seen = set()
    for s in range(1, top + 1):
        seen.add(tuple(w.to_int() for w in ControlSchedule.from_seed(s).words))
    return top, len(seen)


def recover_seed(key: bytes, plaintext: int, ciphertext: int, candidates=None,
                 cipher_cls=DynamicDES) -> list[int]:
    """Known-plaintext attack when the DES key is known (or already recovered):
    try every LFSR seed. Returns all seeds consistent with the pair."""
    hits = []
    for s in (range(1, 65536) if candidates is None else candidates):
        if s == 0:
            continue
        if cipher_cls(key, s, reject_weak=False).encrypt_block(plaintext) == ciphertext:
            hits.append(s)
    return hits


def seed_search_rate(key: bytes, trials: int = 500) -> dict:
    t0 = time.perf_counter()
    for s in range(1, trials + 1):
        DynamicDES(key, s, reject_weak=False).encrypt_block(0x0123456789ABCDEF)
    per = (time.perf_counter() - t0) / trials
    return {"seconds_per_candidate": per, "full_seed_space_seconds": per * 65535}


# ---- E. configuration audit -----------------------------------------------------------
def reach_ddt(f: tuple[int, ...]) -> int:
    """Largest difference-table entry over input differences that activate ONE
    S-box through the expansion (only the middle four bits b2..b5 set)."""
    best = 0
    for dx in range(2, 32, 2):
        c = [0] * 16
        for x in range(64):
            c[f[x] ^ f[x ^ dx]] += 1
        best = max(best, max(c))
    return best


def hamming_isometry_row_perms() -> list[int]:
    """Indices of row orderings that preserve Hamming distance between the
    2-bit row labels (the 8 automorphisms of the square, i.e. the dihedral group)."""
    out = []
    for idx, p in enumerate(ROW_PERMS):
        if all(popcount(p[a] ^ p[b]) == popcount(a ^ b) for a in range(4) for b in range(4)):
            out.append(idx)
    return out


def configuration_audit() -> dict:
    """Evaluate all 8 x 24 x 16 = 3072 (table, row-perm, shift) configurations
    on all 8 S-boxes. Output rotation is omitted: it is a bit permutation of
    the output, so it changes neither the DDT maximum nor the Hamming weights."""
    static = ControlWord(0, 0, 0, 0)
    static_reach = [reach_ddt(sbox_function(b, static)) for b in range(8)]
    worst, crit_ok = {}, set()
    for t in range(8):
        for rp in range(N_ROW_PERMS):
            for cs in range(16):
                c = ControlWord(t, rp, cs, 0)
                fs = [sbox_function(b, c) for b in range(8)]
                worst[(t, rp, cs)] = max(reach_ddt(f) for f in fs)
                if all(min_single_bit_output_change(f) >= 2 for f in fs):
                    crit_ok.add((t, rp, cs))
    static_worst = max(static_reach)
    return {"configs": len(worst), "static_reach_per_box": static_reach,
            "static_worst": static_worst,
            "worst_box_histogram": dict(sorted(Counter(worst.values()).items())),
            "configs_worse_than_static": sum(v > static_worst for v in worst.values()),
            "criterion_ok": sorted(crit_ok),
            "criterion_ok_tables": sorted({k[0] for k in crit_ok}),
            "criterion_ok_shifts": sorted({k[2] for k in crit_ok}),
            "criterion_ok_row_perms": sorted({k[1] for k in crit_ok})}


# ---- F. property-preserving knobs -------------------------------------------------------
def hardened_sbox_function(box: int, table_offset: int, row_perm: tuple[int, ...],
                           col_xor: int, rot: int) -> tuple[int, ...]:
    """Candidate 'safe' configuration (audit only; not wired into the cipher):
    a genuine DES S-box chosen by offset, rows permuted, column index XORed
    with a mask (input translation), output rotated."""
    base = DES_SBOXES[(box + table_offset) % 8]
    f = []
    for x in range(64):
        row, col = split_six(x)
        f.append(rotl(base[row_perm[row]][col ^ col_xor], rot, 4))
    return tuple(f)


def verify_property_preserving_knobs() -> dict:
    d4 = hamming_isometry_row_perms()
    checked = bad = 0
    for box in range(8):
        ref = sbox_function(box, ControlWord(0, 0, 0, 0))
        ref_reach = reach_ddt(ref)
        for idx in d4:
            for col_xor in range(16):
                for rot in range(4):
                    f = hardened_sbox_function(box, 0, ROW_PERMS[idx], col_xor, rot)
                    checked += 1
                    if reach_ddt(f) != ref_reach or min_single_bit_output_change(f) < 2:
                        bad += 1
    return {"functions_checked": checked, "functions_degraded": bad, "row_perms": d4}


# ---- G. linear approximation table and hardened-variant verification -------------------
def lat_max(f: tuple[int, ...]) -> int:
    """Largest |Walsh coefficient| over non-trivial input masks and non-zero
    output masks (bias = value / 64). Computed with a fast Walsh-Hadamard transform."""
    best = 0
    for b in range(1, 16):
        v = [1 - 2 * (popcount(b & f[x]) & 1) for x in range(64)]
        h = 1
        while h < 64:
            for i in range(0, 64, 2 * h):
                for j in range(i, i + h):
                    a, c = v[j], v[j + h]
                    v[j], v[j + h] = a + c, a - c
            h *= 2
        best = max(best, max(abs(w) for w in v[1:]))
    return best


def sbox_metrics(f: tuple[int, ...]) -> tuple[int, int, int]:
    return reach_ddt(f), lat_max(f), min_single_bit_output_change(f)


def verify_hardened_invariants(boxes=range(8)) -> dict:
    """Every hardened configuration of base box b must have exactly the same
    (reach_ddt, lat_max, single-bit criterion) as the genuine DES S-box b."""
    from .hardened import D4_ROW_PERMS
    checked = bad = 0
    for b in boxes:
        ref = sbox_metrics(sbox_function(b, ControlWord(0, 0, 0, 0)))
        for rows in D4_ROW_PERMS:
            for col_xor in range(16):
                for rot in range(4):
                    f = hardened_sbox_function(b, 0, rows, col_xor, rot)
                    checked += 1
                    if sbox_metrics(f) != ref:
                        bad += 1
    return {"functions_checked": checked, "functions_with_changed_metrics": bad}


def compare_sbox_quality(samples: int = 300, seed: int = 5) -> dict:
    """Original dynamic design: how often does a random configuration make a
    S-box worse than the genuine DES S-box in that position? Hardened: by
    construction never (verified above)."""
    rng = random.Random(seed)
    worse_ddt = worse_lat = broke_crit = total = 0
    for b in range(8):
        ref_ddt, ref_lat, _ = sbox_metrics(sbox_function(b, ControlWord(0, 0, 0, 0)))
        for _ in range(samples):
            c = ControlWord(rng.randrange(8), rng.randrange(24), rng.randrange(16), rng.randrange(4))
            f = sbox_function(b, c)
            total += 1
            worse_ddt += reach_ddt(f) > ref_ddt
            worse_lat += lat_max(f) > ref_lat
            broke_crit += min_single_bit_output_change(f) < 2
    return {"samples": total, "worse_differential": worse_ddt / total,
            "worse_linear": worse_lat / total, "violates_single_bit_criterion": broke_crit / total}


def hardened_distinct_functions(position: int) -> dict:
    """How many different S-box functions can the hardened knobs produce at one position?"""
    from .hardened import D4_ROW_PERMS
    seen = set()
    for off in range(8):
        for rows in D4_ROW_PERMS:
            for col_xor in range(16):
                for rot in range(4):
                    seen.add(hardened_sbox_function(position, off, rows, col_xor, rot))
    return {"configs": 8 * 8 * 16 * 4, "distinct_functions": len(seen)}
