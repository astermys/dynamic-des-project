"""Statistical and algebraic analysis of the LFSR control stream."""
from __future__ import annotations

import math
from collections import Counter


# ---- Golomb's randomness postulates (full period) ----------------------------
def golomb_report(bits: list[int], autocorr_step: int = 1) -> dict:
    n = len(bits)
    ones = sum(bits)
    # runs, circular: start at a boundary
    k = next((i for i in range(n) if bits[i] != bits[i - 1]), None)
    if k is None:
        raise ValueError("constant sequence")
    rot = bits[k:] + bits[:k]
    runs, cur = Counter(), 1
    for i in range(1, n):
        if rot[i] == rot[i - 1]:
            cur += 1
        else:
            runs[(rot[i - 1], cur)] += 1
            cur = 1
    runs[(rot[-1], cur)] += 1
    run_len = Counter()
    for (_, ln), cnt in runs.items():
        run_len[ln] += cnt
    # two-level autocorrelation via big-int rotation
    val = int("".join(map(str, bits)), 2)
    full = (1 << n) - 1
    ac = set()
    for sh in range(autocorr_step, n, autocorr_step):
        rotated = ((val << sh) | (val >> (n - sh))) & full
        disagreements = bin(val ^ rotated).count("1")
        ac.add(n - 2 * disagreements)       # agreements - disagreements
    return {"length": n, "ones": ones, "zeros": n - ones,
            "total_runs": sum(run_len.values()), "runs_by_length": dict(sorted(run_len.items())),
            "autocorrelation_values": sorted(ac)}


# ---- NIST SP 800-22 (subset) --------------------------------------------------
def nist_monobit(bits: list[int]) -> float:
    n = len(bits)
    s = abs(sum(2 * b - 1 for b in bits)) / math.sqrt(n)
    return math.erfc(s / math.sqrt(2))


def nist_runs(bits: list[int]) -> float:
    n, ones = len(bits), sum(bits)
    pi = ones / n
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return 0.0
    v = 1 + sum(bits[i] != bits[i + 1] for i in range(n - 1))
    return math.erfc(abs(v - 2 * n * pi * (1 - pi)) / (2 * math.sqrt(2 * n) * pi * (1 - pi)))


# ---- Linear complexity (Berlekamp-Massey over GF(2)) ---------------------------
def berlekamp_massey(s: list[int]) -> tuple[int, list[int]]:
    """Return (L, C) with C[0]=1 and s[n] = XOR_{i=1..L} C[i]*s[n-i]."""
    C, B = [1], [1]
    L, m = 0, 1
    for n in range(len(s)):
        d = s[n]
        for i in range(1, L + 1):
            if i < len(C):
                d ^= C[i] & s[n - i]
        if d == 0:
            m += 1
            continue
        T = C[:]
        C = C + [0] * (len(B) + m - len(C))
        for i, b in enumerate(B):
            C[i + m] ^= b
        if 2 * L <= n:
            L, B, m = n + 1 - L, T, 1
        else:
            m += 1
    return L, C + [0] * (L + 1 - len(C))


def predict_from_recurrence(prefix: list[int], C: list[int], count: int) -> list[int]:
    out = list(prefix)
    L = len(C) - 1
    for _ in range(count):
        n = len(out)
        out.append(sum(C[i] & out[n - i] for i in range(1, L + 1)) & 1)
    return out[len(prefix):]
