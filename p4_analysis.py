"""Analysis of the control-word design: bias, entropy, empirical uniformity."""
from __future__ import annotations

import math
from collections import Counter

from .p4_control import (FIELDS, N_ROW_PERMS, ControlWord, ControlWordGenerator,
                         RowPermPolicy)


def row_perm_distribution(policy: RowPermPolicy) -> dict[int, float]:
    """P(permutation index) when the 5-bit code is uniform (MOD24) or
    rejection-sampled (REJECT)."""
    if policy is RowPermPolicy.REJECT:
        return {i: 1 / N_ROW_PERMS for i in range(N_ROW_PERMS)}
    dist = {i: 0.0 for i in range(N_ROW_PERMS)}
    for code in range(32):
        dist[code % N_ROW_PERMS] += 1 / 32
    return dist


def shannon_entropy(dist: dict) -> float:
    return -sum(p * math.log2(p) for p in dist.values() if p > 0)


def min_entropy(dist: dict) -> float:
    return -math.log2(max(dist.values()))


def tv_distance_from_uniform(dist: dict) -> float:
    u = 1 / len(dist)
    return 0.5 * sum(abs(p - u) for p in dist.values())


def config_entropy_per_round(policy: RowPermPolicy) -> float:
    """Shannon entropy (bits) of one round's configuration."""
    others = sum(w for n, w in FIELDS if n != "row_perm")
    return others + shannon_entropy(row_perm_distribution(policy))


def probability_standard_config(policy: RowPermPolicy) -> float:
    """P(round uses T0, identity row order, shift 0, rotation 0), i.e. the
    unmodified DES S-boxes."""
    p_row = row_perm_distribution(policy)[0]          # index 0 = identity
    return p_row * (1 / 8) * (1 / 16) * (1 / 4)


def field_histograms(words: list[ControlWord]) -> dict[str, Counter]:
    return {n: Counter(getattr(w, n) for w in words) for n, _ in FIELDS}


def chi_square(counts: Counter, expected_probs: dict) -> tuple[float, int, float]:
    """Return (statistic, degrees of freedom, approx p-value).
    p-value uses the Wilson-Hilferty normal approximation (adequate for df >= 3)."""
    n = sum(counts.values())
    stat = sum((counts.get(k, 0) - n * p) ** 2 / (n * p) for k, p in expected_probs.items())
    df = len(expected_probs) - 1
    z = ((stat / df) ** (1 / 3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    p = 0.5 * math.erfc(z / math.sqrt(2))
    return stat, df, p


def empirical_field_report(seed: int, n_words: int, policy: RowPermPolicy) -> dict:
    gen = ControlWordGenerator(seed, policy)
    words = [gen.next_word() for _ in range(n_words)]
    hist = field_histograms(words)
    report = {}
    for name, width in FIELDS:
        if name == "row_perm":
            dist = row_perm_distribution(policy)
            counts = Counter({i: 0 for i in dist})
            for code, c in hist[name].items():
                counts[code % N_ROW_PERMS] += c
            report[name] = chi_square(counts, dist)
        else:
            k = 1 << width
            report[name] = chi_square(hist[name], {i: 1 / k for i in range(k)})
    report["bits_per_word"] = gen.bits_consumed / n_words
    return report
