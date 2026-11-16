"""Demo for process 4.  Run from the folder containing the ddes package:
    python3 demo_p4.py
"""
from ddes.p3_lfsr import seed_from_bits
from ddes.p4_analysis import (config_entropy_per_round, empirical_field_report,
                              min_entropy, probability_standard_config,
                              row_perm_distribution, shannon_entropy,
                              tv_distance_from_uniform)
from ddes.p4_control import ControlSchedule, ControlWord, RowPermPolicy

seed = seed_from_bits("1100 1010 1011 0011")
print("Diagram example word:", ControlWord.from_bits("101 10101 0110 10").describe())
print()
print(ControlSchedule.from_seed(seed).trace())

print("\n=== Row-permutation policy comparison ===")
for pol in RowPermPolicy:
    d = row_perm_distribution(pol)
    print(f"{pol.value:7s} H={shannon_entropy(d):.3f} bits  H_min={min_entropy(d):.3f} bits  "
          f"TV-from-uniform={tv_distance_from_uniform(d):.4f}  "
          f"config entropy/round={config_entropy_per_round(pol):.3f} bits  "
          f"P(standard DES round)=1/{round(1 / probability_standard_config(pol))}")
    rep = empirical_field_report(seed, 4000, pol)
    print("        bits/word = %.3f; chi-square p-values: %s" % (
        rep["bits_per_word"],
        ", ".join(f"{k}={rep[k][2]:.3f}" for k in ("table", "row_perm", "col_shift", "out_rot"))))
