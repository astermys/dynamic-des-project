"""Security evaluation report.  Run from the folder containing the ddes package:
    python3 demo_security.py            (about 1 minute)
"""
import time

from ddes.cipher import DynamicDES
from ddes.security import (avalanche_progression, configuration_audit,
                           key_seed_avalanche, recover_seed, sac_matrix,
                           seed_schedule_injectivity, seed_search_rate,
                           verify_property_preserving_knobs)

KEY, SEED = "133457799BBCDFF1", 0xCAB3
static = DynamicDES.from_hex(KEY, None, static=True)
dynamic = DynamicDES.from_hex(KEY, "CAB3")

print("== A. Avalanche by round (mean differing bits of 64) ==")
for name, des in (("static ", static), ("dynamic", dynamic)):
    print(name, " ".join(f"{x:5.1f}" for x in avalanche_progression(des, 300)))

print("\n== B. Strict avalanche criterion (full cipher) ==")
for name, des in (("static ", static), ("dynamic", dynamic)):
    r = sac_matrix(des, 100)
    print(f"{name} mean={r['mean_probability']:.4f} max|dev|={r['max_abs_deviation']:.3f} "
          f"beyond 3.5 sigma={r['fraction_beyond_3.5_sigma']:.4f}")

print("\n== C. Key / seed sensitivity ==")
print(key_seed_avalanche(KEY, SEED, 40))

print("\n== D. Seed as a secret ==")
t0 = time.time()
print("seeds tried / distinct schedules:", seed_schedule_injectivity())
print("  (took %.1fs)" % (time.time() - t0))
rate = seed_search_rate(bytes.fromhex(KEY))
print("search rate: %.2f ms/seed -> full 65,535-seed space in %.0f s" % (
    rate["seconds_per_candidate"] * 1000, rate["full_seed_space_seconds"]))
pt = 0x0123456789ABCDEF
ct = dynamic.encrypt_block(pt)
print("recovered seed(s) from ONE known pair, key known:",
      [hex(s) for s in recover_seed(bytes.fromhex(KEY), pt, ct)])

print("\n== E. Configuration audit (3072 configs x 8 S-boxes) ==")
a = configuration_audit()
print("static best single-box difference count per box:", a["static_reach_per_box"])
print("worst-box histogram (value: #configs):", a["worst_box_histogram"])
print("configs worse than static DES:", a["configs_worse_than_static"], "of", a["configs"])
print("configs keeping DES 1-bit criterion on all boxes:", len(a["criterion_ok"]))
print("  tables:", a["criterion_ok_tables"], " shifts:", a["criterion_ok_shifts"],
      " row-perm indices:", a["criterion_ok_row_perms"])

print("\n== F. Property-preserving knobs (DES S-box + D4 rows + column XOR + rotation) ==")
print(verify_property_preserving_knobs())
