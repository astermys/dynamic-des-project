"""Original vs hardened Dynamic DES.  Run from the folder containing ddes:
    python3 demo_hardened.py            (about 1.5 minutes)
"""
from ddes.cipher import DynamicDES
from ddes.hardened import HardenedDES
from ddes.security import (avalanche_progression, compare_sbox_quality,
                           hardened_distinct_functions, key_seed_avalanche,
                           recover_seed, sac_matrix, seed_schedule_injectivity,
                           verify_hardened_invariants)

KEY = "133457799BBCDFF1"
variants = {
    "static DES": DynamicDES.from_hex(KEY, None, static=True),
    "original  ": DynamicDES.from_hex(KEY, "CAB3"),
    "hardened  ": HardenedDES.from_hex(KEY, "CAB3"),
}

print("== S-box quality vs the genuine DES S-box in the same position ==")
r = compare_sbox_quality(samples=300)
print(f"original design, {r['samples']} random configs: "
      f"worse differential {r['worse_differential']:.1%}, worse linear {r['worse_linear']:.1%}, "
      f"breaks single-bit criterion {r['violates_single_bit_criterion']:.1%}")
v = verify_hardened_invariants()
print(f"hardened design, ALL {v['functions_checked']} knob combinations: "
      f"{v['functions_with_changed_metrics']} with changed (differential, linear, criterion) metrics")
d = hardened_distinct_functions(0)
print(f"hardened distinct S-box functions per position: {d['distinct_functions']} of {d['configs']} configs")

print("\n== Diffusion by round (mean differing bits of 64) ==")
for name, des in variants.items():
    print(name, " ".join(f"{x:5.1f}" for x in avalanche_progression(des, 300)[:8]), "...")

print("\n== Strict avalanche criterion ==")
for name, des in variants.items():
    s = sac_matrix(des, 100)
    print(f"{name} mean={s['mean_probability']:.4f}  beyond 3.5 sigma={s['fraction_beyond_3.5_sigma']:.4f}")

print("\n== Key / seed sensitivity ==")
for name, cls in (("original ", DynamicDES), ("hardened ", HardenedDES)):
    print(name, key_seed_avalanche(KEY, 0xCAB3, 30, cipher_cls=cls))

print("\n== Seed as a secret (unchanged weakness) ==")
h = variants["hardened  "]
ct = h.encrypt_block(0x0123456789ABCDEF)
print("seed recovered from one known pair + key:",
      [hex(s) for s in recover_seed(bytes.fromhex(KEY), 0x0123456789ABCDEF, ct,
                                    candidates=range(0xCAB3 - 500, 0xCAB3 + 500), cipher_cls=HardenedDES)],
      "(searched 1000 candidates; full space is 65,535)")
