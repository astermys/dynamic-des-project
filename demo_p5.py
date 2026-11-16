"""Demo for process 5.  Run from the folder containing the ddes package:
    python3 demo_p5.py            (add --analysis for the S-box property study)
"""
import sys

from ddes.p1_input_ip import apply_ip, final_permutation
from ddes.p2_key_schedule import generate_key_schedule
from ddes.p3_lfsr import seed_from_bits
from ddes.p4_control import ControlSchedule
from ddes.p5_round import run_rounds
from ddes.p5_sboxes import STATIC_CONTROL, dynamic_sbox_trace

KEY = bytes.fromhex("133457799BBCDFF1")
PLAIN = 0x0123456789ABCDEF
ks = generate_key_schedule(KEY)
ip = apply_ip(PLAIN)

print("=== Round 1, standard DES controls (matches the textbook worked example) ===")
res = run_rounds(ip.l0, ip.r0, ks.round_keys, [STATIC_CONTROL] * 16, keep_traces=True)
print(res.traces[0].describe())
print("Ciphertext (static) : %016X" % final_permutation(res.preoutput))

cs = ControlSchedule.from_seed(seed_from_bits("1100 1010 1011 0011"))
res = run_rounds(ip.l0, ip.r0, ks.round_keys, cs.words, keep_traces=True)
print("\n=== Round 1, dynamic controls from LFSR seed 0xCAB3 ===")
print(res.traces[0].describe())
print("\nS-box 1 stage trace:")
print(" ", dynamic_sbox_trace(res.traces[0].sixes[0], 0, cs.for_round(1)).describe())
print("Ciphertext (dynamic): %016X" % final_permutation(res.preoutput))

if "--analysis" in sys.argv:
    from ddes.p5_analysis import distinct_function_stats, property_report
    print("\n=== Configuration-space study ===")
    for box in range(8):
        s = distinct_function_stats(box)
        r = property_report(box, samples=200)
        print(f"S{box+1}: configs={s['configs']} distinct={s['distinct_functions']} "
              f"max_mult={s['max_multiplicity']} | DDTmax std={r['standard_ddt_max']} "
              f"dyn min/mean/max={r['dynamic_ddt_max_min']}/"
              f"{r['dynamic_ddt_max_mean']:.1f}/{r['dynamic_ddt_max_max']} | "
              f"1-bit criterion={r['frac_meeting_1bit_criterion']:.2f} "
              f"rows bijective={r['frac_rows_bijective']:.2f}")
