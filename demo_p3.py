"""Demo for process 3.  Run from the folder containing the ddes package:
    python3 demo_p3.py
"""
from ddes.p3_analysis import (berlekamp_massey, golomb_report, nist_monobit,
                              nist_runs, predict_from_recurrence)
from ddes.p3_lfsr import (DEFAULT_POLY, PERIOD, ControlStream, FibonacciLFSR,
                          seed_from_bits)

seed = seed_from_bits("1100 1010 1011 0011")
print("Polynomial        :", DEFAULT_POLY)
print("Primitive         :", DEFAULT_POLY.is_primitive())
print("Seed              : 0x%04X" % seed)
print("Measured period   :", FibonacciLFSR(seed).measure_period(), "(expected", PERIOD, ")")

stream = ControlStream(seed)
print("First 64 bits     :", stream.read_bits(64))

bits = FibonacciLFSR(seed).bits(PERIOD)
g = golomb_report(bits, autocorr_step=61)
print("Ones / zeros      :", g["ones"], "/", g["zeros"])
print("Total runs        :", g["total_runs"])
print("Autocorrelation   :", g["autocorrelation_values"])
print("NIST monobit p    : %.4f" % nist_monobit(bits[:20000]))
print("NIST runs p       : %.4f" % nist_runs(bits[:20000]))

obs = bits[:32]
L, C = berlekamp_massey(obs)
pred = predict_from_recurrence(obs, C, 64)
print("\nLinear complexity from 32 observed bits:", L)
print("Predicted next 64 :", "".join(map(str, pred)))
print("Actual next 64    :", "".join(map(str, bits[32:96])))
print("Attack succeeds   :", pred == bits[32:96])
