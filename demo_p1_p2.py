"""Demo for processes 1-2.  Run from the folder containing the ddes package:
    python3 demo_p1_p2.py
"""
from ddes.p1_input_ip import process_input
from ddes.p2_key_schedule import generate_key_schedule

print("=== Process 1: Input and Initial Permutation ===")
for res in process_input(bytes.fromhex("0123456789ABCDEF"), pad=False):
    print(res.trace())

print("\n=== Process 2: DES Key Schedule ===")
print(generate_key_schedule(bytes.fromhex("133457799BBCDFF1")).trace())
