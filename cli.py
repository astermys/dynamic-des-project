"""Command-line interface:  python -m ddes <command> ...

  enc      --key HEX16 --seed HEX --text "msg" [--mode cbc|ctr]
  dec      --key HEX16 --seed HEX --hex CIPHERTEXT_HEX [--mode cbc|ctr]
  block    --key HEX16 --seed HEX --plain HEX16 [--decrypt] [--trace] [--full]
  sbox     --key HEX16 --seed HEX --round N --box 1..8 --six 011011
  controls --seed HEX [--policy mod24|reject] [--variant original|hardened]
Add --variant hardened for the property-preserving design.
Use --static for standard DES, --allow-weak to permit weak DES keys.
"""
from __future__ import annotations

import argparse
import sys

from .cipher import DynamicDES
from .hardened import HardenedControlSchedule, HardenedDES
from .p3_lfsr import validate_seed
from .p4_control import ControlSchedule, RowPermPolicy


def _cipher_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--key", required=True, help="DES key, 16 hex digits")
    sp.add_argument("--seed", help="16-bit LFSR seed, hex (not needed with --static)")
    sp.add_argument("--policy", choices=[p.value for p in RowPermPolicy], default="mod24")
    sp.add_argument("--variant", choices=["original", "hardened"], default="original",
                    help="original = diagram design; hardened = property-preserving knobs")
    sp.add_argument("--static", action="store_true", help="standard DES S-boxes")
    sp.add_argument("--allow-weak", action="store_true")


def _make(a):
    if a.variant == "hardened":
        return HardenedDES.from_hex(a.key, a.seed, static=a.static, reject_weak=not a.allow_weak)
    return DynamicDES.from_hex(a.key, a.seed, policy=RowPermPolicy(a.policy),
                               static=a.static, reject_weak=not a.allow_weak)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ddes", description="Dynamic DES (LFSR S-boxes)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("enc"); _cipher_args(s)
    s.add_argument("--text", required=True); s.add_argument("--mode", choices=["cbc", "ctr"], default="cbc")
    s = sub.add_parser("dec"); _cipher_args(s)
    s.add_argument("--hex", required=True); s.add_argument("--mode", choices=["cbc", "ctr"], default="cbc")
    s = sub.add_parser("block"); _cipher_args(s)
    s.add_argument("--plain", required=True, help="64-bit block, 16 hex digits")
    s.add_argument("--decrypt", action="store_true")
    s.add_argument("--trace", action="store_true"); s.add_argument("--full", action="store_true")
    s = sub.add_parser("sbox"); _cipher_args(s)
    s.add_argument("--round", type=int, required=True); s.add_argument("--box", type=int, required=True)
    s.add_argument("--six", required=True, help="6 input bits, e.g. 011011")
    s = sub.add_parser("controls")
    s.add_argument("--seed", required=True)
    s.add_argument("--policy", choices=[p.value for p in RowPermPolicy], default="mod24")
    s.add_argument("--variant", choices=["original", "hardened"], default="original")

    a = ap.parse_args(argv)
    try:
        if a.cmd == "controls":
            seed = validate_seed(int(a.seed, 16))
            if a.variant == "hardened":
                print(HardenedControlSchedule.from_seed(seed).trace())
            else:
                print(ControlSchedule.from_seed(seed, policy=RowPermPolicy(a.policy)).trace())
            return 0
        des = _make(a)
        if a.cmd == "enc":
            print(des.encrypt(a.text.encode(), a.mode).hex())
        elif a.cmd == "dec":
            print(des.decrypt(bytes.fromhex(a.hex), a.mode).decode())
        elif a.cmd == "block":
            blk = int(a.plain, 16)
            if a.trace:
                print(des.trace_block(blk, a.decrypt).describe(full=a.full))
            else:
                out = des.decrypt_block(blk) if a.decrypt else des.encrypt_block(blk)
                print(f"{out:016X}")
        elif a.cmd == "sbox":
            if not 1 <= a.box <= 8:
                raise ValueError("box must be 1..8")
            print(des.trace_sbox(int(a.six, 2), a.box - 1, a.round).describe())
    except (ValueError, TypeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
