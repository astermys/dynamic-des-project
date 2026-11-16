"""Process 3: LFSR bit generation (control stream).

seed (16 bits, non-zero) -> LFSR (x^16 + x^14 + x^13 + x^11 + 1)
                         -> pseudo-random bit stream, consumed sequentially

Conventions (stated explicitly because they differ between textbooks):
  * Polynomial exponents (16, 14, 13, 11) are "taps": 1-indexed positions in
    the state register counted from the output end (position 16 = MSB).
  * State shifts left; the output bit is the MSB before the shift; the new
    LSB is the XOR of the tapped bits.
  * The sequence therefore satisfies s[n+16] = s[n]^s[n+2]^s[n+3]^s[n+5],
    whose characteristic polynomial is the RECIPROCAL of the tap polynomial.
    Both are primitive, so the period is 2^16 - 1 = 65535 either way.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterator

DEGREE = 16
PERIOD = (1 << DEGREE) - 1          # 65535
DEFAULT_EXPONENTS = (16, 14, 13, 11, 0)


# ---- GF(2)[x] arithmetic (polynomials as Python ints, bit e = coeff of x^e) --
def gf2_mulmod(a: int, b: int, mod: int) -> int:
    deg = mod.bit_length() - 1
    res = 0
    while b:
        if b & 1:
            res ^= a
        b >>= 1
        a <<= 1
        if (a >> deg) & 1:
            a ^= mod
    return res


def gf2_mod(a: int, mod: int) -> int:
    deg = mod.bit_length() - 1
    while a.bit_length() > deg:
        a ^= mod << (a.bit_length() - 1 - deg)
    return a


def gf2_powmod(base: int, exp: int, mod: int) -> int:
    result, base = 1, gf2_mod(base, mod)
    while exp:
        if exp & 1:
            result = gf2_mulmod(result, base, mod)
        base = gf2_mulmod(base, base, mod)
        exp >>= 1
    return result


def _prime_factors(n: int) -> list[int]:
    out, p = [], 2
    while p * p <= n:
        if n % p == 0:
            out.append(p)
            while n % p == 0:
                n //= p
        p += 1
    if n > 1:
        out.append(n)
    return out


@dataclass(frozen=True)
class Polynomial:
    """A GF(2) polynomial given by its exponents, e.g. (16, 14, 13, 11, 0)."""
    exponents: tuple[int, ...]

    def __post_init__(self):
        e = self.exponents
        if list(e) != sorted(set(e), reverse=True):
            raise ValueError("exponents must be unique and descending")
        if e[-1] != 0:
            raise ValueError("constant term (x^0) is required for an LFSR")

    @property
    def degree(self) -> int:
        return self.exponents[0]

    @property
    def as_int(self) -> int:
        return sum(1 << e for e in self.exponents)

    @property
    def taps(self) -> tuple[int, ...]:
        return tuple(e for e in self.exponents if e != 0)

    def reciprocal(self) -> "Polynomial":
        d = self.degree
        return Polynomial(tuple(sorted((d - e for e in self.exponents), reverse=True)))

    def is_primitive(self) -> bool:
        """x must have multiplicative order 2^n - 1 modulo the polynomial."""
        n, p = self.degree, self.as_int
        order = (1 << n) - 1
        if gf2_powmod(2, order, p) != 1:
            return False
        return all(gf2_powmod(2, order // q, p) != 1 for q in _prime_factors(order))

    def __str__(self) -> str:
        names = {0: "1", 1: "x"}
        return " + ".join(names.get(e, f"x^{e}") for e in self.exponents)


DEFAULT_POLY = Polynomial(DEFAULT_EXPONENTS)


# ---- seed handling ---------------------------------------------------------
def validate_seed(seed: int, degree: int = DEGREE) -> int:
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise TypeError("seed must be an int")
    if not 1 <= seed < (1 << degree):
        raise ValueError(f"seed must be in 1..{(1 << degree) - 1} (all-zero locks the LFSR)")
    return seed


def seed_from_bits(s: str) -> int:
    """'1100 1010 1011 0011' -> 0xCAB3 (spaces ignored)."""
    s = s.replace(" ", "")
    if len(s) != DEGREE or set(s) - {"0", "1"}:
        raise ValueError(f"need exactly {DEGREE} binary digits")
    return validate_seed(int(s, 2))


def derive_seed(key: bytes, context: bytes = b"ddes/lfsr/v1") -> int:
    """OPTIONAL: derive a non-zero 16-bit seed from the DES key (SHA-256 with
    rejection of zero). The source design keeps key and LFSR seed separate;
    this is a convenience for experiments only."""
    counter = 0
    while True:
        h = hashlib.sha256(context + counter.to_bytes(4, "big") + key).digest()
        seed = int.from_bytes(h[:2], "big")
        if seed:
            return seed
        counter += 1


# ---- LFSRs -----------------------------------------------------------------
class FibonacciLFSR:
    def __init__(self, seed: int, poly: Polynomial = DEFAULT_POLY):
        self.poly = poly
        self.degree = poly.degree
        self._mask = (1 << self.degree) - 1
        self.state = validate_seed(seed, self.degree)
        self._seed = self.state

    def step(self) -> int:
        out = (self.state >> (self.degree - 1)) & 1
        fb = 0
        for t in self.poly.taps:
            fb ^= (self.state >> (t - 1)) & 1
        self.state = ((self.state << 1) | fb) & self._mask
        return out

    def bits(self, n: int) -> list[int]:
        return [self.step() for _ in range(n)]

    def __iter__(self) -> Iterator[int]:
        while True:
            yield self.step()

    def clone(self) -> "FibonacciLFSR":
        c = FibonacciLFSR(self._seed, self.poly)
        c.state = self.state
        return c

    def measure_period(self, limit: int | None = None) -> int:
        """Steps until the state first repeats (<= 2^n - 1 for non-zero seeds)."""
        limit = limit or (1 << self.degree)
        probe = self.clone()
        start = probe.state
        for n in range(1, limit + 1):
            probe.step()
            if probe.state == start:
                return n
        raise RuntimeError("period exceeds limit")

    def recurrence_polynomial(self) -> Polynomial:
        d = self.degree
        return Polynomial(tuple(sorted({d - t for t in self.poly.taps} | {d}, reverse=True)))


class GaloisLFSR:
    """Galois (internal-XOR) form. Same polynomial, different state mapping;
    the emitted sequence is a cyclic shift of the Fibonacci sequence."""

    def __init__(self, seed: int, poly: Polynomial = DEFAULT_POLY):
        self.poly = poly
        self.degree = poly.degree
        self.state = validate_seed(seed, self.degree)
        self._toggle = sum(1 << (t - 1) for t in poly.taps)   # 0xB400 for default

    def step(self) -> int:
        out = self.state & 1
        self.state >>= 1
        if out:
            self.state ^= self._toggle
        return out

    def bits(self, n: int) -> list[int]:
        return [self.step() for _ in range(n)]


# ---- consumption interface for later processes ------------------------------
class ControlStream:
    """Sequential consumer of LFSR bits ('used sequentially' in the diagram)."""

    def __init__(self, seed: int, poly: Polynomial = DEFAULT_POLY):
        self._lfsr = FibonacciLFSR(seed, poly)
        self._seed, self._poly = seed, poly
        self.consumed = 0

    def read_bits(self, n: int) -> str:
        if n < 0:
            raise ValueError("n must be >= 0")
        self.consumed += n
        return "".join(map(str, self._lfsr.bits(n)))

    def read_int(self, n: int) -> int:
        """Read n bits as an unsigned integer, first bit = MSB."""
        s = self.read_bits(n)
        return int(s, 2) if s else 0

    def reset(self) -> None:
        self.__init__(self._seed, self._poly)

    def snapshot(self) -> tuple[int, int]:
        return self._lfsr.state, self.consumed

    def restore(self, snap: tuple[int, int]) -> None:
        self._lfsr.state, self.consumed = snap
