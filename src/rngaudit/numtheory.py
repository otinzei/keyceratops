"""Number theory helpers. Uses gmpy2 transparently when it is installed."""

from __future__ import annotations

import math
from functools import lru_cache
from typing import Sequence

try:  # optional accelerator
    import gmpy2

    _mpz = gmpy2.mpz
    _gcd = gmpy2.gcd
    _isqrt = gmpy2.isqrt
    HAVE_GMPY2 = True
except ImportError:  # pragma: no cover - exercised when gmpy2 is absent
    gmpy2 = None
    _mpz = int
    _gcd = math.gcd
    _isqrt = math.isqrt
    HAVE_GMPY2 = False


def product_tree(values: Sequence[int]) -> list[list]:
    level = [_mpz(v) for v in values]
    tree = [level]
    while len(level) > 1:
        level = [
            level[i] * level[i + 1] if i + 1 < len(level) else level[i]
            for i in range(0, len(level), 2)
        ]
        tree.append(level)
    return tree


def batch_gcd(moduli: Sequence[int]) -> list[int]:
    """Bernstein's batch GCD.

    Returns ``g[i] = gcd(N_i, prod_{j != i} N_j)`` for pairwise *distinct*
    moduli. ``g[i] > 1`` means N_i shares a factor with another modulus.
    Runs in quasi-linear time in the total input size, which is what makes
    auditing a whole fleet (rather than comparing pairs) feasible.
    """
    n = len(moduli)
    if n < 2:
        return [1] * n
    tree = product_tree(moduli)
    rem = [tree[-1][0]]  # P = product of everything
    for level in reversed(tree[:-1]):
        rem = [rem[i // 2] % (x * x) for i, x in enumerate(level)]
    out: list[int] = []
    for r, m in zip(rem, tree[0]):
        out.append(int(_gcd((r // m) % m, m)))
    return out


def gcd(a: int, b: int) -> int:
    return int(_gcd(_mpz(a), _mpz(b)))


def isqrt(n: int) -> int:
    return int(_isqrt(_mpz(n)))


def is_perfect_square(n: int) -> bool:
    r = isqrt(n)
    return r * r == n


def fermat_factor(n: int, max_iter: int) -> tuple[int, int] | None:
    """Fermat's method, bounded. Succeeds only when the two prime factors are
    close together, which is what a flawed generator that derives q from p
    produces. ``n`` must be odd."""
    if n % 2 == 0 or max_iter <= 0:
        return None
    nn = _mpz(n)
    a = _isqrt(nn)
    if a * a < nn:
        a += 1
    b2 = a * a - nn
    for _ in range(max_iter):
        b = _isqrt(b2)
        if b * b == b2:
            p, q = int(a - b), int(a + b)
            if p > 1:
                return p, q
            return None
        b2 += 2 * a + 1
        a += 1
    return None


@lru_cache(maxsize=4)
def small_primes_product(limit: int = 1 << 16) -> int:
    """Product of all primes below ``limit``."""
    sieve = bytearray([1]) * limit
    sieve[0:2] = b"\x00\x00"
    for i in range(2, math.isqrt(limit) + 1):
        if sieve[i]:
            sieve[i * i :: i] = bytearray(len(sieve[i * i :: i]))
    prod = _mpz(1)
    for p, flag in enumerate(sieve):
        if flag:
            prod *= p
    return int(prod)


def has_small_factor(n: int, limit: int = 1 << 16) -> bool:
    """True if ``n`` has a prime factor below ``limit``."""
    if n < 2:
        return False
    return gcd(n, small_primes_product(limit) % n) > 1
