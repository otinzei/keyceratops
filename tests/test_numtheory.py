import importlib
import math
import random
import sys

import pytest

from keyceratops import numtheory as nt
from keyceratops import synth


def naive(moduli):
    out = []
    for i, n in enumerate(moduli):
        others = 1
        for j, m in enumerate(moduli):
            if j != i:
                others *= m
        out.append(math.gcd(n, others))
    return out


def make_moduli(rng, count, shared_every=3, bits=64):
    primes = [synth.rand_prime(bits, rng) for _ in range(count * 2)]
    mods = []
    for i in range(count):
        p = primes[0] if i % shared_every == 0 else primes[2 * i]
        q = primes[2 * i + 1]
        mods.append(p * q)
    return sorted(set(mods))


@pytest.mark.parametrize("count", [2, 3, 4, 5, 7, 8, 13])
def test_batch_gcd_matches_naive(count):
    rng = random.Random(count)
    mods = make_moduli(rng, count)
    assert nt.batch_gcd(mods) == naive(mods)


def test_batch_gcd_trivial_inputs():
    assert nt.batch_gcd([]) == []
    assert nt.batch_gcd([15]) == [1]


def test_batch_gcd_coprime_all_ones():
    rng = random.Random(0)
    primes = [synth.rand_prime(48, rng) for _ in range(12)]
    mods = [primes[i] * primes[i + 1] for i in range(0, 12, 2)]
    assert nt.batch_gcd(mods) == [1] * 6


def test_batch_gcd_without_gmpy2(monkeypatch):
    """The pure-Python fallback must give identical answers."""
    mods = make_moduli(random.Random(5), 9)
    expected = nt.batch_gcd(mods)
    monkeypatch.setitem(sys.modules, "gmpy2", None)
    importlib.reload(nt)
    try:
        assert nt.HAVE_GMPY2 is False
        assert nt.batch_gcd(mods) == expected == naive(mods)
        assert nt.fermat_factor(101 * 103, 10) == (101, 103)
    finally:
        monkeypatch.undo()
        importlib.reload(nt)


def test_fermat_finds_close_primes_only():
    rng = random.Random(3)
    p = synth.rand_prime(256, rng)
    q = synth.next_prime(p + (1 << 20), rng)
    f = nt.fermat_factor(p * q, 100)
    assert f == (p, q)
    # unrelated primes: not found within the bound
    r = synth.rand_prime(256, rng)
    assert nt.fermat_factor(p * r, 1000) is None


def test_fermat_rejects_even_and_zero_bound():
    assert nt.fermat_factor(100, 10) is None
    assert nt.fermat_factor(15, 0) is None


def test_small_factor_detection():
    rng = random.Random(4)
    big = synth.rand_prime(128, rng)
    assert nt.has_small_factor(65521 * big)
    assert nt.has_small_factor(2 * big)
    assert not nt.has_small_factor(big * synth.rand_prime(128, rng))
    # primes just above the limit are not "small"
    assert not nt.has_small_factor(synth.next_prime(1 << 17, rng) * big)


def test_perfect_square():
    assert nt.is_perfect_square(10**40)
    assert not nt.is_perfect_square(10**40 + 1)
