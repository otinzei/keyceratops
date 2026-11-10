"""Time and memory of the batch-GCD step on random 2048-bit odd numbers.

    python benchmarks/bench_batch_gcd.py 20000 100000

(Random odd numbers are as hard for batch GCD as real moduli: its cost depends
on the sizes, not on primality.)
"""

import random
import resource
import sys
import time

from rngaudit import numtheory as nt


def main() -> None:
    sizes = [int(a) for a in sys.argv[1:]] or [5000, 20000]
    print(f"gmpy2: {nt.HAVE_GMPY2}")
    rng = random.Random(0)
    for n in sizes:
        mods = [rng.getrandbits(2048) | (1 << 2047) | 1 for _ in range(n)]
        t = time.perf_counter()
        nt.batch_gcd(mods)
        dt = time.perf_counter() - t
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        print(f"{n:>8} moduli: {dt:7.1f} s   peak RSS {rss:7.0f} MB")


if __name__ == "__main__":
    main()
