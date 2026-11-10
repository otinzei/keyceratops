"""Raw entropy-source checks: a well-defined subset of NIST SP 800-90B.

What is implemented (exactly as specified, all on *raw* samples taken from the
noise source before any conditioning):

* the Most Common Value (MCV) min-entropy estimator (SP 800-90B 6.3.1)
* the Repetition Count Test (4.4.1)
* the Adaptive Proportion Test (4.4.2)

What is NOT implemented: the other nine estimators of 6.3 and the IID
permutation tests. The final SP 800-90B assessment is the *minimum* over all
estimators, so the MCV figure printed here is an **upper bound** on the
assessed min-entropy: if it is already low, the source fails; if it is high,
that proves nothing. Use NIST's reference tool for certification evidence.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass

Z_99 = 2.5758293035489004  # z for the 99% one-sided bound used by 6.3.1


@dataclass
class EntropyReport:
    samples: int
    bits_per_sample: int
    mcv_min_entropy: float  # bits / sample, 99% confidence lower bound
    most_common_value: int
    most_common_fraction: float
    claimed_h: float
    rct_cutoff: int
    rct_failures: int
    apt_window: int
    apt_cutoff: int
    apt_failures: int

    @property
    def claim_consistent(self) -> bool:
        """False if the data contradict the claimed entropy outright."""
        return self.mcv_min_entropy + 1e-9 >= self.claimed_h

    @property
    def healthy(self) -> bool:
        return (
            self.claim_consistent and self.rct_failures == 0 and self.apt_failures == 0
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["claim_consistent"] = self.claim_consistent
        d["healthy"] = self.healthy
        return d


def to_samples(data: bytes, bits_per_sample: int, packed: bool = False) -> list[int]:
    """Turn a byte string into samples.

    Default: one sample per byte, masked to ``bits_per_sample`` bits.
    ``packed=True``: the file is a bitstream (MSB first) of 1-bit samples.
    """
    if packed:
        if bits_per_sample != 1:
            raise ValueError("packed input implies 1-bit samples")
        return [(b >> i) & 1 for b in data for i in range(7, -1, -1)]
    if not 1 <= bits_per_sample <= 8:
        raise ValueError("bits_per_sample must be in 1..8")
    mask = (1 << bits_per_sample) - 1
    return [b & mask for b in data]


def mcv_min_entropy(samples: list[int]) -> tuple[float, int, float]:
    """SP 800-90B 6.3.1. Returns (min-entropy, most common value, p-hat)."""
    n = len(samples)
    if n < 2:
        raise ValueError("need at least 2 samples")
    counts: dict[int, int] = {}
    for x in samples:
        counts[x] = counts.get(x, 0) + 1
    mode, top = max(counts.items(), key=lambda kv: (kv[1], -kv[0]))
    p_hat = top / n
    p_u = min(1.0, p_hat + Z_99 * math.sqrt(p_hat * (1.0 - p_hat) / (n - 1)))
    return -math.log2(p_u), mode, p_hat


def _binom_cutoff(window: int, p: float, alpha: float) -> int:
    """Smallest k with P(Binomial(window, p) > k) <= alpha (CRITBINOM)."""
    if p >= 1.0:
        return window
    lg = math.lgamma
    log_p, log_q = math.log(p), math.log1p(-p)
    pmf = [
        math.exp(
            lg(window + 1) - lg(i + 1) - lg(window - i + 1)
            + i * log_p + (window - i) * log_q
        )
        for i in range(window + 1)
    ]
    tail = 0.0
    tails = [0.0] * (window + 1)  # tails[k] = P(X > k)
    for k in range(window, -1, -1):
        tails[k] = tail
        tail += pmf[k]
    for k in range(window + 1):
        if tails[k] <= alpha:
            return k
    return window


def rct_cutoff(h: float, alpha_exp: int = 20) -> int:
    """C = 1 + ceil(-log2(alpha) / H)  (4.4.1)."""
    return 1 + math.ceil(alpha_exp / h)


def apt_cutoff(h: float, window: int, alpha_exp: int = 20) -> int:
    """C = 1 + CRITBINOM(W, 2^-H, 1 - alpha)  (4.4.2)."""
    return 1 + _binom_cutoff(window, 2.0 ** (-h), 2.0 ** (-alpha_exp))


def repetition_count_failures(samples: list[int], cutoff: int) -> int:
    fails, run, prev = 0, 0, None
    for x in samples:
        if x == prev:
            run += 1
            if run >= cutoff:
                fails += 1
                run = 1
        else:
            prev, run = x, 1
    return fails


def adaptive_proportion_failures(samples: list[int], window: int, cutoff: int) -> int:
    fails = 0
    for start in range(0, len(samples) - window + 1, window):
        ref = samples[start]
        count = 1
        for x in samples[start + 1 : start + window]:
            if x == ref:
                count += 1
        if count >= cutoff:
            fails += 1
    return fails


def assess(
    samples: list[int], bits_per_sample: int, claimed_h: float | None = None
) -> EntropyReport:
    """Run MCV plus both health tests.

    ``claimed_h`` is the designer's min-entropy claim per sample; the health
    test cutoffs are derived from it. Default: the MCV estimate itself,
    capped to the sample width and floored at 0.01 so degenerate data (a
    stuck source, MCV estimate 0) still yields finite cutoffs and then fails
    them, instead of crashing.
    """
    h_mcv, mode, p_hat = mcv_min_entropy(samples)
    h_claim = (
        claimed_h
        if claimed_h is not None
        else max(min(h_mcv, float(bits_per_sample)), 0.01)
    )
    if not 0 < h_claim <= bits_per_sample:
        raise ValueError(f"claimed entropy must be in (0, {bits_per_sample}]")
    # SP 800-90B 4.4.2: W = 1024 for binary sources, 512 otherwise.
    window = 1024 if bits_per_sample == 1 else 512
    rc = rct_cutoff(h_claim)
    ac = apt_cutoff(h_claim, window)
    return EntropyReport(
        samples=len(samples),
        bits_per_sample=bits_per_sample,
        mcv_min_entropy=h_mcv,
        most_common_value=mode,
        most_common_fraction=p_hat,
        claimed_h=h_claim,
        rct_cutoff=rc,
        rct_failures=repetition_count_failures(samples, rc),
        apt_window=window,
        apt_cutoff=ac,
        apt_failures=adaptive_proportion_failures(samples, window, ac),
    )
