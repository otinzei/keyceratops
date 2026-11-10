import math
import os
import random

import pytest

from rngaudit import entropy as e


def test_cutoffs_match_sp800_90b_table_2():
    # SP 800-90B, Table 2 (alpha = 2^-20): non-binary W=512, binary W=1024.
    assert [e.apt_cutoff(h, 512) for h in (1, 2, 4, 8)] == [311, 177, 62, 13]
    assert e.apt_cutoff(1, 1024) == 589
    # RCT, 4.4.1: C = 1 + ceil(20 / H); worked example in the spec: H=2 -> 11
    assert e.rct_cutoff(2.0) == 11
    assert e.rct_cutoff(1.0) == 21


def test_window_choice_follows_spec():
    rng = random.Random(0)
    bits = e.to_samples(bytes(rng.getrandbits(8) for _ in range(5000)), 1)
    assert e.assess(bits, 1).apt_window == 1024
    assert e.assess(bits, 1).apt_cutoff > 500
    byts = e.to_samples(bytes(rng.getrandbits(8) for _ in range(5000)), 8)
    assert e.assess(byts, 8).apt_window == 512


def test_mcv_uniform_bytes_is_close_to_8_bits():
    rng = random.Random(1)
    data = bytes(rng.getrandbits(8) for _ in range(400_000))
    h, _, p = e.mcv_min_entropy(e.to_samples(data, 8))
    assert 7.7 < h <= 8.0
    assert 0.0039 < p < 0.0043


def test_mcv_formula_by_hand():
    samples = [0] * 90 + [1] * 10
    p_hat = 0.9
    p_u = p_hat + 2.5758293035489004 * math.sqrt(p_hat * (1 - p_hat) / 99)
    h, mode, _ = e.mcv_min_entropy(samples)
    assert mode == 0
    assert h == pytest.approx(-math.log2(p_u))


def test_mcv_all_same_value_is_zero_entropy():
    assert e.mcv_min_entropy([7] * 1000)[0] == 0.0


def test_healthy_source_passes():
    data = os.urandom(300_000)
    rep = e.assess(e.to_samples(data, 8), 8, claimed_h=7.0)
    assert rep.healthy and rep.rct_failures == 0 and rep.apt_failures == 0


def test_stuck_source_fails_without_crashing():
    rep = e.assess([0x41] * 5000, 8)
    assert not rep.healthy
    assert rep.rct_failures > 0


def test_overclaiming_is_caught():
    # A source that only ever emits 16 values cannot deliver 7 bits/sample.
    rng = random.Random(2)
    samples = [rng.randrange(16) for _ in range(100_000)]
    rep = e.assess(samples, 8, claimed_h=7.0)
    assert not rep.claim_consistent and not rep.healthy
    assert rep.mcv_min_entropy < 4.1


def test_repetition_count_catches_a_burst():
    rng = random.Random(3)
    samples = [rng.randrange(256) for _ in range(20_000)]
    samples[5000:5030] = [9] * 30
    rep = e.assess(samples, 8, claimed_h=7.5)
    assert rep.rct_failures >= 1


def test_adaptive_proportion_catches_a_biased_window():
    rng = random.Random(4)
    samples = [rng.randrange(256) for _ in range(20_000)]
    # inside one 512-window, make value 3 appear every 4th sample: fine for RCT, not APT
    for i in range(1024, 1536, 4):
        samples[i] = 3
    samples[1024] = 3
    rep = e.assess(samples, 8, claimed_h=7.5)
    assert rep.rct_failures == 0
    assert rep.apt_failures >= 1


def test_packed_bits():
    assert e.to_samples(b"\xa5", 1, packed=True) == [1, 0, 1, 0, 0, 1, 0, 1]
    with pytest.raises(ValueError):
        e.to_samples(b"\xa5", 4, packed=True)


def test_sample_width_validation():
    with pytest.raises(ValueError):
        e.to_samples(b"abc", 9)
    with pytest.raises(ValueError):
        e.assess([1, 2, 3, 4], 8, claimed_h=9.0)
