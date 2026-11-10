# rngaudit: design notes, limits, research agenda

Status: v0.1. Everything in "What exists" is implemented and tested. Everything under
"Hypotheses" and "Roadmap" is not, and is labelled as such.

## 1. The problem

A random number generator fails silently. The device works, the certificate validates,
the TLS handshake succeeds. The failure is only visible later, and only in aggregate:

* RSA key generation draws two primes from the generator. If the generator is in the
  same state on two devices for the first prime but diverges before the second, the
  moduli share a prime and both keys fall to a gcd.
* ECDSA needs a fresh secret nonce per signature. A repeated nonce reveals the private
  key from two signatures.
* A generator in the same state on every unit at first boot yields the same key on every
  unit.

Prior work established all of this on the public Internet (Heninger et al., *Mining
your Ps and Qs*, 2012; Lenstra et al., *Ron was wrong, Whit is right*, 2012; Bernstein
et al., smart-card RSA keys, 2013; Breitner and Heninger on biased ECDSA nonces in
cryptocurrencies, 2019). Those were one-off measurement studies by researchers. The
gap `rngaudit` addresses is the other direction: an operator running the same analysis
over **their own** fleet or CA output, repeatably, with a report and a CI exit code.

## 2. What exists (v0.1)

| layer | module | notes |
|---|---|---|
| ingest | `ingest.py` | PEM/DER certs, keys, CSRs; OpenSSH; signatures JSONL; harvests ECDSA signatures out of certificates; skips private keys |
| number theory | `numtheory.py` | Bernstein batch GCD (product/remainder tree), bounded Fermat, small-factor gcd; gmpy2 when present |
| checks | `checks.py` | 17 check ids, see README |
| entropy | `entropy.py` | MCV, RCT, APT from SP 800-90B; cutoffs verified against its Table 2 |
| report | `report.py`, `cli.py` | text / JSON / Markdown; exit codes for CI |
| ground truth | `synth.py` | deterministic fleets with planted failures, including certificates re-signed with a chosen ECDSA nonce, so the nonce checks are tested end to end |

### How it is verified

* Every planted failure type must be found, and the set of check ids fired on the full
  synthetic fleet must equal the planted set exactly (`tests/test_fleet.py`).
* The 32 healthy devices produce zero findings.
* Mutation spot checks: disabling batch GCD, removing signature de-duplication,
  flagging single-holder keys, and inverting the repetition test each make the suite
  fail.
* Reports are asserted not to contain recovered primes in decimal or hex.
* The suite passes with and without gmpy2.

### What a finding means (evidence model)

| check | what it proves | false-positive sources |
|---|---|---|
| `shared-prime` | Mathematical fact: the keys are factorable by anyone. | None for 2-prime RSA. Multi-prime RSA clusters may be mis-grouped (counts still right). |
| `ecdsa-nonce-reuse` | Mathematical fact for the same signer. | Signer identity for non-self-signed certificates is the issuer DN: two distinct CAs sharing a DN could be conflated. |
| `duplicate-key` | One private key on several holders. | A "holder" is a file/host label; renewals in separate files look like sharing (use `--holder dir`). The *cause* (default image vs RNG) is not determined. |
| `ecdsa-shared-r` | Equal `r` across keys has probability about 2^-256 by chance: generator states coincided. | Same as above for signer identity. |
| `rsa-close-primes` | Factoring succeeded. | None. |
| `serial-*` | Policy and hygiene, weaker than the above. | Counters are legitimate in private PKI; hence LOW. |

## 3. What it cannot see

1. **Low entropy without collisions.** A 40-bit generator state gives 2^40 possible
   keys; a fleet of 10^4 will almost never collide, yet an attacker can enumerate the
   space. Fleet analysis has no power here. This is the main reason the raw-entropy
   module exists, and the main reason source-level assurance (section 5) matters more
   than fleet analysis in the long run.
2. **Anything that leaves no public trace.** ECDSA nonce checks need signatures; a
   corpus of keys alone has none. TLS server signatures must be captured separately.
3. **Post-quantum keys.** ML-KEM, ML-DSA and SLH-DSA public keys have no shared-factor
   analogue. Public data reveals exact repeats and little else. The attack class that
   makes fleet analysis powerful for RSA largely disappears, which pushes the value
   toward source-level checks. Parsing PQC keys and flagging exact repeats is on the
   roadmap; claiming more would be wrong.
4. **Entropy certification.** `entropy` implements three components of SP 800-90B.
   The final assessed entropy is the minimum over ten estimators, so MCV only bounds it
   from above. Hill's analysis of the standard health-test cutoffs also notes they have
   low statistical power for many noise-source designs
   (<https://www.untruth.org/~josh/sp80090b/N23A%20HillJ%20The%20SP800-90B%20Approved%20Health%20Tests%20and%20Their%20Cutoffs.pdf>).
5. **Scale above ~10^5 keys** on one machine (section 4).

## 4. Performance

Measured, one core, random 2048-bit moduli: 20,000 moduli in 11.8 s / 153 MB and
100,000 in 87 s / 733 MB with gmpy2. Without gmpy2, 5,000 moduli take 388 s: Python's
integer remainder is quadratic and the top of the remainder tree has multi-million-bit
operands. gmpy2 is therefore a hard dependency and the fallback warns.

Memory grows with the product tree. A sharded scheme is straightforward in principle
(for shard i, reduce the product of all other shards modulo each N^2 of shard i) but is
not implemented.

## 5. Research agenda

These are open directions the tool makes concrete. They are ordered by how well they
fit a thesis-sized project, not by how interesting they are.

**R1. Estimating generator entropy from fleet collisions (designed, not built).**
If N devices draw their key-generation state from a distribution with probabilities
p_i, the expected number of colliding pairs is C(N,2) * sum(p_i^2), so the observed
pair count gives a point estimate of the Renyi order-2 (collision) entropy
H2 = -log2(sum p_i^2). Zero observed collisions still yields a lower bound
(about log2(C(N,2) / 3) at 95% by the rule of three). Pairs come from identical keys
and from moduli sharing a prime. What an attacker cares about is min-entropy, and the
two are related by H_min <= H2 <= 2 * H_min (from p_max^2 <= sum p_i^2 <= p_max), so
an H2 estimate of k bits guarantees at least k/2 bits of min-entropy but says nothing
stronger. Open questions: confidence intervals when collisions cluster (a default key
on 12 units is one event, not 66 independent pairs), and whether the factor 2 can be
tightened under realistic generator models. That is the research content. It would turn
the report from "these keys are broken" into "your generator behaved as if it had at
least k bits".

**R2. Certificate Transparency at scale.** CT logs are a public corpus of billions of
certificates. Serial entropy, duplicate keys across unrelated subjects, and shared
factors can be measured per issuer and over time. That needs the sharded batch GCD
above. A measurement study with per-CA serial entropy is publishable independently of
any product.

**R3. Fleet analysis in the PQC era.** What, if anything, can be inferred about the
randomness of ML-KEM or ML-DSA keys from public data? Exact repeats are the floor. Whether
any structural signal exists (for example bias in how a flawed implementation expands
the seed) is open and worth a careful negative result.

**R4. Closing the gap between source and fleet.** Combine raw-sample assessment (what
the noise source delivers), seeding behaviour (what the DRBG actually receives at first
boot) and fleet traces (what leaked). Each sees a different failure class; no existing
tool joins them. For an implementation-oriented thesis this is the strongest direction:
a harness that measures entropy available at boot on a device class and predicts the
collision rate it implies, validated against R1.

## 6. Product hypotheses (unvalidated)

Nothing in this section is a finding. Each needs a conversation with a real buyer
before any code is written for it.

* **Who might pay:** embedded and IoT vendors preparing for the EU Cyber Resilience Act
  (main obligations apply from late 2027; verify the current dates), private PKI
  operators, security consultancies who need a repeatable randomness check in a fleet
  assessment, certification labs, and acquirers doing technical due diligence.
* **Why a free CLI first:** the checks are well known; the defensible value is the
  workflow (collection, history, regression alerts, evidence packs for auditors), not
  the gcd. The CLI earns trust and a design partner; hosted monitoring and reporting
  are the plausible product.
* **Cheapest validation:** ten 30-minute interviews with embedded security leads and
  PKI operators asking one question: "How do you know your devices' random number
  generator was healthy at provisioning, and who asks you to prove it?" Success is
  one design partner who lets you scan a real provisioning corpus.
* **Risks:** the buyer may not exist outside certification labs; manufacturers may
  not want findings in writing; the strongest evidence (shared primes) is rare in
  modern fleets that use hardware RNGs. Measure prevalence on real corpora before
  assuming demand.

## 7. Roadmap

Priority order, each independently shippable.

1. Sharded batch GCD (removes the 10^5 ceiling; prerequisite for R2).
2. Fleet collision-entropy estimator (R1) with documented confidence intervals.
3. PQC key ingestion (ML-KEM, ML-DSA, SLH-DSA) with exact-repeat detection.
4. Remaining SP 800-90B estimators, validated against NIST's reference implementation
   on its published test vectors.
5. Collectors: `ssh-keyscan` / TLS handshake capture helpers that emit the formats
   above, including server signatures for the nonce checks.
6. SARIF output and a GitHub Action for CI gating.
7. Source-level detection of weak RNG usage (fixed seeds, `rand()` for keys, unseeded
   DRBGs), joined to fleet findings.
8. Known-bad-key blocklists (for example historic Debian OpenSSL keys) as an optional
   data pack; the data is not bundled because its provenance needs care.

## 8. Ethics

The tool reads only supplied files and has no network code. Findings never include
recovered secrets, deliberately: a report should be safe to circulate. Scanning
third-party keys should follow coordinated-disclosure norms; shared-prime and nonce
findings identify keys that are, in effect, already public.

## v0.2 notes

Serial rule: judged per issuer population, not per certificate, because generators that
draw 64 random bits yield bit_length <= 63 about half the time. Trust-store layouts
(hash symlinks, bundles) are collapsed before duplicate-key analysis. Output text lives
in explain.py (ja/en); report.py only lays it out.
