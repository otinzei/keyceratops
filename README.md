# keyceratops

**A horned guard for your keys.** keyceratops finds broken randomness in what
devices and servers already publish (public keys, certificates and
signatures), tells you which software or model is behind it, and inventories
what a quantum computer will break.

Homepage: https://otinzei.github.io/keyceratops/

Weak random number generation shows up in public data long before anyone
attacks it: two routers that generated RSA primes from the same boot-time state
share a prime factor; a signer that repeats an ECDSA nonce leaks its key; a
factory image ships one key to every unit. keyceratops looks for exactly these
traces and reports them with severity, evidence and the affected keys. It never
needs a private key.

Three horns:

1. **Randomness failures**: shared primes (batch GCD), duplicate keys, ECDSA
   nonce reuse and bias, broken RSA structure, ROCA (Infineon) keys, weak
   certificate serials, plus SP 800-90B health tests for raw entropy samples.
2. **Leads**: which SSH software, firmware or device model the affected hosts
   have in common (Fisher exact test).
3. **Post-quantum inventory**: classical strength, quantum exposure, migration
   priorities and a CycloneDX 1.6 CBOM.

```
$ keyceratops demo /tmp/fleet
$ keyceratops scan /tmp/fleet --sigs /tmp/fleet/signatures.jsonl
Verdict: ACTION NEEDED   CRITICAL 9 · HIGH 3 · MEDIUM 2
Start with: ecdsa-nonce-reuse (2), shared-prime (2), duplicate-key (1), rsa-close-primes (1)

■ CRITICAL  ECDSA nonce reused  [ecdsa-nonce-reuse] 2
...
```

## Install

Python 3.10 or newer. Installing into a virtual environment is recommended.

```
python3 -m venv .venv && . .venv/bin/activate
pip install "keyceratops @ git+https://github.com/otinzei/keyceratops"
```

Or download the wheel from the
[latest release](https://github.com/otinzei/keyceratops/releases/latest) and
`pip install keyceratops-*.whl`. Dependencies: `cryptography` and `gmpy2`
(`gmpy2` is effectively required beyond a few thousand RSA keys; see
Performance).

Development:

```
git clone https://github.com/otinzei/keyceratops && cd keyceratops
pip install -e ".[dev]"
pytest
```

keyceratops was called `rngaudit` before v0.6; snapshots written under the old
name still load.

## Usage

```
keyceratops collect TARGET... -o SNAPSHOT.jsonl [-n SAMPLES]
keyceratops scan PATH... [--sigs FILE.jsonl] [-f text|json|md|cbom] [-o OUT]
                      [--inventory CSV] [--pqc] [--lang auto|ja|en]
                      [--fail-on info|low|medium|high|critical|never]
                      [--holder file|dir] [--fermat-iterations N] [--min-rsa-bits N]
keyceratops entropy FILE --bits 8 [--claim-h 7.0] [--packed] [-f text|json]
keyceratops demo DIR        # synthetic fleet with planted failures (insecure keys!)
```

Exit status: `0` clean, `1` findings at/above `--fail-on` (default `high`) or an
unhealthy entropy source, `2` input or usage error. That makes `scan` usable as a CI
gate over a directory of freshly provisioned device certificates.

**Inputs**: PEM and DER certificates, public keys and CSRs; OpenSSH public keys
(`authorized_keys`, `known_hosts`); directories (recursive). Private keys are
recognised and skipped, never read. ECDSA signatures inside certificates are
harvested automatically. Extra signatures come as JSON Lines:

```json
{"key_id": "dev-17", "r": "0x3f...", "s": "0x91..."}
{"pub": "-----BEGIN PUBLIC KEY-----...", "sig": "<DER hex>"}
```

**Holders.** A key shared by several *holders* is a duplicate-key finding. A holder is
a file (or a `known_hosts` host label); `--holder dir` treats each directory as one
device, for `host/*.pem` layouts. Organise the corpus so that one holder is one device,
otherwise a legitimate certificate renewal in a separate file looks like a shared key.

## Collecting from servers (`collect`, v0.3)

```
keyceratops collect ssh://192.168.1.10 tls://nas.lan:8443 router.lan -n 20 -o lab.jsonl
keyceratops scan lab.jsonl
```

* Targets: `tls://host[:port]`, `ssh://host[:port]`, or a bare host (TLS 443 and
  SSH 22). `-T FILE` reads one target per line. Only the targets you name are
  contacted; there is no range expansion. **Scan only systems you own or are
  authorised to test.**
* TLS: the certificate chain, plus (for TLS 1.2 servers with an ECDSA
  certificate) the ECDSA signature in each ServerKeyExchange. TLS 1.3
  encrypts its signature, so 1.3-only servers yield certificates only.
* SSH: every host key, plus for ECDSA host keys the signature over the
  exchange hash of each key exchange. The probe stops before NEWKEYS: nothing
  is authenticated.
* Each collected signature is verified against the server's key before its
  message hash `z` is recorded; signatures that do not verify keep only `r, s`.
* `-n N` collects N signatures per ECDSA key (one connection each, `--delay`
  apart). More samples make nonce reuse and bias detectable.
* The snapshot (JSON Lines) is appended to on later runs; certificates and
  keys are stored once, signatures accumulate.
* Leaf certificates and host keys are attributed to the host, so one key on
  two hosts is a `duplicate-key` finding. One *certificate* served under
  several names (a SAN / wildcard deployment) is not.

## Leads: which software or model is affected (v0.4)

A finding says that keys are broken; the report also says *where to look*.
Each holder (host, file or directory) can carry labels:

* the SSH software version recorded by `collect` (`dropbear_2014.63`),
* an inventory you supply: `keyceratops scan ... --inventory devices.csv` with a
  header row `host,vendor,model,firmware` (`host` is a collected host name or
  a scanned file / directory path),
* the organisation in a self-signed certificate (device vendors put it there).

For every label the report compares the share of affected holders with the
share among all others (one-sided Fisher exact test, Bonferroni-corrected),
and lists over-represented labels under "Leads", e.g.

```
- SSH software dropbear 2014.63: 6 of 6 affected (others: 0 of 14)  p<0.0001
```

That is a lead to investigate, not proof of a cause.

New check `rsa-roca`: RSA keys made by Infineon RSALib (CVE-2017-15361) are
recognised from the public key alone. Unlike the other checks it names its
cause: TPMs, smart cards and security tokens with that library made before the
2017 fix.

## Post-quantum inventory and CBOM (v0.5)

```
keyceratops scan certs/ lab.jsonl --pqc        # inventory + migration priorities
keyceratops scan certs/ lab.jsonl -f cbom -o cbom.json   # CycloneDX 1.6 CBOM
```

* Every key is classified: algorithm and parameter set, classical strength
  (NIST SP 800-57) and whether a quantum computer breaks it. ML-DSA, SLH-DSA
  and ML-KEM keys are recognised by OID, including keys the `cryptography`
  package cannot load yet.
* Migration priorities, each key or endpoint counted once at its most urgent
  level: (1) already broken (a HIGH/CRITICAL finding), (2) weak today (below
  112-bit, or a SHA-1/MD5-signed certificate other than a self-signed root),
  (3) quantum-vulnerable certificates valid after 2030 (NIST IR 8547
  deprecates such algorithms after 2030 and disallows them after 2035),
  (4) endpoints without post-quantum key exchange ("harvest now, decrypt
  later").
* `collect` now records each SSH server's key-exchange methods
  (`mlkem768x25519-sha256`, `sntrup761x25519-sha512` count as post-quantum)
  and asks TLS 1.3 servers about the hybrid groups X25519MLKEM768 and
  SecP256r1MLKEM768. The TLS probe offers the group without a key share; a
  server that supports it must answer with a HelloRetryRequest naming it, so
  no ML-KEM computation is needed.
* `-f cbom` writes algorithms, public keys (by fingerprint, with every place
  they were seen), certificates and endpoints as CycloneDX cryptographic
  assets, and the findings as CycloneDX vulnerabilities referencing the
  affected keys.

## Checks

| id | severity | what it means |
|---|---|---|
| `shared-prime` | critical | RSA moduli with a common factor: all of them factor from public data (batch GCD) |
| `ecdsa-nonce-reuse` | critical | same key, same `r`, different `s`: the private key follows algebraically |
| `duplicate-key` | high / critical (>= 10 holders) | one key on several holders: factory default or identical RNG output |
| `rsa-even`, `rsa-small-factor`, `rsa-square` | critical | modulus trivially factored (even, prime factor < 2^16, p = q) |
| `rsa-close-primes` | critical | Fermat factoring succeeds within a bounded search: q derived from p |
| `rsa-tiny` / `rsa-short` | critical / high | modulus < 1024 bits / below `--min-rsa-bits` |
| `common-modulus` | high | same modulus, different exponents |
| `ecdsa-shared-r` | high | same `r` under different keys: the devices' RNGs were in the same state |
| `ecdsa-biased-nonce` | high | `r` at least 32 bits short of the group order (chance: 2^-32) |
| `serial-collision` | high / medium | same issuer + serial on different certificates (high if serial >= 64 bits) |
| `serial-short` | medium | serial under 64 bits |
| `rsa-bad-exponent` | high | even exponent or < 3 |
| `serial-predictable` | low | sequential or low-variability serials (>= 30 certs per issuer) |
| `rsa-low-exponent` | low | e < 65537 |

Findings never contain recovered primes or keys; keys are identified by the SHA-256 of
their SubjectPublicKeyInfo (shown truncated).

### Raw entropy sources (`entropy`)

A well-defined subset of NIST SP 800-90B on raw, unconditioned samples: the MCV
min-entropy estimator (6.3.1), the Repetition Count Test (4.4.1) and the Adaptive
Proportion Test (4.4.2). The test cutoffs are checked against Table 2 of SP 800-90B
(`tests/test_entropy.py`). This is **not** a full 90B assessment: the other estimators
are missing, and the assessed entropy is the minimum over all of them, so the MCV figure
is only an upper bound. A pass here is not certification evidence.

## What it can and cannot tell you

It finds failures that leave a trace in public data *and* collide or break structure
inside the corpus you give it. It does not prove a generator is sound. A source with 40
bits of entropy produces no repeats in a fleet of 10,000 and passes every fleet check;
only looking at the source itself (the `entropy` command, a code review) catches that.
ECDSA checks need signatures, which only exist in your corpus if you captured them
(certificate signatures are included automatically). See `docs/DESIGN.md`.

## Performance

Batch GCD on random 2048-bit moduli (`benchmarks/bench_batch_gcd.py`, one core):

| moduli | with gmpy2 | peak memory | pure Python |
|---:|---:|---:|---:|
| 2,000 | | | 61 s |
| 5,000 | 2.3 s | 51 MB | 388 s |
| 20,000 | 11.8 s | 153 MB | |
| 100,000 | 87 s | 733 MB | |

Above 100,000 keys, shard the corpus (not implemented; see roadmap). Pure Python is
kept only as a fallback and warns above 1,000 moduli.

## Safety

`keyceratops` only reads files you give it. The planted-failure generator in
`keyceratops.synth` is deliberately insecure and exists for tests and demos. If you scan
keys that are not yours, follow the disclosure norms of the affected vendors.

## License

MIT

## v0.2 changes

- Report rewritten: a verdict line, one explanation per check (what is wrong / what to do),
  numbered cases with shortened paths. `--lang auto|ja|en` (auto follows the locale),
  `--color auto|always|never`, `--max-items N` (default 5; `-v` shows everything).
- False positives fixed: symlinks and hash links in trust stores are de-duplicated,
  CA bundles are not counted as holders, known_hosts aliases are reported at lower
  severity with a note, certificates issued before 2016-09-30 are exempt from the
  64-bit serial rule (CA/B Forum Ballot 164), serials are judged per issuer.
- New check: `serial-invalid` (zero or negative serials).
