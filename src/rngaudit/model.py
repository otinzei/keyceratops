"""Shared data model: key records, signature records and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {name!r}") from exc


@dataclass(frozen=True)
class KeyRecord:
    """One public key observed somewhere in the fleet.

    ``source`` identifies where it was seen (file path plus index, host label
    ...). ``fingerprint`` is a SHA-256 over the canonical key material and is
    what findings refer to, so reports never have to print key material.
    """

    source: str
    algorithm: str  # "rsa" | "ec" | "ed25519" | "ed448" | "dsa" | "other"
    fingerprint: str
    bits: int | None = None
    # RSA
    modulus: int | None = None
    exponent: int | None = None
    # EC
    curve: str | None = None
    # Certificate context (None when the key was not inside a certificate)
    cert_serial: int | None = None
    cert_issuer: str | None = None
    cert_subject: str | None = None
    cert_not_before: str | None = None
    # SHA-256 of the whole certificate (distinguishes reissues of one key)
    cert_fingerprint: str | None = None


@dataclass(frozen=True)
class SignatureRecord:
    """One ECDSA signature (r, s) over a message hash ``z`` made by ``pub``."""

    source: str
    pub_fingerprint: str
    r: int
    s: int
    z: int | None = None
    curve: str | None = None


@dataclass
class Finding:
    check: str
    severity: Severity
    title: str
    detail: str
    # Sources / fingerprints involved. Never contains private material.
    sources: list[str] = field(default_factory=list)
    fingerprints: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "severity": self.severity.name,
            "title": self.title,
            "detail": self.detail,
            "sources": self.sources,
            "fingerprints": self.fingerprints,
            "data": self.data,
        }
