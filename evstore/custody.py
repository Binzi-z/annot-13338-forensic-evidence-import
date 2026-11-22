"""Hash-chained, signed custody events and chain validation.

Each event is signed by its custodian and carries the digest of its
predecessor (``prev``), forming a tamper-evident chain. Validation detects:

* ``BAD_SIGNATURE``   – an event was altered or forged,
* ``MISSING_SEGMENT`` – one or more ``seq`` numbers are absent,
* ``LINK_BROKEN``     – ``prev`` does not equal the predecessor's digest with
  a *contiguous* seq (i.e. history was rewritten / the pack was swapped),
* ``DUPLICATE_SEQ``   – two different events claim the same seq,
* ``REVOKED``         – a later ``revoke`` event retracts the chain/subject.

Cross-chain conflicts (two custodians disagreeing about the same file or
alias) are reported by :func:`cross_chain_conflicts`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import crypto
from .canonical import digest
from .errors import CustodyError
from .pathalias import name_key

EVENT_TYPES = {"acquire", "transfer", "verify", "revoke"}


@dataclass
class CustodyEvent:
    custodian: str
    seq: int
    type: str
    prev: str | None
    subject: dict | None = None
    note: str = ""

    def unsigned(self) -> dict:
        body = {
            "custodian": self.custodian,
            "seq": self.seq,
            "type": self.type,
            "prev": self.prev,
            "subject": self.subject,
            "note": self.note,
        }
        return body

    def digest(self) -> str:
        return digest(self.unsigned())

    def to_dict(self, signature: str) -> dict:
        d = self.unsigned()
        d["sig"] = signature
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "CustodyEvent":
        return cls(
            custodian=d["custodian"],
            seq=int(d["seq"]),
            type=d["type"],
            prev=d.get("prev"),
            subject=d.get("subject"),
            note=d.get("note", ""),
        )


def make_event(
    priv: Ed25519PrivateKey,
    custodian: str,
    seq: int,
    type: str,
    prev: str | None,
    subject: dict | None = None,
    note: str = "",
) -> dict:
    if type not in EVENT_TYPES:
        raise CustodyError(f"unknown event type {type!r}")
    ev = CustodyEvent(custodian, seq, type, prev, subject, note)
    sig = crypto.sign_object(priv, ev.unsigned())
    return ev.to_dict(sig)


@dataclass
class ChainReport:
    custodian: str
    ok: bool
    reasons: list[str] = field(default_factory=list)   # machine codes
    messages: list[str] = field(default_factory=list)
    revoked: bool = False
    revoked_at: int | None = None
    leaves: int = 0
    head: str | None = None

    def add(self, code: str, msg: str) -> None:
        self.reasons.append(code)
        self.messages.append(msg)

    def as_dict(self) -> dict:
        return {
            "custodian": self.custodian,
            "ok": self.ok,
            "reasons": self.reasons,
            "messages": self.messages,
            "revoked": self.revoked,
            "revoked_at": self.revoked_at,
            "leaves": self.leaves,
            "head": self.head,
        }


def verify_chain(
    events: Iterable[dict],
    public_key: Ed25519PublicKey,
    custodian: str | None = None,
) -> ChainReport:
    """Validate one custodian's event list. Never raises for content issues."""
    evs = list(events)
    name = custodian or (evs[0]["custodian"] if evs else "?")
    rep = ChainReport(custodian=name, ok=True)
    prev_obj = None
    seen_seq: dict[int, str] = {}
    for raw in evs:
        ev = CustodyEvent.from_dict(raw)
        # 1. signature over the unsigned body
        try:
            crypto.verify_object(public_key, ev.unsigned(), raw.get("sig", ""))
        except Exception:
            rep.add("BAD_SIGNATURE", f"event seq={ev.seq} signature invalid")
        # 2. sequence bookkeeping
        d = ev.digest()
        if ev.seq in seen_seq:
            if seen_seq[ev.seq] != d:
                rep.add("DUPLICATE_SEQ", f"seq={ev.seq} has two distinct events")
        seen_seq[ev.seq] = d
        # 3. link integrity
        if prev_obj is None:
            if ev.seq != 0:
                rep.add("MISSING_SEGMENT", f"chain starts at seq={ev.seq}, expected 0")
            if ev.prev is not None:
                rep.add("LINK_BROKEN", f"first event seq={ev.seq} has non-null prev")
        else:
            gap = ev.seq - prev_obj.seq
            if gap > 1:
                rep.add(
                    "MISSING_SEGMENT",
                    f"seq jumps {prev_obj.seq}->{ev.seq} ({gap - 1} missing)",
                )
            elif gap <= 0:
                rep.add("DUPLICATE_SEQ", f"non-increasing seq {prev_obj.seq}->{ev.seq}")
            if ev.prev != prev_obj.digest():
                rep.add(
                    "LINK_BROKEN",
                    f"seq={ev.seq} prev {ev.prev!r} != digest of seq={prev_obj.seq}",
                )
        # 4. revocation
        if ev.type == "revoke":
            rep.revoked = True
            rep.revoked_at = ev.seq
        prev_obj = ev
    if prev_obj is not None:
        rep.leaves = prev_obj.seq + 1
        rep.head = prev_obj.digest()
    rep.ok = not rep.reasons
    return rep


# --------------------------------------------------------------------------- #
# Cross-chain analysis
# --------------------------------------------------------------------------- #
@dataclass
class Conflict:
    kind: str            # "content" | "alias-content"
    file_key: str
    detail: str
    custodians: list[str]
    values: list[str]

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "file_key": self.file_key,
            "detail": self.detail,
            "custodians": self.custodians,
            "values": self.values,
        }


def _claims(events: Iterable[dict]) -> dict[str, set[str]]:
    """Map normalised file_key -> set of content digests asserted for it."""
    out: dict[str, set[str]] = {}
    for raw in events:
        ev = CustodyEvent.from_dict(raw)
        subj = ev.subject or {}
        sha = subj.get("sha256")
        if not sha:
            continue
        keys = set()
        if subj.get("path"):
            keys.add(name_key(subj["path"]))
        for alias in subj.get("aliases", []) or []:
            keys.add(name_key(alias))
        if ev.type == "revoke":
            continue
        for k in keys:
            out.setdefault(k, set()).add(sha)
    return out


def cross_chain_conflicts(
    chains: dict[str, Iterable[dict]],
) -> list[Conflict]:
    """Detect custodians who disagree about the content behind a file/alias."""
    per_chain: dict[str, dict[str, set[str]]] = {
        cust: _claims(evs) for cust, evs in chains.items()
    }
    keys: set[str] = set()
    for claims in per_chain.values():
        keys.update(claims)
    conflicts: list[Conflict] = []
    for key in sorted(keys):
        by_digest: dict[str, list[str]] = {}
        for cust, claims in per_chain.items():
            for d in claims.get(key, ()):  # noqa: E501
                by_digest.setdefault(d, []).append(cust)
        if len(by_digest) > 1:
            conflicts.append(
                Conflict(
                    kind="content",
                    file_key=key,
                    detail="custodians assert different content for the same path/alias",
                    custodians=sorted({c for cs in by_digest.values() for c in cs}),
                    values=sorted(by_digest),
                )
            )
    return conflicts
