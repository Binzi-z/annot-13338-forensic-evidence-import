"""Declarative, deterministic scenario DSL.

A *scenario* is pure data describing custodians, packs, file payloads and
custody chains.  The same dict is used by the tests to build fixtures and by
:mod:`evstore.repro` to emit a minimal, replayable bundle, which guarantees the
reproduction reconstructs byte-identical inputs.

Scenario schema (all fields except ``name``/``packs`` optional)::

    {
      "name": "str",
      "keys": {"custodian": "seed-hex"},            # deterministic Ed25519
      "packs": [
        {
          "custodian": "str", "pack_id": "str", "created": int,
          "files": [{"name","path","aliases":[],"content_hex"}],
          "custody": {
             "steps": ["acquire","transfer","verify"],
             "subject_path": "C:\\\\...",            # default = first file path
             "sha256": "sha256:..."                 # default = first file sha
             "aliases": [],
             "skip_seqs": [],                       # drop events -> gaps
             "revoke_at_seq": null,
             "tamper": null | "sig" | "prev" | "body"
          }
        }
      ]
    }
"""

from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import crypto
from .custody import CustodyEvent, make_event
from .fsutil import atomic_write_bytes, atomic_write_json
from .manifest import FileEntry, build_manifest


def key_from_seed(seed_hex: str) -> tuple[Ed25519PrivateKey, str]:
    raw = hashlib.sha256(("ed25519:" + seed_hex).encode("utf-8")).digest()
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    return priv, crypto.public_bytes(priv.public_key())


def _content_of(files: list[dict]) -> tuple[str, str, list[str]]:
    f = files[0]
    return f["path"], f["content_hex"], list(f.get("aliases", []))


def _sha256_hex_of(content_hex: str) -> str:
    return "sha256:" + hashlib.sha256(bytes.fromhex(content_hex)).hexdigest()


def build_custody(
    priv: Ed25519PrivateKey,
    custodian: str,
    files: list[dict],
    spec: dict,
) -> list[dict]:
    steps = spec.get("steps", ["acquire", "transfer", "verify"])
    subject_path = spec.get("subject_path") or _content_of(files)[0]
    aliases = spec.get("aliases")
    if aliases is None:
        aliases = _content_of(files)[2]
    sha = spec.get("sha256") or _sha256_hex_of(_content_of(files)[1])
    skip = set(spec.get("skip_seqs", []))
    revoke_at = spec.get("revoke_at_seq")
    events: list[dict] = []
    prev = None
    subject = {"path": subject_path, "aliases": list(aliases), "sha256": sha}
    plan = list(enumerate(steps))
    if revoke_at is not None:
        plan.append((revoke_at, "revoke"))
    for s, typ in sorted(plan, key=lambda x: x[0]):
        ev = make_event(
            priv, custodian, s, typ, prev,
            subject=None if typ == "revoke" else subject,
            note=f"{typ} step",
        )
        if s not in skip:
            events.append(ev)
        prev = CustodyEvent.from_dict(ev).digest()
    tamper = spec.get("tamper")
    if tamper and events:
        target = events[-1]
        if tamper == "sig":
            target["sig"] = "AAAA" + target["sig"][4:]
        elif tamper == "prev":
            target["prev"] = "sha256:" + ("ab" * 32)
        elif tamper == "body":
            ev = CustodyEvent.from_dict(target)
            ev.note = ev.note + " (edited)"
            # keep the old signature -> now invalid, and recompute nothing
            target["note"] = ev.note
    return events


def build_pack_dir(
    scenario: dict, pack_spec: dict, out_dir: str
) -> tuple[str, Ed25519PrivateKey, str]:
    """Materialise one pack into *out_dir*; return (dir, priv, pub_b64)."""
    custodian = pack_spec["custodian"]
    seed = scenario.get("keys", {}).get(custodian, custodian)
    priv, pub_b64 = key_from_seed(seed)
    os.makedirs(out_dir, exist_ok=True)
    entries: list[FileEntry] = []
    for f in pack_spec["files"]:
        data = bytes.fromhex(f["content_hex"])
        atomic_write_bytes(os.path.join(out_dir, f["name"]), data)
        sha, n, b2 = crypto.sha256_stream([data])
        entries.append(FileEntry(
            name=f["name"], path=f["path"], size=n,
            sha256="sha256:" + sha, blake2b=b2,
            aliases=list(f.get("aliases", [])),
        ))
    manifest = build_manifest(
        priv, custodian, pack_spec["pack_id"],
        int(pack_spec.get("created", 0)), entries,
    )
    atomic_write_json(os.path.join(out_dir, "manifest.json"), manifest)
    custody = build_custody(priv, custodian, pack_spec["files"],
                            pack_spec.get("custody", {}))
    atomic_write_json(os.path.join(out_dir, "custody.json"), custody)
    return out_dir, priv, pub_b64


def build_scenario(scenario: dict, root: str) -> tuple[dict, dict[str, str]]:
    """Materialise every pack; return ({pack_id: dir}, {custodian: pub_b64})."""
    packs: dict[str, str] = {}
    keys: dict[str, str] = {}
    for i, ps in enumerate(scenario["packs"]):
        out = os.path.join(root, f"pack-{i}-{ps['pack_id']}")
        d, _priv, pub = build_pack_dir(scenario, ps, out)
        packs[ps["pack_id"]] = d
        keys[ps["custodian"]] = pub
    return packs, keys


def sha256_of_content_hex(content_hex: str) -> str:
    return _sha256_hex_of(content_hex)
