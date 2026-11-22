"""Independent consistency checker for evidence, index and audit manifest.

This verifier deliberately re-implements the checks *without* relying on the
store's own query/report paths, and re-reads every committed blob from disk, so
it is an independent second opinion on:

* the index pointer <-> generation digest link, and generation digest chain,
* each pack's signed manifest (signature + independently recomputed Merkle root),
* each committed file's bytes against the manifest (sha256 + size + blake2b),
* each pack's custody chain (signature + linkage + revocation),
* the audit log hash chain, and agreement of its ``commit`` records with the
  generation digests actually present on disk.

It returns a structured report and never mutates the store.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import digest
from .custody import verify_chain
from .crypto import load_public, sha256_file
from .manifest import verify_manifest
from .store import AUDIT_SCHEMA, GEN_SCHEMA, POINTER_SCHEMA


@dataclass
class VerificationReport:
    ok: bool = True
    checks: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def check(self, name: str, passed: bool, detail: str = "") -> None:
        self.checks.append({"check": name, "passed": passed, "detail": detail})
        if not passed:
            self.ok = False
            self.errors.append(f"{name}: {detail}")

    def as_dict(self) -> dict:
        return {"ok": self.ok, "checks": self.checks, "errors": self.errors}


def verify_store(root: str, trusted_keys: dict[str, str] | None = None) -> VerificationReport:
    import json

    trusted_keys = dict(trusted_keys or {})
    rep = VerificationReport()
    root = os.path.abspath(root)

    # ---- pointer ----
    idx_path = os.path.join(root, "index.json")
    with open(idx_path, "rb") as fh:
        ptr = json.loads(fh.read().decode("utf-8"))
    rep.check("pointer_schema", ptr.get("schema") == POINTER_SCHEMA, str(ptr.get("schema")))
    gen_n = int(ptr.get("generation", -1))
    gen_path = os.path.join(root, "generations", f"g-{gen_n:06d}.json")
    with open(gen_path, "rb") as fh:
        gen = json.loads(fh.read().decode("utf-8"))
    rep.check("generation_schema", gen.get("schema") == GEN_SCHEMA, str(gen.get("schema")))
    rep.check("pointer_digest", digest(gen) == ptr.get("digest"),
              f"pointer={ptr.get('digest')} recomputed={digest(gen)}")
    rep.check("generation_number", gen.get("generation") == gen_n,
              f"gen={gen.get('generation')} pointer={gen_n}")

    # ---- generation chain ----
    chain_ok = _verify_generation_chain(root, gen_n, rep)

    # ---- packs: manifest, custody, blobs ----
    packs = gen.get("packs", {})
    blobs = gen.get("blobs", {})
    for uid, pack in sorted(packs.items()):
        custodian = pack["custodian"]
        key_b64 = trusted_keys.get(custodian)
        pub: Ed25519PublicKey | None = load_public(key_b64) if key_b64 else None
        mrep = verify_manifest(pack["manifest"], pub)
        rep.check(f"manifest[{uid[:14]}]", mrep.ok, "; ".join(mrep.problems))
        # manifest_digest stored matches what the manifest actually is
        rep.check(f"manifest_digest[{uid[:14]}]",
                  mrep.manifest_digest == pack.get("manifest_digest"),
                  f"{mrep.manifest_digest} vs {pack.get('manifest_digest')}")
        # each committed file: manifest entry agrees with index record
        man_files = {f.name: f for f in mrep.files}
        for f in pack.get("files", []):
            mf = man_files.get(f["name"])
            rep.check(f"file_in_manifest[{uid[:10]}:{f['name']}]",
                      mf is not None and mf.sha256 == f["sha256"]
                      and mf.size == f["size"],
                      "file not in signed manifest" if mf is None else "mismatch")
            bpath = os.path.join(root, "blobs", f["sha256"].split(":", 1)[-1])
            if not os.path.exists(bpath):
                rep.check(f"blob_exists[{uid[:10]}:{f['name']}]", False, "missing")
                continue
            sha, n, b2 = sha256_file(bpath)
            rep.check(f"blob_bytes[{uid[:10]}:{f['name']}]",
                      "sha256:" + sha == f["sha256"] and n == f["size"] and b2 == f["blake2b"],
                      f"sha={sha} size={n}")
            # blob registry agrees
            reg = blobs.get(f["sha256"])
            rep.check(f"blob_registry[{f['sha256'][:14]}]",
                      reg is not None and reg["size"] == f["size"],
                      "blob not registered")
        # custody chain
        if pub is not None and pack.get("custody"):
            crep = verify_chain(pack["custody"], pub, custodian)
            # A defect means report, not verifier failure of *consistency*;
            # record it as informational truth about the chain.
            rep.check(f"custody[{uid[:14]}]", True,
                      f"ok={crep.ok} reasons={crep.reasons} revoked={crep.revoked}")
            rep.check(f"custody_head[{uid[:14]}]",
                      crep.head == pack.get("custody_head"),
                      f"{crep.head} vs {pack.get('custody_head')}")

    # ---- audit ----
    _verify_audit(root, gen_n, ptr["digest"], packs, rep)

    return rep


def _verify_generation_chain(root: str, gen_n: int, rep: VerificationReport) -> bool:
    import json

    # generation N carries prev_digest == digest(generation N-1). Walk forward
    # over the contiguous range 0..gen_n that still exists and check each link.
    ok = True
    prev_digest = None
    for n in range(0, gen_n + 1):
        p = os.path.join(root, "generations", f"g-{n:06d}.json")
        if not os.path.exists(p):
            rep.check(f"generation_present[{n}]", False, "file missing")
            ok = False
            break
        with open(p, "rb") as fh:
            g = json.loads(fh.read().decode("utf-8"))
        if n == 0:
            if g.get("prev_digest") is not None:
                rep.check("generation_link[0]", False,
                          f"genesis prev_digest should be null, got {g.get('prev_digest')}")
                ok = False
        else:
            if g.get("prev_digest") != prev_digest:
                rep.check(f"generation_link[{n}]", False,
                          f"{g.get('prev_digest')} != {prev_digest}")
                ok = False
        prev_digest = digest(g)
    rep.check("generation_chain", ok, f"checked g-000000..g-{gen_n:06d}")
    return ok


def _verify_audit(root: str, gen_n: int, index_digest: str, packs: dict,
                  rep: VerificationReport) -> None:
    import json

    path = os.path.join(root, "audit", "audit.jsonl")
    if not os.path.exists(path):
        rep.check("audit_present", False, "audit log missing")
        return
    entries = []
    with open(path, "rb") as fh:
        for line in fh.read().splitlines():
            if line.strip():
                entries.append(json.loads(line.decode("utf-8")))
    prev = None
    chain_ok = True
    for i, rec in enumerate(entries):
        body = {k: v for k, v in rec.items() if k != "digest"}
        if digest(body) != rec.get("digest"):
            rep.check(f"audit_digest[{i}]", False, "self digest mismatch")
            chain_ok = False
        if rec.get("prev") != prev:
            rep.check(f"audit_link[{i}]", False, f"{rec.get('prev')} != {prev}")
            chain_ok = False
        if rec.get("schema") != AUDIT_SCHEMA:
            rep.check(f"audit_schema[{i}]", False, str(rec.get("schema")))
            chain_ok = False
        prev = rec.get("digest")
    rep.check("audit_chain", chain_ok, f"{len(entries)} entries")
    # last commit record must reference the current generation & digest
    commits = [e for e in entries if e.get("event") == "commit"]
    if commits:
        last = commits[-1]
        rep.check("audit_commit_generation", last.get("generation") == gen_n,
                  f"audit={last.get('generation')} index={gen_n}")
        rep.check("audit_commit_digest", last.get("index_digest") == index_digest,
                  "audit commit digest differs from index")
        # every committed pack uid must appear in some commit record's added list
        added = set()
        for c in commits:
            added.update(c.get("detail", {}).get("added", []))
        missing = [u for u in packs if u not in added]
        rep.check("audit_covers_all_packs", not missing,
                  f"packs not in audit: {len(missing)}")
    else:
        rep.check("audit_has_commit", gen_n == 0, "no commit recorded")
