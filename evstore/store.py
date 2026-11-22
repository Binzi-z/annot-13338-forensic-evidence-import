"""Crash-safe evidence store: staging, index commit, recovery, query, report.

On-disk layout (all durable writes are temp->fsync->os.replace)::

    root/
      LOCK                      advisory cross-process lock (commit/recovery)
      index.json                {generation, digest}   <- THE commit point
      generations/g-000001.json immutable, digest-chained snapshots
      blobs/<sha256>            content-addressed, immutable evidence bytes
      staging/<txn>/txn.json    in-flight transaction (writer pid, packs)
      staging/<txn>/<uid>/      per-pack state + copied-but-uncommitted bytes
      audit/audit.jsonl         append-only, hash-chained audit log

Commit protocol (visibility *only* via ``index.json``):

1. (unlocked) copy+verify each pack payload into ``staging`` (Merkle/sha checks).
2. (under LOCK) ``recover()`` – clean stale staging / orphan generations.
3. (under LOCK) move verified staged files into ``blobs/<sha256>`` (never
   overwriting an existing blob, so original bytes are preserved).
4. (under LOCK) write ``generations/g-{N+1}.json`` (orphan if we crash here).
5. (under LOCK) atomically replace ``index.json`` -> generation N+1.  **Commit.**
6. (under LOCK) append audit ``commit`` record; delete staging (recoverable).

Recovery rules: staging for a pack that already appears in the *committed*
generation is deleted; staging whose writer pid is dead is abandoned; orphan
generation files above the pointer are deleted; a missing trailing audit
``commit`` record is fast-forwarded but any *divergent* audit is reported, never
silently rewritten.  Uncommitted bytes are never referenced by ``index.json``
and are therefore invisible to queries.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import SCHEMA_VERSION, crypto
from .canonical import digest
from .custody import ChainReport, cross_chain_conflicts, verify_chain
from .errors import IntegrityError, RecoveryError, UncommittedError
from .fsutil import (
    FileLock,
    atomic_write_json,
    pid_alive,
    read_json,
)
from .manifest import manifest_digest, verify_manifest
from .pathalias import name_key

GEN_SCHEMA = "evstore/idx/1"
POINTER_SCHEMA = "evstore/pointer/1"
AUDIT_SCHEMA = "evstore/audit/1"

# A staging dir without a txn.json is only reaped once it is older than this,
# so a concurrent recover() cannot delete a live stager's just-mkdir'd dir.
STAGING_GRACE_S = 300


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _now() -> int:
    return int(time.time())


def _blob_rel(sha256: str) -> str:
    return sha256.split(":", 1)[1] if ":" in sha256 else sha256


def _pack_uid_of(manifest: dict) -> str:
    return manifest_digest(manifest)


# --------------------------------------------------------------------------- #
# Result containers
# --------------------------------------------------------------------------- #
@dataclass
class RecoveryResult:
    abandoned: list[str] = field(default_factory=list)
    cleaned: list[str] = field(default_factory=list)
    orphan_generations: list[str] = field(default_factory=list)
    audit_appended: int = 0
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "abandoned": self.abandoned,
            "cleaned": self.cleaned,
            "orphan_generations": self.orphan_generations,
            "audit_appended": self.audit_appended,
            "notes": self.notes,
        }


@dataclass
class CommitResult:
    generation: int
    index_digest: str
    added: list[str]
    already_present: list[str]

    def as_dict(self) -> dict:
        return {
            "generation": self.generation,
            "index_digest": self.index_digest,
            "added": self.added,
            "already_present": self.already_present,
        }


# --------------------------------------------------------------------------- #
# Store
# --------------------------------------------------------------------------- #
class Store:
    def __init__(self, root: str, trusted_keys: dict[str, str] | None = None):
        self.root = os.path.abspath(root)
        self.trusted_keys = dict(trusted_keys or {})
        self._pub_cache: dict[str, Ed25519PublicKey] = {}

    # -- paths -------------------------------------------------------------
    @property
    def lock_path(self) -> str:
        return os.path.join(self.root, "LOCK")

    @property
    def index_path(self) -> str:
        return os.path.join(self.root, "index.json")

    @property
    def gens_dir(self) -> str:
        return os.path.join(self.root, "generations")

    @property
    def blobs_dir(self) -> str:
        return os.path.join(self.root, "blobs")

    @property
    def staging_dir(self) -> str:
        return os.path.join(self.root, "staging")

    @property
    def audit_path(self) -> str:
        return os.path.join(self.root, "audit", "audit.jsonl")

    def genesis_path(self, n: int) -> str:
        return os.path.join(self.gens_dir, f"g-{n:06d}.json")

    def blob_path(self, sha256: str) -> str:
        return os.path.join(self.blobs_dir, _blob_rel(sha256))

    # -- lifecycle ---------------------------------------------------------
    def init(self) -> "Store":
        for d in (self.gens_dir, self.blobs_dir, self.staging_dir,
                  os.path.dirname(self.audit_path)):
            os.makedirs(d, exist_ok=True)
        if not os.path.exists(self.index_path):
            empty = self._empty_generation(0)
            atomic_write_json(self.genesis_path(0), empty)
            atomic_write_json(
                self.index_path,
                {"schema": POINTER_SCHEMA, "generation": 0,
                 "digest": digest(empty)},
            )
            self._append_audit("init", 0, digest(empty), {"root": "."})
        return self

    def open(self, recover: bool = True, timeout: float = 30.0) -> "Store":
        if not os.path.exists(self.index_path):
            raise RecoveryError(f"store not initialised at {self.root}")
        if recover:
            with self.write_lock(timeout=timeout):
                self.recover(locked=True)
        return self

    def _empty_generation(self, n: int, prev_digest: str | None = None) -> dict:
        return {
            "schema": GEN_SCHEMA,
            "generation": n,
            "prev_digest": prev_digest,
            "created": _now(),
            "packs": {},
            "blobs": {},
        }

    # -- locking -----------------------------------------------------------
    def write_lock(self, timeout: float = 30.0) -> FileLock:
        return FileLock(self.lock_path, timeout=timeout)

    # -- pointer / generation reads ---------------------------------------
    def read_pointer(self) -> dict:
        ptr = read_json(self.index_path)
        if ptr.get("schema") != POINTER_SCHEMA:
            raise RecoveryError("bad index pointer schema")
        return ptr

    def load_generation(self, n: int) -> dict:
        return read_json(self.genesis_path(n))

    def current(self) -> dict:
        ptr = self.read_pointer()
        gen = self.load_generation(ptr["generation"])
        if digest(gen) != ptr["digest"]:
            raise IntegrityError(
                f"index digest mismatch at generation {ptr['generation']}"
            )
        return gen

    def current_generation(self) -> int:
        return self.read_pointer()["generation"]

    # -- trusted keys ------------------------------------------------------
    def public_key(self, custodian: str, manifest: dict | None = None) -> Ed25519PublicKey:
        if custodian in self._pub_cache:
            return self._pub_cache[custodian]
        text = self.trusted_keys.get(custodian)
        if text is None and manifest is not None:
            text = manifest.get("public_key")
        if text is None:
            raise RecoveryError(f"no trusted key for custodian {custodian!r}")
        pub = crypto.load_public(text)
        self._pub_cache[custodian] = pub
        return pub

    # -- audit -------------------------------------------------------------
    def _read_audit(self) -> list[dict]:
        if not os.path.exists(self.audit_path):
            return []
        out = []
        with open(self.audit_path, "rb") as fh:
            for line in fh.read().splitlines():
                if line.strip():
                    import json

                    out.append(json.loads(line.decode("utf-8")))
        return out

    def _append_audit(
        self, event: str, generation: int, index_digest: str, detail: dict
    ) -> dict:
        entries = self._read_audit()
        prev = entries[-1]["digest"] if entries else None
        rec_body = {
            "schema": AUDIT_SCHEMA,
            "seq": len(entries),
            "ts": _now(),
            "event": event,
            "generation": generation,
            "index_digest": index_digest,
            "detail": detail,
            "prev": prev,
        }
        rec = {**rec_body, "digest": digest(rec_body)}
        from .canonical import canonical_bytes

        data = canonical_bytes(rec) + b"\n"
        os.makedirs(os.path.dirname(self.audit_path), exist_ok=True)
        with open(self.audit_path, "ab") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        return rec

    def audit_entries(self) -> list[dict]:
        return self._read_audit()

    # -- recovery ----------------------------------------------------------
    def recover(self, locked: bool = False, timeout: float = 30.0) -> RecoveryResult:
        if not locked:
            with self.write_lock(timeout=timeout):
                return self.recover(locked=True)
        res = RecoveryResult()
        ptr = self.read_pointer()
        gen_n = ptr["generation"]
        gen = self.load_generation(gen_n)
        if digest(gen) != ptr["digest"]:
            raise IntegrityError("cannot recover: committed generation digest mismatch")

        # 1. orphan generation files above the committed pointer
        for name in sorted(os.listdir(self.gens_dir)):
            if not name.startswith("g-") or not name.endswith(".json"):
                continue
            try:
                num = int(name[2:-5])
            except ValueError:
                continue
            if num > gen_n:
                os.remove(os.path.join(self.gens_dir, name))
                res.orphan_generations.append(name)

        committed_uids = set(gen.get("packs", {}).keys())

        # 2. staging cleanup / abandonment
        if os.path.isdir(self.staging_dir):
            for txn in sorted(os.listdir(self.staging_dir)):
                tdir = os.path.join(self.staging_dir, txn)
                if not os.path.isdir(tdir):
                    continue
                tmeta_path = os.path.join(tdir, "txn.json")
                if not os.path.exists(tmeta_path):
                    # A live stager writes txn.json immediately after mkdir, but
                    # another process's recover() can race into that tiny gap.
                    # Only reap a dir that is clearly abandoned (older than the
                    # grace period); otherwise leave it for a later recovery.
                    try:
                        age = time.time() - os.stat(tdir).st_mtime
                    except OSError:
                        continue
                    if age > STAGING_GRACE_S:
                        _rmtree(tdir)
                        res.orphan_generations.append(f"staging:{txn}")
                    else:
                        res.notes.append(f"staging:{txn} within grace period; kept")
                    continue
                tmeta = read_json(tmeta_path)
                uids = {p["pack_uid"] for p in tmeta.get("packs", [])}
                if uids and uids <= committed_uids:
                    _rmtree(tdir)
                    res.cleaned.append(txn)
                    continue
                if not pid_alive(int(tmeta.get("pid", -1))):
                    _rmtree(tdir)
                    res.abandoned.append(txn)
                    self._append_audit(
                        "abandon", gen_n, ptr["digest"], {"txn": txn}
                    )
                # else: a live writer owns it - leave it alone.

        # 3. audit fast-forward for a commit that landed before the log line
        entries = self._read_audit()
        commits = {e["generation"] for e in entries if e["event"] == "commit"}
        if gen_n > 0 and gen_n not in commits:
            last = entries[-1] if entries else None
            prev_ok = last is None or last.get("event") != "commit" or \
                last.get("generation") == gen_n - 1
            # If the audit already carries a *later* commit for this generation
            # under a different digest we must not mask divergence.
            same_gen = [e for e in entries
                        if e["event"] == "commit" and e["generation"] == gen_n]
            if prev_ok and not same_gen and self._audit_chain_ok(entries):
                prev_packs = set()
                if gen_n - 1 >= 0:
                    prevp = self.genesis_path(gen_n - 1)
                    if os.path.exists(prevp):
                        prev_packs = set(self.load_generation(gen_n - 1)["packs"].keys())
                added = sorted(set(gen.get("packs", {}).keys()) - prev_packs)
                self._append_audit(
                    "commit", gen_n, ptr["digest"],
                    {"recovered": True, "added": added, "generation": gen_n},
                )
                res.audit_appended += 1
            else:
                res.notes.append(
                    "audit lacks commit for committed generation and cannot "
                    "be fast-forwarded without masking divergence")
        return res

    @staticmethod
    def _audit_chain_ok(entries: Iterable[dict]) -> bool:
        prev = None
        for rec in entries:
            body = {k: v for k, v in rec.items() if k != "digest"}
            if digest(body) != rec.get("digest"):
                return False
            if rec.get("prev") != prev:
                return False
            prev = rec["digest"]
        return True

    # -- commit ------------------------------------------------------------
    def commit_staged(self, staged, txn_id: str, timeout: float = 30.0) -> CommitResult:
        """Merge verified *staged* packs (list[StagedPack]) into a new generation."""
        from .faults import crashpoint

        with self.write_lock(timeout=timeout):
            self.recover(locked=True)
            gen = self.current()
            gen_n = gen["generation"]
            packs = dict(gen["packs"])
            blobs = dict(gen["blobs"])
            added, present = [], []
            for sp in staged:
                uid = sp.pack_uid
                if uid in packs:
                    present.append(uid)
                    continue
                for f in sp.files:
                    bpath = self.blob_path(f.sha256)
                    if not os.path.exists(bpath):
                        # atomic move into content-addressed storage
                        os.makedirs(self.blobs_dir, exist_ok=True)
                        os.replace(f.staged_path, bpath)
                    else:
                        # verify the existing blob before trusting it (preserve
                        # original bytes; never overwrite a mismatching blob)
                        got = self._hash_blob(bpath)
                        if got[0] != f.sha256:
                            raise IntegrityError(
                                f"existing blob {f.sha256} has been replaced"
                            )
                    blobs[f.sha256] = {"size": f.size, "blake2b": f.blake2b}
                packs[uid] = sp.to_pack_record(txn_id)
                added.append(uid)
            crashpoint("before_generation")
            if not added:
                # nothing new; still report current committed generation
                ptr = self.read_pointer()
                _rmtree(os.path.join(self.staging_dir, txn_id))
                return CommitResult(gen_n, ptr["digest"], [], present)
            new_gen = {
                "schema": GEN_SCHEMA,
                "generation": gen_n + 1,
                "prev_digest": digest(gen),
                "created": _now(),
                "packs": packs,
                "blobs": blobs,
            }
            new_digest = digest(new_gen)
            atomic_write_json(self.genesis_path(gen_n + 1), new_gen)  # step 4
            crashpoint("after_generation")
            atomic_write_json(  # step 5: commit point
                self.index_path,
                {"schema": POINTER_SCHEMA, "generation": gen_n + 1,
                 "digest": new_digest},
            )
            crashpoint("after_index")
            self._append_audit(  # step 6
                "commit", gen_n + 1, new_digest,
                {"txn": txn_id, "added": added},
            )
            crashpoint("after_audit")
            # step 7: drop our staging (recoverable if we crash before this)
            _rmtree(os.path.join(self.staging_dir, txn_id))
            return CommitResult(gen_n + 1, new_digest, added, present)

    @staticmethod
    def _hash_blob(path: str) -> tuple[str, int, str]:
        with open(path, "rb") as fh:
            sha, n, b2 = crypto.sha256_stream(iter(lambda: fh.read(crypto.CHUNK), b""))
        return "sha256:" + sha, n, b2

    # -- query (committed-only) -------------------------------------------
    def committed_packs(self) -> dict:
        return self.current()["packs"]

    def list_packs(self) -> list[dict]:
        out = []
        for uid, p in sorted(self.current()["packs"].items()):
            out.append({
                "pack_uid": uid,
                "custodian": p["custodian"],
                "pack_id": p["pack_id"],
                "file_count": len(p["files"]),
                "imported_at": p["imported_at"],
            })
        return out

    def get_pack(self, pack_uid: str) -> dict:
        packs = self.committed_packs()
        if pack_uid not in packs:
            raise UncommittedError(f"pack {pack_uid} is not committed")
        return packs[pack_uid]

    def get_file_bytes(self, pack_uid: str, name: str) -> bytes:
        pack = self.get_pack(pack_uid)
        entry = None
        for f in pack["files"]:
            if f["name"] == name:
                entry = f
                break
        if entry is None:
            raise KeyError(f"{name} not in pack {pack_uid}")
        bpath = self.blob_path(entry["sha256"])
        if not os.path.exists(bpath):
            raise IntegrityError(f"blob for {entry['sha256']} is missing")
        with open(bpath, "rb") as fh:
            data = fh.read()
        sha, n, b2 = crypto.sha256_stream([data])
        if "sha256:" + sha != entry["sha256"] or n != entry["size"]:
            raise IntegrityError(
                f"stored bytes for {entry['sha256']} were replaced"
            )
        return data

    def find_by_path(self, path: str) -> list[dict]:
        key = name_key(path)
        hits = []
        for uid, p in sorted(self.committed_packs().items()):
            matched = []
            for f in p["files"]:
                cand = {name_key(f["path"])} | {name_key(a) for a in f.get("aliases", [])}
                if key in cand:
                    matched.append(f["name"])
            if matched:
                hits.append({
                    "pack_uid": uid,
                    "custodian": p["custodian"],
                    "pack_id": p["pack_id"],
                    "files": sorted(matched),
                })
        return hits

    # -- report (recomputed, read-only) -----------------------------------
    def report(self) -> dict:
        gen = self.current()
        packs = gen["packs"]
        chain_reports: dict[str, ChainReport] = {}
        per_custody: dict[str, list] = {}
        for uid, p in sorted(packs.items()):
            pub = self.public_key(p["custodian"], p.get("manifest"))
            rep = verify_chain(p["custody"], pub, p["custodian"])
            chain_reports[uid] = rep
            per_custody.setdefault(p["custodian"], []).extend(p["custody"])
        # combine manifest + custody claims for cross-chain conflicts
        claims: dict[str, list] = {}
        for uid, p in sorted(packs.items()):
            claims.setdefault(p["custodian"], []).extend(p["custody"])
            for f in p["files"]:
                claims[p["custodian"]].append({
                    "custodian": p["custodian"], "seq": 0, "type": "acquire",
                    "prev": None,
                    "subject": {"path": f["path"], "aliases": f.get("aliases", []),
                                "sha256": f["sha256"]},
                    "sig": "",
                })
        conflicts = cross_chain_conflicts(claims)
        # name reuse: same (custodian, pack_id) -> multiple pack_uids
        name_groups: dict[tuple, list] = {}
        for uid, p in packs.items():
            name_groups.setdefault((p["custodian"], p["pack_id"]), []).append(uid)
        name_reuse = [
            {"custodian": k[0], "pack_id": k[1], "pack_uids": sorted(v)}
            for k, v in sorted(name_groups.items()) if len(v) > 1
        ]
        blob_issues = self._check_blobs(gen)
        packs_summary = [
            {
                "pack_uid": uid,
                "custodian": packs[uid]["custodian"],
                "pack_id": packs[uid]["pack_id"],
                "chain_ok": chain_reports[uid].ok,
                "chain_reasons": chain_reports[uid].reasons,
                "revoked": chain_reports[uid].revoked,
            }
            for uid in sorted(packs)
        ]
        return {
            "schema": "evstore/report/1",
            "store_schema": SCHEMA_VERSION,
            "generation": gen["generation"],
            "index_digest": digest(gen),
            "packs": packs_summary,
            "conflicts": [c.as_dict() for c in conflicts],
            "name_reuse": name_reuse,
            "blob_issues": blob_issues,
            "missing_custody_segments": [
                {"pack_uid": uid,
                 "reasons": [r for r in rep.reasons if r in
                             ("MISSING_SEGMENT", "LINK_BROKEN", "DUPLICATE_SEQ",
                              "BAD_SIGNATURE")]}
                for uid, rep in sorted(chain_reports.items()) if not rep.ok
            ],
            "revoked": [
                {"pack_uid": uid, "revoked_at": rep.revoked_at}
                for uid, rep in sorted(chain_reports.items()) if rep.revoked
            ],
        }

    def _check_blobs(self, gen: dict) -> list[dict]:
        issues = []
        for sha, meta in sorted(gen.get("blobs", {}).items()):
            bpath = self.blob_path(sha)
            if not os.path.exists(bpath):
                issues.append({"sha256": sha, "problem": "missing"})
                continue
            got_sha, n, b2 = self._hash_blob(bpath)
            if got_sha != sha or n != meta["size"]:
                issues.append({"sha256": sha, "problem": "bytes_replaced"})
        return issues


def _rmtree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)
