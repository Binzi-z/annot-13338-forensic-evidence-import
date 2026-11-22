"""Streaming, crash-safe evidence-pack importer.

Public flow::

    importer = Importer(store)
    staged  = importer.stage_pack(pack_dir, txn_id)   # no lock, streams+verifies
    importer.commit([staged, ...], txn_id)            # locked, atomic, durable

``commit`` accepts a list of already-verified :class:`StagedPack` objects so
that *parallel* workers can each stage independently and then commit together
in one atomic generation bump.

Fault injection uses :func:`evstore.faults.crashpoint` at protocol boundaries;
the hard-kill test additionally re-runs staging with ``EVSTORE_CRASH_HARD=1``
so that ``os._exit`` fires and no Python cleanup runs at all.
"""

from __future__ import annotations

import os
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import crypto
from .custody import verify_chain
from .errors import IntegrityError, ManifestError
from .faults import InjectedCrash, crashpoint
from .fsutil import atomic_write_json, read_json
from .manifest import manifest_digest, require_ok

__all__ = [
    "Importer", "StagedPack", "StagedFile",
    "snapshot_sources", "verify_source_unchanged", "InjectedCrash",
]


class StagedFile:
    def __init__(self, name: str, path: str, aliases, size: int, sha256: str,
                 blake2b: str, staged_path: str):
        self.name = name
        self.path = path
        self.aliases = aliases
        self.size = size
        self.sha256 = sha256
        self.blake2b = blake2b
        self.staged_path = staged_path

    def to_record(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "aliases": list(self.aliases),
            "size": self.size,
            "sha256": self.sha256,
            "blake2b": self.blake2b,
        }


class StagedPack:
    def __init__(self, pack_uid: str, custodian: str, pack_id: str,
                 manifest: dict, manifest_digest_value: str,
                 custody: list[dict], custody_head: str | None,
                 files: list[StagedFile], source_dir: str, txn_id: str,
                 source_changed: list[str] | None = None):
        self.pack_uid = pack_uid
        self.custodian = custodian
        self.pack_id = pack_id
        self.manifest = manifest
        self.manifest_digest = manifest_digest_value
        self.custody = custody
        self.custody_head = custody_head
        self.files = files
        self.source_dir = source_dir
        self.txn_id = txn_id
        self.source_changed = list(source_changed or [])

    def to_pack_record(self, txn_id: str) -> dict:
        return {
            "custodian": self.custodian,
            "pack_id": self.pack_id,
            "manifest": self.manifest,
            "manifest_digest": self.manifest_digest,
            "custody": self.custody,
            "custody_head": self.custody_head,
            "source_dir": self.source_dir,
            "txn": txn_id,
            "imported_at": int(time.time()),
            "files": [f.to_record() for f in self.files],
        }


class Importer:
    def __init__(self, store):
        self.store = store

    def _txn_dir(self, txn_id: str) -> str:
        return os.path.join(self.store.staging_dir, txn_id)

    def stage_pack(
        self,
        pack_dir: str,
        txn_id: str | None = None,
        trusted_key: Ed25519PublicKey | None = None,
        after_copy_hook=None,
        source_snapshot: dict | None = None,
    ) -> StagedPack:
        """Stream + verify one pack into staging. Holds NO store lock.

        *source_snapshot* (name -> (mtime_ns, size)) can be supplied so that a
        caller which captured the source state before a parallel run can detect
        files changed mid-import; the staged bytes are still what get committed.
        """
        txn_id = txn_id or f"txn-{os.getpid()}-{time.time_ns()}"
        pack_dir = os.path.abspath(pack_dir)
        manifest_path = os.path.join(pack_dir, "manifest.json")
        custody_path = os.path.join(pack_dir, "custody.json")
        if not os.path.exists(manifest_path):
            raise ManifestError(f"missing manifest at {manifest_path}")
        manifest = read_json(manifest_path)
        custody = read_json(custody_path) if os.path.exists(custody_path) else []

        tdir = self._txn_dir(txn_id)
        os.makedirs(tdir, exist_ok=True)
        pack_uid = manifest_digest(manifest)
        pdir = os.path.join(tdir, pack_uid.replace(":", "_"))
        os.makedirs(pdir, exist_ok=True)
        # Merge this pack's intent into the transaction journal so that a crash
        # mid-multi-pack stage still lists every pack the txn is responsible for.
        tmeta_path = os.path.join(tdir, "txn.json")
        if os.path.exists(tmeta_path):
            tmeta = read_json(tmeta_path)
            tmeta.setdefault("packs", [])
            if not any(p.get("pack_uid") == pack_uid for p in tmeta["packs"]):
                tmeta["packs"].append({"pack_uid": pack_uid, "pack_dir": pack_dir,
                                       "custodian": manifest.get("custodian")})
            tmeta["pid"] = os.getpid()
        else:
            tmeta = {
                "txn": txn_id, "pid": os.getpid(), "started": int(time.time()),
                "packs": [{"pack_uid": pack_uid, "pack_dir": pack_dir,
                           "custodian": manifest.get("custodian")}],
            }
        atomic_write_json(tmeta_path, tmeta)
        crashpoint("after_stage_begin")

        try:
            rep = require_ok(manifest, trusted_key)
            custodian = rep.custodian
            pub = trusted_key or self._trusted(custodian, manifest)
            chain_rep = verify_chain(custody, pub, custodian) if (custody and pub) else None

            staged_files: list[StagedFile] = []
            changed_sources: list[str] = []
            for entry in rep.files:
                src = os.path.join(pack_dir, entry.name)
                if not os.path.exists(src):
                    raise IntegrityError(f"missing payload {entry.name}")
                staged_path = os.path.join(pdir, entry.name)
                if self._stream_copy(src, staged_path, entry, source_snapshot):
                    changed_sources.append(entry.name)
                crashpoint("after_copy")
                if after_copy_hook is not None:
                    after_copy_hook(entry.name, staged_path)
                sha, n, b2 = self._hash(staged_path)
                if "sha256:" + sha != entry.sha256 or n != entry.size:
                    raise IntegrityError(
                        f"payload {entry.name} does not match manifest "
                        f"(size {n}/{entry.size})")
                if b2 != entry.blake2b:
                    raise IntegrityError(f"payload {entry.name} blake2b mismatch")
                staged_files.append(StagedFile(
                    entry.name, entry.path, entry.aliases, entry.size,
                    entry.sha256, entry.blake2b, staged_path,
                ))
            crashpoint("after_verify")
        except BaseException:
            from .store import _rmtree
            _rmtree(tdir)
            raise

        head = chain_rep.head if chain_rep else None
        return StagedPack(
            pack_uid=pack_uid, custodian=custodian, pack_id=rep.pack_id,
            manifest=manifest, manifest_digest_value=pack_uid,
            custody=list(custody), custody_head=head, files=staged_files,
            source_dir=pack_dir, txn_id=txn_id, source_changed=changed_sources,
        )

    def _trusted(self, custodian: str, manifest: dict) -> Ed25519PublicKey | None:
        try:
            return self.store.public_key(custodian, manifest)
        except Exception:
            return None

    def _stream_copy(self, src, dst, entry, snapshot) -> bool:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        changed = False
        if snapshot is not None and entry.name in snapshot:
            mtime_ns, size = snapshot[entry.name]
            try:
                cur = os.stat(src)
                if cur.st_mtime_ns != mtime_ns or cur.st_size != size:
                    changed = True
            except OSError:
                changed = True
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            while True:
                chunk = fin.read(crypto.CHUNK)
                if not chunk:
                    break
                fout.write(chunk)
            fout.flush()
            os.fsync(fout.fileno())
        return changed

    @staticmethod
    def _hash(path: str) -> tuple[str, int, str]:
        with open(path, "rb") as fh:
            return crypto.sha256_stream(iter(lambda: fh.read(crypto.CHUNK), b""))

    def commit(self, staged: list[StagedPack], txn_id: str, timeout: float = 30.0):
        return self.store.commit_staged(staged, txn_id, timeout=timeout)

    def import_packs(self, pack_dirs, txn_id: str | None = None,
                     trusted_key=None, timeout: float = 30.0):
        """Convenience: stage all then commit as one generation."""
        txn_id = txn_id or f"txn-{os.getpid()}-{time.time_ns()}"
        staged = [self.stage_pack(d, txn_id, trusted_key) for d in pack_dirs]
        return self.commit(staged, txn_id, timeout=timeout)


def snapshot_sources(pack_dir: str) -> dict[str, tuple[int, int]]:
    """Record (mtime_ns, size) for each manifest-listed payload in *pack_dir*."""
    manifest = read_json(os.path.join(pack_dir, "manifest.json"))
    snap = {}
    for f in manifest.get("files", []):
        src = os.path.join(pack_dir, f["name"])
        try:
            st = os.stat(src)
            snap[f["name"]] = (st.st_mtime_ns, st.st_size)
        except OSError:
            snap[f["name"]] = (-1, -1)
    return snap


def verify_source_unchanged(staged: StagedPack) -> list[str]:
    """Re-hash *source* payloads; return names whose bytes changed after staging."""
    changed = []
    for f in staged.files:
        src = os.path.join(staged.source_dir, f.name)
        if not os.path.exists(src):
            changed.append(f.name)
            continue
        sha, n, _ = Importer._hash(src)
        if "sha256:" + sha != f.sha256 or n != f.size:
            changed.append(f.name)
    return changed
