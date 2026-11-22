"""Signed evidence-pack manifest: model + independent verification.

A manifest enumerates the pack's synthetic files (name, canonical path,
aliases, size, sha256, blake2b), commits to them with a Merkle root, and is
signed by the custodian's Ed25519 key. Verification is pure: it re-derives the
Merkle root and checks the signature over the canonical unsigned body, and it
reports (never repairs) any mismatch so original bytes are preserved.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import crypto
from .canonical import digest
from .errors import ManifestError

MANIFEST_SCHEMA = "evstore/manifest/1"


@dataclass
class FileEntry:
    name: str
    path: str
    size: int
    sha256: str
    blake2b: str
    aliases: list[str] = field(default_factory=list)

    def unsigned(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "aliases": list(self.aliases),
            "size": self.size,
            "sha256": self.sha256,
            "blake2b": self.blake2b,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FileEntry":
        return cls(
            name=d["name"],
            path=d["path"],
            size=int(d["size"]),
            sha256=d["sha256"],
            blake2b=d["blake2b"],
            aliases=list(d.get("aliases", [])),
        )


def _manifest_body(
    custodian: str, pack_id: str, created: int, files: list[FileEntry]
) -> dict:
    entries = [f.unsigned() for f in files]
    return {
        "schema": MANIFEST_SCHEMA,
        "custodian": custodian,
        "pack_id": pack_id,
        "created": int(created),
        "files": entries,
        "merkle": crypto.merkle_root([f["sha256"] for f in entries]),
    }


def build_manifest(
    priv: Ed25519PrivateKey,
    custodian: str,
    pack_id: str,
    created: int,
    files: list[FileEntry],
) -> dict:
    body = _manifest_body(custodian, pack_id, created, files)
    sig = crypto.sign_object(priv, body)
    return {**body, "sig": sig, "public_key": crypto.public_bytes(priv.public_key())}


@dataclass
class ManifestReport:
    ok: bool
    custodian: str
    pack_id: str
    manifest_digest: str
    files: list[FileEntry]
    problems: list[str] = field(default_factory=list)

    def file_by_name(self, name: str) -> FileEntry | None:
        for f in self.files:
            if f.name == name:
                return f
        return None


def unsigned_of(manifest: dict) -> dict:
    return {k: v for k, v in manifest.items() if k not in ("sig", "public_key")}


def manifest_digest(manifest: dict) -> str:
    """Digest of the *signed* manifest (covers the signature too)."""
    return digest(manifest)


def verify_manifest(
    manifest: dict, trusted_key: Ed25519PublicKey | None = None
) -> ManifestReport:
    problems: list[str] = []
    if manifest.get("schema") != MANIFEST_SCHEMA:
        problems.append(f"unknown schema {manifest.get('schema')!r}")
    files_raw = manifest.get("files")
    files: list[FileEntry] = []
    if not isinstance(files_raw, list):
        problems.append("files is not a list")
        files_raw = []
    for fr in files_raw:
        try:
            files.append(FileEntry.from_dict(fr))
        except Exception as e:  # malformed entry – report, keep going
            problems.append(f"malformed file entry: {e}")
    # Re-derive merkle root independently.
    recomputed = crypto.merkle_root([f.sha256 for f in files])
    if recomputed != manifest.get("merkle"):
        problems.append("merkle root mismatch")
    # Signature.
    try:
        if trusted_key is not None:
            pub = trusted_key
        else:
            pub = crypto.load_public(manifest["public_key"])
        crypto.verify_object(pub, unsigned_of(manifest), manifest.get("sig", ""))
    except Exception:
        problems.append("manifest signature invalid")
    if trusted_key is not None and manifest.get("public_key") != crypto.public_bytes(trusted_key):
        problems.append("embedded public_key does not match trusted key")
    try:
        md = manifest_digest(manifest)
    except Exception:
        md = ""
        problems.append("manifest not canonicalisable")
    return ManifestReport(
        ok=not problems,
        custodian=manifest.get("custodian", "?"),
        pack_id=manifest.get("pack_id", "?"),
        manifest_digest=md,
        files=files,
        problems=problems,
    )


def require_ok(manifest: dict, trusted_key: Ed25519PublicKey | None = None) -> ManifestReport:
    rep = verify_manifest(manifest, trusted_key)
    if not rep.ok:
        raise ManifestError("; ".join(rep.problems))
    return rep
