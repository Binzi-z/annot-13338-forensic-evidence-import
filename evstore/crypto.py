"""Ed25519 signatures and streaming content digests."""

from __future__ import annotations

import base64
import hashlib
from typing import BinaryIO, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_bytes

CHUNK = 1 << 20  # 1 MiB streaming window


# --------------------------------------------------------------------------- #
# Key handling
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def public_bytes(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def load_public(text: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(text))


def private_to_bytes(priv: Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def private_from_bytes(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


# --------------------------------------------------------------------------- #
# Signing
# --------------------------------------------------------------------------- #
def sign_object(priv: Ed25519PrivateKey, obj) -> str:
    """Detached signature (base64) over the canonical encoding of *obj*."""
    sig = priv.sign(canonical_bytes(obj))
    return base64.b64encode(sig).decode("ascii")


def verify_object(pub: Ed25519PublicKey, obj, signature_b64: str) -> None:
    """Raise ``InvalidSignature`` if *obj* is not signed by *pub*."""
    sig = base64.b64decode(signature_b64)
    try:
        pub.verify(sig, canonical_bytes(obj))
    except InvalidSignature:
        raise


# --------------------------------------------------------------------------- #
# Streaming digests
# --------------------------------------------------------------------------- #
def sha256_stream(chunks: Iterable[bytes]) -> tuple[str, int, str]:
    """Return ``(sha256_hex, total_bytes, blake2b_hex)`` over *chunks*."""
    h = hashlib.sha256()
    b = hashlib.blake2b(digest_size=32)
    n = 0
    for chunk in chunks:
        if not chunk:
            continue
        h.update(chunk)
        b.update(chunk)
        n += len(chunk)
    return h.hexdigest(), n, b.hexdigest()


def sha256_file(path: str) -> tuple[str, int, str]:
    with open(path, "rb") as fh:
        return sha256_stream(iter(lambda: fh.read(CHUNK), b""))


def read_chunks(fh: BinaryIO) -> Iterable[bytes]:
    while True:
        chunk = fh.read(CHUNK)
        if not chunk:
            return
        yield chunk


def merkle_root(leaves: list[str]) -> str:
    """Binary Merkle root over ordered ``sha256:`` hex leaves (empty -> zero)."""
    if not leaves:
        return "sha256:" + ("0" * 64)
    level = [bytes.fromhex(x.split(":", 1)[1]) for x in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hashlib.sha256(left + right).digest())
        level = nxt
    return "sha256:" + level[0].hex()
