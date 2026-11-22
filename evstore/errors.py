"""Exception types used across the evidence store."""

from __future__ import annotations


class EvStoreError(Exception):
    """Base class for all store errors."""


class IntegrityError(EvStoreError):
    """Content bytes do not match their expected digest/size."""


class ManifestError(EvStoreError):
    """Signed manifest is malformed or its signature does not verify."""


class CustodyError(EvStoreError):
    """Custody chain is malformed (bad link, gap, unknown schema)."""


class UncommittedError(EvStoreError):
    """Query touched evidence that is not part of a committed generation."""


class RecoveryError(EvStoreError):
    """Store recovery could not reach a consistent state."""


class LockTimeout(EvStoreError):
    """Could not acquire the store write lock within the timeout."""
