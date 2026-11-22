"""Verifiable parallel evidence import with crash-safe checkpoint recovery.

Package layout
--------------
errors     : exception types
canonical  : deterministic JSON encoding used for hashing / signing
pathalias  : Windows path alias normalisation + file-identity detection
crypto     : Ed25519 sign/verify + streaming sha256
manifest   : signed manifest model / verification
custody    : hash-chained custody events + chain validation
fsutil     : atomic writes, fsync helpers, cross-process file lock
store      : staging / journal / index-commit / recovery / query / report
importer   : streaming worker that copies, verifies and commits a pack
verifier   : independent consistency checker (evidence + index + audit)
scenario   : declarative, deterministic scenario DSL (shared by repro/tests)
repro      : minimal replayable reproduction bundle generator / replayer
"""

__all__ = ["store", "importer", "verifier", "scenario", "repro"]

SCHEMA_VERSION = "evstore/1"
