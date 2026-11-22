"""Unit tests: deterministic encoding, path aliasing, crypto, manifest, custody."""

import os

import pytest

from evstore import crypto
from evstore.canonical import canonical_bytes, canonical_text, digest
from evstore.custody import (
    cross_chain_conflicts,
    make_event,
    verify_chain,
)
from evstore.errors import ManifestError
from evstore.manifest import FileEntry, build_manifest, verify_manifest
from evstore.pathalias import file_identity, name_aliases, name_key, same_file
from evstore.scenario import build_custody, key_from_seed


# --------------------------------------------------------------------------- #
# canonical
# --------------------------------------------------------------------------- #
def test_canonical_is_order_independent():
    a = {"b": 1, "a": [2, {"y": True, "x": None}]}
    b = {"a": [2, {"x": None, "y": True}], "b": 1}
    assert canonical_bytes(a) == canonical_bytes(b)
    assert digest(a) == digest(b)


def test_canonical_rejects_floats_and_nonstring_keys():
    with pytest.raises(ValueError):
        canonical_bytes({"x": 1.5})
    with pytest.raises(ValueError):
        canonical_bytes({1: "a"})


def test_canonical_unicode_not_escaped():
    assert canonical_text({"k": "证"}) == '{"k":"证"}'


# --------------------------------------------------------------------------- #
# pathalias
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("a,b", [
    ("C:\\Cases\\A.EVD", "c:\\cases\\a.evd"),
    ("C:/Cases/A.EVD", "C:\\Cases\\A.EVD"),
    ("C:\\Cases\\A.EVD.", "C:\\Cases\\A.EVD"),
    ("C:\\Cases\\A.EVD   ", "C:\\Cases\\A.EVD"),
    ("C:\\Cases\\.\\A.EVD", "C:\\Cases\\A.EVD"),
    ("C:\\Cases\\Sub\\..\\A.EVD", "C:\\Cases\\A.EVD"),
    ("\\\\Server\\Share\\F.TXT", "\\\\server\\share\\f.txt"),
])
def test_name_aliases_true(a, b):
    assert name_aliases(a, b)


@pytest.mark.parametrize("a,b", [
    ("C:\\Cases\\A.EVD", "C:\\Cases\\B.EVD"),
    ("C:\\Cases\\A.EVD", "D:\\Cases\\A.EVD"),
    ("C:\\Cases\\A.EVD", "\\\\Server\\Cases\\A.EVD"),
])
def test_name_aliases_false(a, b):
    assert not name_aliases(a, b)


def test_name_key_is_stable():
    assert name_key("C:\\A\\B.EVD") == "c:\\a\\b.evd"


def test_file_identity_hardlink(tmp_path):
    src = tmp_path / "orig.bin"
    src.write_bytes(b"payload")
    try:
        link = tmp_path / "alias.bin"
        os.link(src, link)  # hard link on NTFS / POSIX
    except (OSError, NotImplementedError):
        pytest.skip("hard links unsupported here")
    assert file_identity(str(src)) == file_identity(str(link))
    assert same_file(str(src), str(link))
    assert not same_file(str(src), str(tmp_path / "nope.bin"))


def test_file_identity_same_spelling(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"z")
    assert same_file(str(f), str(f))
    assert same_file(str(f), str(f).upper())


# --------------------------------------------------------------------------- #
# crypto
# --------------------------------------------------------------------------- #
def test_sign_verify_roundtrip():
    priv, pub = crypto.generate_keypair()
    obj = {"a": 1, "b": [2, 3]}
    sig = crypto.sign_object(priv, obj)
    crypto.verify_object(pub, obj, sig)  # no raise


def test_sign_verify_detects_tamper():
    from cryptography.exceptions import InvalidSignature

    priv, pub = crypto.generate_keypair()
    sig = crypto.sign_object(priv, {"a": 1})
    with pytest.raises(InvalidSignature):
        crypto.verify_object(pub, {"a": 2}, sig)


def test_sha256_stream_matches_file(tmp_path):
    data = b"x" * 100000 + b"y" * 5
    p = tmp_path / "f"
    p.write_bytes(data)
    sha, n, b2 = crypto.sha256_file(str(p))
    import hashlib

    assert sha == hashlib.sha256(data).hexdigest()
    assert n == len(data)


def test_merkle_root_order_sensitive():
    a = "sha256:" + "11" * 32
    b = "sha256:" + "22" * 32
    assert crypto.merkle_root([a, b]) != crypto.merkle_root([b, a])
    assert crypto.merkle_root([]) == "sha256:" + "0" * 64


# --------------------------------------------------------------------------- #
# manifest
# --------------------------------------------------------------------------- #
def _entries(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"hello world")
    sha, n, b2 = crypto.sha256_file(str(p))
    return [FileEntry("f.bin", "C:\\Ev\\f.bin", n, "sha256:" + sha, b2,
                      ["c:/ev/F.BIN"])]


def test_manifest_roundtrip_ok(tmp_path):
    priv, pub = crypto.generate_keypair()
    ents = _entries(tmp_path)
    m = build_manifest(priv, "alice", "P1", 123, ents)
    rep = verify_manifest(m, pub)
    assert rep.ok, rep.problems
    assert rep.file_by_name("f.bin").size == 11


def test_manifest_detects_merkle_tamper(tmp_path):
    priv, pub = crypto.generate_keypair()
    m = build_manifest(priv, "alice", "P1", 123, _entries(tmp_path))
    m["files"][0]["sha256"] = "sha256:" + "00" * 32  # edit content claim
    rep = verify_manifest(m, pub)
    assert not rep.ok
    assert any("signature" in p or "merkle" in p for p in rep.problems)


def test_manifest_require_ok_raises(tmp_path):
    from evstore.manifest import require_ok

    priv, pub = crypto.generate_keypair()
    m = build_manifest(priv, "alice", "P1", 1, _entries(tmp_path))
    m["merkle"] = "sha256:" + "00" * 32
    with pytest.raises(ManifestError):
        require_ok(m, pub)


def test_manifest_wrong_trusted_key(tmp_path):
    priv, _pub = crypto.generate_keypair()
    _priv2, other = crypto.generate_keypair()
    m = build_manifest(priv, "alice", "P1", 1, _entries(tmp_path))
    rep = verify_manifest(m, other)
    assert not rep.ok


# --------------------------------------------------------------------------- #
# custody
# --------------------------------------------------------------------------- #
def _events(steps=("acquire", "transfer", "verify"), **kw):
    priv, pub_b64 = key_from_seed("cust1")
    pub = crypto.load_public(pub_b64)
    files = [{"path": "C:\\Ev\\f.bin", "content_hex": "00", "aliases": []}]
    evs = build_custody(priv, "cust1", files, {"steps": list(steps), **kw})
    return evs, pub


def test_chain_ok():
    evs, pub = _events()
    rep = verify_chain(evs, pub, "cust1")
    assert rep.ok, rep.reasons
    assert rep.leaves == 3


def test_chain_missing_segment():
    evs, pub = _events(skip_seqs=[1])
    rep = verify_chain(evs, pub, "cust1")
    assert not rep.ok
    assert "MISSING_SEGMENT" in rep.reasons


def test_chain_link_broken_when_swapped():
    evs, pub = _events()
    # simulate history swap: alter a middle event's prev and re-sign? here just
    # flip prev to break the link AND invalidate signature.
    evs[1]["prev"] = "sha256:" + "cd" * 32
    rep = verify_chain(evs, pub, "cust1")
    assert not rep.ok
    assert "LINK_BROKEN" in rep.reasons


def test_chain_tampered_body_breaks_signature():
    evs, pub = _events()
    evs[2]["note"] = "edited after the fact"
    rep = verify_chain(evs, pub, "cust1")
    assert not rep.ok
    assert "BAD_SIGNATURE" in rep.reasons


def test_chain_revocation_flagged():
    evs, pub = _events(revoke_at_seq=3)
    rep = verify_chain(evs, pub, "cust1")
    assert rep.revoked
    assert rep.revoked_at == 3


def test_chain_duplicate_seq():
    evs, pub = _events()
    dup = dict(evs[1])
    dup["seq"] = 1
    evs.insert(2, dup)
    rep = verify_chain(evs, pub, "cust1")
    assert "DUPLICATE_SEQ" in rep.reasons


def test_cross_chain_conflict():
    priv_a, _ = key_from_seed("alice")
    priv_b, _ = key_from_seed("bob")
    # same path, different content digests
    subj_a = {"path": "C:\\Shared\\doc.txt", "aliases": ["c:/shared/DOC.txt"],
              "sha256": "sha256:" + "11" * 32}
    subj_b = {"path": "C:\\Shared\\doc.txt", "aliases": [],
              "sha256": "sha256:" + "22" * 32}
    ev_a = [make_event(priv_a, "alice", 0, "acquire", None, subj_a)]
    ev_b = [make_event(priv_b, "bob", 0, "acquire", None, subj_b)]
    conflicts = cross_chain_conflicts({"alice": ev_a, "bob": ev_b})
    assert len(conflicts) == 1
    assert set(conflicts[0].custodians) == {"alice", "bob"}


def test_cross_chain_no_conflict_when_same_content():
    priv_a, _ = key_from_seed("alice")
    priv_b, _ = key_from_seed("bob")
    subj = {"path": "C:\\Shared\\doc.txt", "aliases": [],
            "sha256": "sha256:" + "11" * 32}
    ev_a = [make_event(priv_a, "alice", 0, "acquire", None, subj)]
    ev_b = [make_event(priv_b, "bob", 0, "transfer", None, dict(subj))]
    assert cross_chain_conflicts({"alice": ev_a, "bob": ev_b}) == []
