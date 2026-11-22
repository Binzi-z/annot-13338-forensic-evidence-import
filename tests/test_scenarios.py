"""End-to-end evidence semantics: aliasing, conflicts, custody defects,
revocation, same-name reuse, source change during recovery, overlap, repro."""

import json
import os
import subprocess
import sys

import pytest

from conftest import build_store, hx
from evstore import scenario as scen
from evstore.importer import Importer, snapshot_sources, verify_source_unchanged
from evstore.repro import generate as repro_generate, run_replay
from evstore.store import Store
from evstore.verifier import verify_store


def _two_custodian_scn(conflict=True):
    """alice and bob assert content for the same path via different aliases."""
    c_alice = hx("content-alice")
    c_bob = hx("content-bob") if conflict else hx("content-alice")
    return {
        "name": "conflict" if conflict else "agree",
        "packs": [
            {
                "custodian": "alice", "pack_id": "A", "created": 1,
                "files": [{"name": "doc.bin", "path": "C:\\Shared\\Evidence.bin",
                           "aliases": ["c:/shared/evidence.bin"],
                           "content_hex": c_alice}],
                "custody": {"steps": ["acquire", "transfer"],
                            "subject_path": "C:\\Shared\\Evidence.bin"},
            },
            {
                "custodian": "bob", "pack_id": "B", "created": 2,
                "files": [{"name": "doc.bin", "path": "C:\\Shared\\EVIDENCE.BIN",
                           "aliases": ["C:/Shared/./Evidence.bin"],
                           "content_hex": c_bob}],
                "custody": {"steps": ["acquire", "transfer"],
                            "subject_path": "C:\\Shared\\EVIDENCE.BIN"},
            },
        ],
    }


# --------------------------------------------------------------------------- #
# Path aliasing across custodians
# --------------------------------------------------------------------------- #
def test_alias_lookup_finds_all_custodians(tmp_path):
    store, dirs, keys = build_store(tmp_path, _two_custodian_scn())
    Importer(store).import_packs(dirs)
    hits = store.find_by_path("c:\\SHARED\\evidence.BIN")
    assert len(hits) == 2
    assert {h["custodian"] for h in hits} == {"alice", "bob"}


def test_conflict_is_reported_not_resolved(tmp_path):
    store, dirs, keys = build_store(tmp_path, _two_custodian_scn(conflict=True))
    Importer(store).import_packs(dirs)
    rep = store.report()
    assert rep["conflicts"], "expected a cross-custodian conflict"
    c = rep["conflicts"][0]
    assert set(c["custodians"]) == {"alice", "bob"}
    assert len(c["values"]) == 2  # both content digests retained, neither dropped
    # original bytes of BOTH are preserved and readable
    packs = store.committed_packs()
    for uid, p in packs.items():
        assert store.get_file_bytes(uid, "doc.bin") in (
            b"content-alice", b"content-bob")


def test_no_conflict_when_content_agrees(tmp_path):
    store, dirs, keys = build_store(tmp_path, _two_custodian_scn(conflict=False))
    Importer(store).import_packs(dirs)
    rep = store.report()
    assert rep["conflicts"] == []
    assert verify_store(str(tmp_path / "store"), keys).ok


# --------------------------------------------------------------------------- #
# Custody defects and revocation -> recomputable report, bytes preserved
# --------------------------------------------------------------------------- #
def _defect_scn(kind):
    content = hx("payload")
    custody = {"steps": ["acquire", "transfer", "verify"]}
    if kind == "missing":
        custody["skip_seqs"] = [1]          # drop a middle segment
    elif kind == "revoked":
        custody["revoke_at_seq"] = 3
    elif kind == "tamper":
        custody["tamper"] = "body"
    return {
        "name": f"defect-{kind}",
        "packs": [{
            "custodian": "alice", "pack_id": "P", "created": 1,
            "files": [{"name": "a.bin", "path": "C:\\Ev\\a.bin",
                       "aliases": [], "content_hex": content}],
            "custody": custody,
        }],
    }


@pytest.mark.parametrize("kind,needle", [
    ("missing", "missing_custody_segments"),
    ("revoked", "revoked"),
    ("tamper", "missing_custody_segments"),
])
def test_custody_defects_recomputable_report(tmp_path, kind, needle):
    store, dirs, keys = build_store(tmp_path, _defect_scn(kind))
    res = Importer(store).import_packs(dirs)
    uid = res.added[0]
    # bytes still preserved despite a defective chain
    assert store.get_file_bytes(uid, "a.bin") == b"payload"
    rep = store.report()
    assert rep[needle], f"expected {needle} populated for {kind}"
    # report is recomputable: calling twice yields identical structure
    rep2 = store.report()
    assert rep == rep2
    # independent verifier still considers the STORE consistent (the defect is
    # recorded as truth about the chain, not corruption of the store)
    v = verify_store(str(tmp_path / "store"), keys)
    assert v.ok, v.errors


def test_revoked_chain_surfaces_revocation(tmp_path):
    store, dirs, keys = build_store(tmp_path, _defect_scn("revoked"))
    res = Importer(store).import_packs(dirs)
    rep = store.report()
    assert any(r["pack_uid"] == res.added[0] for r in rep["revoked"])


# --------------------------------------------------------------------------- #
# Same-name reuse: same custodian+pack_id, different content in a later import
# --------------------------------------------------------------------------- #
def test_same_name_reuse_keeps_provenance(tmp_path):
    v1 = hx("version-one")
    v2 = hx("version-two")
    inputs = str(tmp_path / "in1")
    scn1 = {"name": "v1", "packs": [{
        "custodian": "alice", "pack_id": "SAME", "created": 1,
        "files": [{"name": "a.bin", "path": "C:\\Ev\\a.bin",
                   "aliases": [], "content_hex": v1}],
        "custody": {"steps": ["acquire"]}}]}
    packs, keys = scen.build_scenario(scn1, inputs)
    store = Store(str(tmp_path / "store"), trusted_keys=keys).init()
    r1 = Importer(store).import_packs([packs["SAME"]])

    # second pack, same custodian + pack_id, DIFFERENT content (reused name)
    inputs2 = str(tmp_path / "in2")
    scn2 = {"name": "v2", "packs": [{
        "custodian": "alice", "pack_id": "SAME", "created": 2,
        "files": [{"name": "a.bin", "path": "C:\\Ev\\a.bin",
                   "aliases": [], "content_hex": v2}],
        "custody": {"steps": ["acquire"]}}]}
    packs2, keys2 = scen.build_scenario(scn2, inputs2)
    store.trusted_keys.update(keys2)
    r2 = Importer(store).import_packs([packs2["SAME"]])

    assert r2.generation == r1.generation + 1
    assert len(store.committed_packs()) == 2  # both versions retained
    rep = store.report()
    assert rep["name_reuse"], "same (custodian, pack_id) should be flagged"
    assert set(rep["name_reuse"][0]["pack_uids"]) == set(r1.added + r2.added)
    # both bodies are independently retrievable
    assert store.get_file_bytes(r1.added[0], "a.bin") == b"version-one"
    assert store.get_file_bytes(r2.added[0], "a.bin") == b"version-two"


# --------------------------------------------------------------------------- #
# Source file changes during staging / recovery
# --------------------------------------------------------------------------- #
def test_source_change_detected_via_snapshot(tmp_path):
    scn = {"name": "src", "packs": [{
        "custodian": "alice", "pack_id": "P", "created": 1,
        "files": [{"name": "a.bin", "path": "C:\\Ev\\a.bin",
                   "aliases": [], "content_hex": hx("initial")}],
        "custody": {"steps": ["acquire"]}}]}
    store, dirs, keys = build_store(tmp_path, scn)
    src = os.path.join(dirs[0], "a.bin")

    # (1) Source rewritten with different bytes BEFORE it is copied: staging
    #     must refuse (staged bytes no longer match the signed manifest) and
    #     publish nothing.
    snap = snapshot_sources(dirs[0])
    with open(src, "wb") as fh:
        fh.write(b"swapped-mid-import")
    from evstore.errors import IntegrityError
    with pytest.raises(IntegrityError):
        Importer(store).stage_pack(dirs[0], "t", source_snapshot=snap)
    assert store.current()["packs"] == {}
    assert list((tmp_path / "store" / "staging").iterdir()) == []

    # (2) Source touched (mtime changes, same bytes): staging succeeds but the
    #     snapshot records the change so the operator knows it moved under them.
    restore = bytes.fromhex(hx("initial"))
    with open(src, "wb") as fh:
        fh.write(restore)
    snap2 = snapshot_sources(dirs[0])
    os.utime(src, ns=(snap2["a.bin"][0] + 10_000_000, snap2["a.bin"][0] + 10_000_000))
    staged = Importer(store).stage_pack(dirs[0], "t2", source_snapshot=snap2)
    assert "a.bin" in staged.source_changed
    Importer(store).commit([staged], "t2")

    # (3) Source changed AFTER a successful stage: re-hash before commit flags
    #     it, and the *originally staged* bytes are what get committed, so the
    #     evidence is preserved byte-for-byte (use a distinct pack_id so this is
    #     a genuinely new import, not an idempotent re-commit).
    scn2 = {"name": "src2", "packs": [{
        "custodian": "alice", "pack_id": "P-late", "created": 2,
        "files": [{"name": "a.bin", "path": "C:\\Ev\\a.bin",
                   "aliases": [], "content_hex": hx("late-original")}],
        "custody": {"steps": ["acquire"]}}]}
    late = str(tmp_path / "late")
    packs_late, keys_late = scen.build_scenario(scn2, late)
    store.trusted_keys.update(keys_late)
    staged2 = Importer(store).stage_pack(packs_late["P-late"], "t3")
    with open(os.path.join(packs_late["P-late"], "a.bin"), "wb") as fh:
        fh.write(b"changed-after-stage")
    assert verify_source_unchanged(staged2) == ["a.bin"]
    res = Importer(store).commit([staged2], "t3")
    assert store.get_file_bytes(res.added[0], "a.bin") == b"late-original"


# --------------------------------------------------------------------------- #
# Two overlapping import tasks
# --------------------------------------------------------------------------- #
def _one_pack_scn(custodian, pack_id, content, path="C:\\Ev\\a.bin"):
    return {"name": pack_id, "packs": [{
        "custodian": custodian, "pack_id": pack_id, "created": 1,
        "files": [{"name": "a.bin", "path": path, "aliases": [],
                   "content_hex": hx(content)}],
        "custody": {"steps": ["acquire"]}}]}


def test_overlapping_imports_from_two_processes(tmp_path):
    """Two child processes import different packs into one store concurrently."""
    store, dirs, keys = build_store(tmp_path, _one_pack_scn("alice", "A", "aa"))
    # build a second, independent pack set
    packs2, keys2 = scen.build_scenario(
        _one_pack_scn("bob", "B", "bb"), str(tmp_path / "in2"))
    keys.update(keys2)
    store.trusted_keys.update(keys2)

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {**os.environ,
           "PYTHONPATH": root + os.pathsep + os.environ.get("PYTHONPATH", "")}
    jobs = [
        {"op": "import", "root": str(tmp_path / "store"),
         "packs": [dirs[0]], "txn": "w1", "keys": keys},
        {"op": "import", "root": str(tmp_path / "store"),
         "packs": [packs2["B"]], "txn": "w2", "keys": keys},
    ]
    procs = [subprocess.Popen(
        [sys.executable, "-m", "evstore.worker", json.dumps(j)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        for j in jobs]
    outs = []
    for p in procs:
        o, e = p.communicate(timeout=60)
        assert p.returncode == 0, e
        outs.append(json.loads(o))

    store2 = Store(str(tmp_path / "store"), trusted_keys=keys).open()
    packs = store2.committed_packs()
    assert len(packs) == 2  # both serialised commits landed; nothing lost
    assert {p["custodian"] for p in packs.values()} == {"alice", "bob"}
    v = verify_store(str(tmp_path / "store"), keys)
    assert v.ok, v.errors
    # generations are strictly ordered and chained
    assert store2.current()["generation"] == 2


def test_overlapping_identical_packs_commit_once(tmp_path):
    """Two processes importing the SAME pack must not duplicate it."""
    store, dirs, keys = build_store(tmp_path, _one_pack_scn("alice", "A", "aa"))
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {**os.environ,
           "PYTHONPATH": root + os.pathsep + os.environ.get("PYTHONPATH", "")}
    jobs = [{"op": "import", "root": str(tmp_path / "store"),
             "packs": [dirs[0]], "txn": f"dup{i}", "keys": keys} for i in range(2)]
    procs = [subprocess.Popen(
        [sys.executable, "-m", "evstore.worker", json.dumps(j)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=env)
        for j in jobs]
    for p in procs:
        _, e = p.communicate(timeout=60)
        assert p.returncode == 0, e
    store2 = Store(str(tmp_path / "store"), trusted_keys=keys).open()
    assert len(store2.committed_packs()) == 1
    assert verify_store(str(tmp_path / "store"), keys).ok


# --------------------------------------------------------------------------- #
# Repro bundle: generate + replay reproduces, and minimises
# --------------------------------------------------------------------------- #
def test_repro_generate_and_replay(tmp_path):
    scn = _two_custodian_scn(conflict=True)
    bundle = str(tmp_path / "bundle")
    repro_generate(
        scn, bundle,
        actions=["import", "verify", "report"],
        expected={"verification_ok": True, "committed_packs": 2,
                  "conflicts_min": 1},
        note="two custodians disagree about the same aliased file",
    )
    for f in ("scenario.json", "bundle.json", "replay.py", "README.txt"):
        assert os.path.exists(os.path.join(bundle, f))
    result = run_replay(bundle, str(tmp_path / "replay1"))
    assert result["reproduced"], result
    assert result["conflicts_min"] if "conflicts_min" in result else True
    assert result["verification_ok"] is True

    # the generated standalone replay.py works from a fresh workdir too
    work = str(tmp_path / "replay2")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = subprocess.run(
        [sys.executable, os.path.join(bundle, "replay.py"), work],
        capture_output=True, text=True,
        env={**os.environ,
             "PYTHONPATH": root + os.pathsep + os.environ.get("PYTHONPATH", "")},
        timeout=120,
    )
    assert p.returncode == 0, p.stderr
    summary = json.loads(p.stdout.strip().splitlines()[-1])
    assert summary["reproduced"] is True


def test_repro_replays_soft_crash(tmp_path):
    scn = _one_pack_scn("alice", "A", "aa")
    bundle = str(tmp_path / "bundle")
    repro_generate(
        scn, bundle, actions=["import", "verify", "report"],
        expected={"verification_ok": True, "committed_packs": 0},
        crash_at="after_verify",
        note="crash during staging leaves nothing visible",
    )
    res = run_replay(bundle, str(tmp_path / "work"))
    assert res["reproduced"], res
    assert res["committed_packs"] == 0
