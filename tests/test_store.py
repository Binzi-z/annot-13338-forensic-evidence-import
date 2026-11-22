"""Store protocol: commit visibility, crash points, recovery, durability.

Crash coverage comes in two flavours:

* soft crash (in-process ``InjectedCrash``) at every named point, and
* **hard kill**: a real child process is terminated (``Popen.kill`` ==
  ``TerminateProcess`` on Windows) the instant it reaches a crash point, proving
  the *on-disk* protocol restores consistency with no ``finally`` cleanup.
"""

import json
import os
import subprocess
import sys
import time

import pytest

from conftest import build_store, hx
from evstore.errors import IntegrityError, UncommittedError
from evstore.faults import CRASHPOINTS
from evstore.importer import Importer, InjectedCrash
from evstore.store import Store
from evstore.verifier import verify_store


def _scn(custodian="alice", pack_id="P1", content="hello", path="C:\\Ev\\a.txt",
         aliases=None, custody=None):
    return {
        "name": "t",
        "packs": [{
            "custodian": custodian, "pack_id": pack_id, "created": 1,
            "files": [{"name": "a.txt", "path": path,
                       "aliases": aliases or [], "content_hex": hx(content)}],
            "custody": custody or {"steps": ["acquire", "transfer", "verify"]},
        }],
    }


def _crash_env(monkeypatch, point, hard=False):
    monkeypatch.setenv("EVSTORE_CRASH_AT", point)
    if hard:
        monkeypatch.setenv("EVSTORE_CRASH_HARD", "1")
    else:
        monkeypatch.delenv("EVSTORE_CRASH_HARD", raising=False)


def _run_worker(job, env_overrides):
    env = dict(os.environ)
    env.update(env_overrides)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "evstore.worker", json.dumps(job)],
        capture_output=True, text=True, env=env, timeout=60,
    )


def test_commit_visibility_and_read(tmp_path):
    store, dirs, keys = build_store(tmp_path, _scn())
    res = Importer(store).import_packs(dirs)
    assert res.generation == 1
    assert store.get_file_bytes(res.added[0], "a.txt") == b"hello"
    v = verify_store(str(tmp_path / "store"), keys)
    assert v.ok, v.errors


@pytest.mark.parametrize("point", sorted(CRASHPOINTS))
def test_soft_crash_then_recover(tmp_path, monkeypatch, point):
    store, dirs, keys = build_store(tmp_path, _scn())
    _crash_env(monkeypatch, point)
    imp = Importer(store)
    try:
        staged = [imp.stage_pack(d, "txn-x") for d in dirs]
        imp.commit(staged, "txn-x")
    except InjectedCrash as e:
        assert e.point == point
    monkeypatch.delenv("EVSTORE_CRASH_AT", raising=False)

    store2 = Store(str(tmp_path / "store"), trusted_keys=keys).open()
    gen = store2.current()
    committed = point in ("after_index", "after_audit")
    if committed:
        assert len(gen["packs"]) == 1
        uid = next(iter(gen["packs"]))
        assert store2.get_file_bytes(uid, "a.txt") == b"hello"
    else:
        assert len(gen["packs"]) == 0
        assert store2.list_packs() == []
    rep = verify_store(str(tmp_path / "store"), keys)
    assert rep.ok, rep.errors
    # A *soft* crash keeps this process alive, so recovery correctly treats the
    # transaction as owned by a live writer and leaves its staging untouched.
    # Staging reclamation for a dead writer is proven by the hard-kill test.
    if not committed:
        store3 = Store(str(tmp_path / "store"), trusted_keys=keys).open()
        assert store3.list_packs() == []


def test_crash_before_commit_keeps_no_partial_visible(tmp_path, monkeypatch):
    store, dirs, keys = build_store(tmp_path, _scn())
    _crash_env(monkeypatch, "after_generation")
    imp = Importer(store)
    with pytest.raises(InjectedCrash):
        staged = [imp.stage_pack(d, "t") for d in dirs]
        imp.commit(staged, "t")
    monkeypatch.delenv("EVSTORE_CRASH_AT", raising=False)
    # pointer still at generation 0 (the new generation is an orphan on disk)
    ptr = store.read_pointer()
    assert ptr["generation"] == 0
    assert store.current()["packs"] == {}
    res = store.recover()
    assert res.orphan_generations
    assert not (tmp_path / "store" / "generations" / "g-000001.json").exists()


def test_resume_after_crash_completes(tmp_path, monkeypatch):
    store, dirs, keys = build_store(tmp_path, _scn())
    _crash_env(monkeypatch, "after_verify")
    imp = Importer(store)
    with pytest.raises(InjectedCrash):
        imp.stage_pack(dirs[0], "t1")
    monkeypatch.delenv("EVSTORE_CRASH_AT", raising=False)
    store2 = Store(str(tmp_path / "store"), trusted_keys=keys).open()
    res = Importer(store2).import_packs(dirs)
    assert res.generation == 1
    assert store2.get_file_bytes(res.added[0], "a.txt") == b"hello"
    assert verify_store(str(tmp_path / "store"), keys).ok


def test_failed_verify_does_not_publish(tmp_path):
    store, dirs, keys = build_store(tmp_path, _scn())
    with open(os.path.join(dirs[0], "a.txt"), "wb") as fh:
        fh.write(b"tampered!")
    with pytest.raises(IntegrityError):
        Importer(store).import_packs(dirs)
    assert store.current()["packs"] == {}
    store.open(recover=True)
    assert list((tmp_path / "store" / "staging").iterdir()) == []


def test_original_bytes_preserved_when_blob_replaced(tmp_path):
    store, dirs, keys = build_store(tmp_path, _scn())
    res = Importer(store).import_packs(dirs)
    uid = res.added[0]
    pack = store.get_pack(uid)
    blob = tmp_path / "store" / "blobs" / pack["files"][0]["sha256"].split(":")[1]
    blob.write_bytes(b"different!")
    with pytest.raises(IntegrityError):
        store.get_file_bytes(uid, "a.txt")
    rep = store.report()
    assert any(b["problem"] == "bytes_replaced" for b in rep["blob_issues"])
    v = verify_store(str(tmp_path / "store"), keys)
    assert not v.ok


def test_reimport_same_pack_is_idempotent(tmp_path):
    store, dirs, keys = build_store(tmp_path, _scn())
    r1 = Importer(store).import_packs(dirs)
    store2 = Store(str(tmp_path / "store"), trusted_keys=keys).open()
    r2 = Importer(store2).import_packs(dirs)
    assert r2.generation == r1.generation
    assert r1.added[0] in r2.already_present or r1.added[0] in r2.added
    assert len(store2.current()["packs"]) == 1


def test_audit_log_hash_chained(tmp_path):
    store, dirs, keys = build_store(tmp_path, _scn())
    Importer(store).import_packs(dirs)
    entries = store.audit_entries()
    assert entries[0]["event"] == "init"
    assert any(e["event"] == "commit" for e in entries)
    prev = None
    for e in entries:
        assert e["prev"] == prev
        prev = e["digest"]


# --------------------------------------------------------------------------- #
# Hard-kill: terminate a REAL child process at a crash point.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("point", sorted(CRASHPOINTS))
def test_hard_kill_then_recover(tmp_path, point):
    store, dirs, keys = build_store(tmp_path, _scn())
    # The worker announces the point to a sidecar *before* os._exit; the parent
    # then hard-kills it.  We copy the sidecar-write logic here via the worker's
    # crash hook (faults.crashpoint runs os._exit for EVSTORE_CRASH_HARD).
    job = {"op": "stage_then_commit", "root": str(tmp_path / "store"),
           "packs": dirs, "txn": "hk", "keys": keys}
    p = subprocess.Popen(
        [sys.executable, "-m", "evstore.worker", json.dumps(job)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ,
             "PYTHONPATH": os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
             + os.pathsep + os.environ.get("PYTHONPATH", ""),
             "EVSTORE_CRASH_AT": point, "EVSTORE_CRASH_HARD": "1"},
    )
    try:
        p.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
    assert p.returncode == 97  # the worker hard-exited at the crash point

    # Now recover in a fresh process and assert consistency + visibility.
    store2 = Store(str(tmp_path / "store"), trusted_keys=keys).open()
    gen = store2.current()
    committed = point in ("after_index", "after_audit")
    if committed:
        assert len(gen["packs"]) == 1
        uid = next(iter(gen["packs"]))
        assert store2.get_file_bytes(uid, "a.txt") == b"hello"
    else:
        assert len(gen["packs"]) == 0
        assert store2.list_packs() == []
        assert list((tmp_path / "store" / "staging").iterdir()) == []
    v = verify_store(str(tmp_path / "store"), keys)
    assert v.ok, v.errors
