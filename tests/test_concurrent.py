"""Concurrency stress: many processes import concurrently into one store."""

import json
import os
import subprocess
import sys

from conftest import hx
from evstore import scenario as scen
from evstore.store import Store
from evstore.verifier import verify_store


def _pack_scn(custodian, pack_id, content):
    return {"name": pack_id, "packs": [{
        "custodian": custodian, "pack_id": pack_id, "created": 1,
        "files": [{"name": "a.bin", "path": f"C:\\Ev\\{pack_id}.bin",
                   "aliases": [], "content_hex": hx(content)}],
        "custody": {"steps": ["acquire", "transfer"]}}]}


def test_many_concurrent_imports_all_land(tmp_path):
    """8 processes import 8 distinct packs at once; every one must be committed
    exactly once, generations strictly ordered, store fully verifiable."""
    store = Store(str(tmp_path / "store")).init()
    keys = {}
    dirs = []
    for i in range(8):
        packs, k = scen.build_scenario(
            _pack_scn(f"cust{i}", f"P{i}", f"content-{i}"),
            str(tmp_path / f"in{i}"))
        keys.update(k)
        dirs.append(packs[f"P{i}"])
    store.trusted_keys.update(keys)

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {**os.environ,
           "PYTHONPATH": root + os.pathsep + os.environ.get("PYTHONPATH", "")}
    procs = []
    for i, d in enumerate(dirs):
        job = {"op": "import", "root": str(tmp_path / "store"),
               "packs": [d], "txn": f"w{i}", "keys": keys}
        procs.append(subprocess.Popen(
            [sys.executable, "-m", "evstore.worker", json.dumps(job)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env))
    for p in procs:
        o, e = p.communicate(timeout=120)
        assert p.returncode == 0, e

    store2 = Store(str(tmp_path / "store"), trusted_keys=keys).open()
    packs = store2.committed_packs()
    assert len(packs) == 8
    assert store2.current()["generation"] == 8
    # every pack's bytes readable and correct
    for i in range(8):
        uid = next(u for u, p in packs.items() if p["pack_id"] == f"P{i}")
        assert store2.get_file_bytes(uid, "a.bin") == f"content-{i}".encode()
    v = verify_store(str(tmp_path / "store"), keys)
    assert v.ok, v.errors


def test_many_concurrent_duplicate_imports_commit_once(tmp_path):
    """8 processes import the SAME pack; exactly one pack must be committed."""
    store = Store(str(tmp_path / "store")).init()
    packs, keys = scen.build_scenario(
        _pack_scn("alice", "P", "dup"), str(tmp_path / "in"))
    store.trusted_keys.update(keys)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {**os.environ,
           "PYTHONPATH": root + os.pathsep + os.environ.get("PYTHONPATH", "")}
    procs = [subprocess.Popen(
        [sys.executable, "-m", "evstore.worker",
         json.dumps({"op": "import", "root": str(tmp_path / "store"),
                     "packs": [packs["P"]], "txn": f"d{i}", "keys": keys})],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=env)
        for i in range(8)]
    for p in procs:
        _, e = p.communicate(timeout=120)
        assert p.returncode == 0, e
    store2 = Store(str(tmp_path / "store"), trusted_keys=keys).open()
    assert len(store2.committed_packs()) == 1
    assert verify_store(str(tmp_path / "store"), keys).ok
