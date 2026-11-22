"""Minimal-reproduction: the minimiser shrinks a scenario while preserving the
failure, and the emitted bundle replays to the same outcome."""

import json
import os

from evstore.repro import generate, minimize, run_replay


def _big_conflict_scn():
    """4 packs; only alice+bob actually conflict over the shared alias. A
    minimiser should be able to drop the two irrelevant custodians."""
    return {
        "name": "big",
        "packs": [
            {"custodian": "alice", "pack_id": "A", "created": 1,
             "files": [{"name": "doc.bin", "path": "C:\\Shared\\doc.bin",
                        "aliases": ["c:/shared/DOC.bin"],
                        "content_hex": b"alice-content".hex()}],
             "custody": {"steps": ["acquire"],
                         "subject_path": "C:\\Shared\\doc.bin"}},
            {"custodian": "bob", "pack_id": "B", "created": 2,
             "files": [{"name": "doc.bin", "path": "C:\\Shared\\doc.bin",
                        "aliases": [],
                        "content_hex": b"bob-content".hex()}],
             "custody": {"steps": ["acquire"],
                         "subject_path": "C:\\Shared\\doc.bin"}},
            {"custodian": "carol", "pack_id": "C", "created": 3,
             "files": [{"name": "other.bin", "path": "C:\\Other\\x.bin",
                        "aliases": [], "content_hex": b"carol".hex()}],
             "custody": {"steps": ["acquire"]}},
            {"custodian": "dave", "pack_id": "D", "created": 4,
             "files": [{"name": "other.bin", "path": "C:\\Other2\\y.bin",
                        "aliases": [], "content_hex": b"dave".hex()}],
             "custody": {"steps": ["acquire"]}},
        ],
    }


def test_minimize_keeps_failure_and_shrinks(tmp_path):
    scn = _big_conflict_scn()
    expected = {"verification_ok": True, "conflicts_min": 1}

    # counter so we can hand the minimiser fresh work dirs
    counter = {"n": 0}

    def factory():
        counter["n"] += 1
        d = tmp_path / f"work{counter['n']}"
        d.mkdir(parents=True, exist_ok=True)
        return str(d)

    small = minimize(scn, expected, actions=["import", "verify", "report"],
                     work_factory=factory, max_rounds=20)
    # it dropped the two irrelevant custodians
    assert len(small["packs"]) < len(scn["packs"])
    assert [p["pack_id"] for p in small["packs"]] == ["A", "B"]

    # the minimised scenario still reproduces the conflict
    bundle = str(tmp_path / "min-bundle")
    generate(small, bundle, actions=["import", "verify", "report"],
             expected=expected, note="minimised conflict")
    res = run_replay(bundle, str(tmp_path / "replay"))
    assert res["reproduced"], res


def test_generate_bundle_is_self_describing(tmp_path):
    scn = _big_conflict_scn()
    bundle = str(tmp_path / "b")
    generate(scn, bundle, actions=["import", "verify", "report"],
             expected={"conflicts_min": 1}, note="demo")
    with open(os.path.join(bundle, "scenario.json"), encoding="utf-8") as fh:
        loaded = json.load(fh)
    assert loaded == scn  # canonical round-trip preserves the inputs exactly
    with open(os.path.join(bundle, "bundle.json"), encoding="utf-8") as fh:
        b = json.load(fh)
    assert b["schema"] == "evstore/repro/1"
    assert b["actions"] == ["import", "verify", "report"]
    assert b["keys"]["alice"]
