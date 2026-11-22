"""End-to-end demo for evstore (run: python example.py).

Builds two synthetically-conflicting evidence packs, imports them in one
atomic generation, prints the recomputed report, resolves the shared path via
its alias, runs the independent verifier, and emits a minimal replayable repro
bundle under ./_demo/.
"""

from __future__ import annotations

import json
import os
import shutil

from evstore.importer import Importer
from evstore.repro import generate, run_replay
from evstore.scenario import build_scenario
from evstore.store import Store
from evstore.verifier import verify_store


def demo_scenario() -> dict:
    return {
        "name": "demo-conflict",
        "packs": [
            {"custodian": "alice", "pack_id": "A", "created": 1700000000,
             "files": [{"name": "report.pdf", "path": "C:\\Cases\\77\\report.pdf",
                        "aliases": ["c:/cases/77/REPORT.pdf"],
                        "content_hex": b"alice-signed-copy".hex()}],
             "custody": {"steps": ["acquire", "transfer", "verify"],
                         "subject_path": "C:\\Cases\\77\\report.pdf"}},
            {"custodian": "bob", "pack_id": "B", "created": 1700000100,
             "files": [{"name": "report.pdf", "path": "C:\\Cases\\77\\report.pdf",
                        "aliases": [], "content_hex": b"bob-signed-copy".hex()}],
             "custody": {"steps": ["acquire", "transfer"],
                         "subject_path": "C:\\Cases\\77\\report.pdf"}},
        ],
    }


def main(work_dir: str | None = None) -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    demo = work_dir or os.path.join(here, "_demo")
    shutil.rmtree(demo, ignore_errors=True)
    os.makedirs(demo, exist_ok=True)

    scn = demo_scenario()
    packs, keys = build_scenario(scn, os.path.join(demo, "inputs"))
    store = Store(os.path.join(demo, "store"), trusted_keys=keys).init()
    res = Importer(store).import_packs([packs["A"], packs["B"]])
    print("committed generation:", res.generation, "added:", len(res.added))

    report = store.report()
    print("conflicts:", json.dumps(report["conflicts"], indent=2))
    by_path = store.find_by_path("c://CASES/77/report.PDF")
    print("alias lookup ->", [h["custodian"] for h in by_path])

    v = verify_store(os.path.join(demo, "store"), keys)
    print("independent verifier ok:", v.ok)

    bundle = os.path.join(demo, "bundle")
    generate(scn, bundle, actions=["import", "verify", "report"],
             expected={"verification_ok": True, "conflicts_min": 1},
             note="two custodians disagree over an aliased path")
    replay = run_replay(bundle, os.path.join(demo, "replay"))
    print("repro bundle reproduced:", replay["reproduced"])
    print("bundle at:", bundle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
