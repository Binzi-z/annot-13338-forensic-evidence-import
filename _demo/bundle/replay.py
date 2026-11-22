#!/usr/bin/env python3
"""Standalone reproduction replay (generated). Usage: python replay.py <workdir>"""
import json, os, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "bundle.json"), "r", encoding="utf-8") as fh:
    _BUNDLE = json.load(fh)
sys.path.insert(0, _BUNDLE["evstore_root"])

from evstore.repro import run_replay

work = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp(prefix="evstore-repro-")
result = run_replay(HERE, work)
print(json.dumps({
    "reproduced": result.get("reproduced"),
    "generation": result.get("generation"),
    "committed_packs": result.get("committed_packs"),
    "verification_ok": result.get("verification_ok"),
    "workdir": os.path.abspath(work),
}, sort_keys=True))
sys.exit(0 if result.get("reproduced") else 1)
