"""Subprocess entry point used by the crash tests and by ``import-worker``.

Protocol: JSON on argv, JSON on stdout. Reads a job description, performs one
importer operation against a store, and prints a small result object.  Used so
that tests can hard-kill (``TerminateProcess`` / ``SIGKILL``) a *real* separate
process at any crash point and then verify on-disk recovery.

Job schema::

    {"op": "stage"|"import", "root": "...", "packs": [...],
     "txn": "...", "keys": {"custodian": "b64"}}
"""

from __future__ import annotations

import json
import os
import sys

from .importer import Importer, snapshot_sources
from .store import Store


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    job = json.loads(argv[0]) if argv else json.loads(sys.stdin.read())
    keys = job.get("keys", {})
    store = Store(job["root"], trusted_keys=keys).open()
    imp = Importer(store)
    out = {"pid": os.getpid(), "op": job["op"]}
    if job["op"] == "stage":
        staged = [imp.stage_pack(d, job["txn"]) for d in job["packs"]]
        out["staged"] = [s.pack_uid for s in staged]
        out["source_changed"] = {s.pack_uid: s.source_changed for s in staged}
    elif job["op"] == "import":
        res = imp.import_packs(job["packs"], txn_id=job["txn"])
        out["commit"] = res.as_dict()
    elif job["op"] == "stage_then_commit":
        staged = [imp.stage_pack(d, job["txn"]) for d in job["packs"]]
        res = imp.commit(staged, job["txn"])
        out["commit"] = res.as_dict()
    elif job["op"] == "snapshot":
        out["snapshot"] = {d: snapshot_sources(d) for d in job["packs"]}
    else:
        raise SystemExit(f"unknown op {job['op']!r}")
    sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
