"""Minimal, replayable reproduction bundles.

A bundle is self-contained, deterministic data plus a standalone ``replay.py``:

    <bundle>/
      scenario.json   # exact inputs (payload bytes as hex, custody plan, keys)
      bundle.json     # actions, fault injection, expected outcome, repo root
      replay.py       # `python replay.py <workdir>` -> prints JSON, writes files
      README.txt

Because the scenario DSL is the single source of truth, replay reconstructs
byte-identical packs (deterministic Ed25519 seeds and payload hex), runs the
same store/import/verify code path, and checks the recorded expectation.  This
is what makes a reported inconsistency reproducible on a fresh machine.
"""

from __future__ import annotations

import json
import os

from .canonical import canonical_text
from .fsutil import atomic_write_bytes
from .scenario import build_scenario

REPRO_SCHEMA = "evstore/repro/1"


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _execute_actions(store, pack_dirs: list[str], keys: dict[str, str],
                     actions: list[str], crash_at: str | None,
                     work_root: str) -> dict:
    """Run *actions* in order on an initialised *store*. Reused by replay."""
    from .faults import InjectedCrash
    from .importer import Importer
    from .verifier import verify_store

    old = os.environ.get("EVSTORE_CRASH_AT")
    result: dict = {"actions": []}
    counter = 0
    try:
        for action in actions:
            step: dict = {"action": action}
            if action == "import":
                txn = f"repro-{counter}"
                counter += 1
                os.environ["EVSTORE_CRASH_AT"] = crash_at or ""
                imp = Importer(store)
                try:
                    staged = [imp.stage_pack(d, txn) for d in pack_dirs]
                    cr = imp.commit(staged, txn)
                    step["commit"] = cr.as_dict()
                except InjectedCrash as e:
                    step["crashed"] = e.point
                finally:
                    os.environ["EVSTORE_CRASH_AT"] = old or ""
            elif action == "recover":
                step["recover"] = store.recover().as_dict()
            elif action == "verify":
                v = verify_store(store.root, keys)
                step["verification"] = v.as_dict()
                result["verification_ok"] = v.ok
            elif action == "report":
                rep = store.report()
                step["report"] = rep
                result["report"] = rep
            else:
                raise ValueError(f"unknown action {action!r}")
            result["actions"].append(step)
    finally:
        os.environ["EVSTORE_CRASH_AT"] = old or ""
    gen = store.current()
    result["committed_packs"] = len(gen["packs"])
    result["generation"] = gen["generation"]
    return result


def generate(
    scenario: dict,
    out_dir: str,
    actions: list[str],
    expected: dict,
    crash_at: str | None = None,
    note: str = "",
) -> str:
    """Write a repro bundle to *out_dir*; return path to ``replay.py``."""
    os.makedirs(out_dir, exist_ok=True)
    atomic_write_bytes(
        os.path.join(out_dir, "scenario.json"),
        (canonical_text(scenario) + "\n").encode("utf-8"),
    )
    # derive deterministic public keys for the verifier
    tmp = os.path.join(out_dir, "_keys")
    _packs, keys = build_scenario(scenario, tmp)
    bundle = {
        "schema": REPRO_SCHEMA,
        "name": scenario.get("name", "repro"),
        "note": note,
        "evstore_root": _repo_root(),
        "actions": actions,
        "crash_at": crash_at,
        "expected": expected,
        "keys": keys,
    }
    atomic_write_bytes(
        os.path.join(out_dir, "bundle.json"),
        (canonical_text(bundle) + "\n").encode("utf-8"),
    )
    atomic_write_bytes(
        os.path.join(out_dir, "replay.py"),
        _REPLAY_TEMPLATE.encode("utf-8"),
    )
    atomic_write_bytes(
        os.path.join(out_dir, "README.txt"),
        (
            f"Reproduction bundle: {bundle['name']}\n"
            f"note: {note}\n\n"
            "Replay with:\n"
            "    python replay.py <workdir>\n\n"
            "It rebuilds byte-identical inputs from scenario.json, runs the\n"
            "recorded import/recover/verify/report actions, checks the recorded\n"
            "expectation, and prints a JSON result. Exit code 0 == reproduced.\n"
        ).encode("utf-8"),
    )
    # clean the key-derivation scratch dir
    import shutil

    shutil.rmtree(tmp, ignore_errors=True)
    return os.path.join(out_dir, "replay.py")


def run_replay(bundle_dir: str, work_root: str) -> dict:
    """In-process replay used by ``replay.py`` and by the test-suite."""
    from .store import Store

    with open(os.path.join(bundle_dir, "bundle.json"), "rb") as fh:
        bundle = json.loads(fh.read().decode("utf-8"))
    with open(os.path.join(bundle_dir, "scenario.json"), "rb") as fh:
        scenario = json.loads(fh.read().decode("utf-8"))

    os.makedirs(work_root, exist_ok=True)
    store_root = os.path.join(work_root, "store")
    inputs = os.path.join(work_root, "inputs")
    packs, keys = build_scenario(scenario, inputs)
    pack_dirs = [packs[p["pack_id"]] for p in scenario["packs"]]
    store = Store(store_root, trusted_keys=keys).init()
    result = _execute_actions(
        store, pack_dirs, keys, bundle["actions"], bundle.get("crash_at"), work_root
    )
    result["expected"] = bundle["expected"]
    result["reproduced"] = _matches(result, bundle["expected"])
    with open(os.path.join(work_root, "result.json"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps(result, indent=2, sort_keys=True))
    return result


def _matches(result: dict, expected: dict) -> bool:
    if "verification_ok" in expected:
        if bool(result.get("verification_ok")) != bool(expected["verification_ok"]):
            return False
    if "committed_packs" in expected:
        if result.get("committed_packs") != expected["committed_packs"]:
            return False
    rep = result.get("report") or {}
    if "conflicts_min" in expected:
        if len(rep.get("conflicts", [])) < expected["conflicts_min"]:
            return False
    if "revoked_min" in expected:
        if len(rep.get("revoked", [])) < expected["revoked_min"]:
            return False
    if "custody_defects_min" in expected:
        if len(rep.get("missing_custody_segments", [])) < expected["custody_defects_min"]:
            return False
    if "name_reuse_min" in expected:
        if len(rep.get("name_reuse", [])) < expected["name_reuse_min"]:
            return False
    return True


def minimize(
    scenario: dict,
    expected: dict,
    actions: list[str],
    work_factory,
    crash_at: str | None = None,
    max_rounds: int = 20,
) -> dict:
    """Greedily shrink a scenario while it still reproduces *expected*.

    *work_factory* returns a fresh temp dir per evaluation.  Only whole packs
    and trailing custody steps are dropped, so custody defects expressed via
    ``skip_seqs``/``revoke`` survive minimisation.
    """
    best = json.loads(json.dumps(scenario))

    def still_fails(scn: dict) -> bool:
        work = work_factory()
        try:
            packs, keys = build_scenario(scn, os.path.join(work, "in"))
            store = __import__("evstore.store", fromlist=["Store"]).Store(
                os.path.join(work, "store"), trusted_keys=keys
            ).init()
            pack_dirs = [packs[p["pack_id"]] for p in scn["packs"]]
            res = _execute_actions(store, pack_dirs, keys, actions, crash_at, work)
            return _matches(res, expected)
        except Exception:
            return False

    if not still_fails(best):
        return best
    for _ in range(max_rounds):
        changed = False
        # try dropping whole packs (keep >=1)
        if len(best["packs"]) > 1:
            for i in range(len(best["packs"])):
                cand = json.loads(json.dumps(best))
                cand["packs"].pop(i)
                if still_fails(cand):
                    best = cand
                    changed = True
                    break
        if changed:
            continue
        # try trimming payload count within a pack
        for pi, pack in enumerate(best["packs"]):
            if len(pack.get("files", [])) > 1:
                cand = json.loads(json.dumps(best))
                cand["packs"][pi]["files"].pop()
                if still_fails(cand):
                    best = cand
                    changed = True
                    break
        if not changed:
            break
    return best


_REPLAY_TEMPLATE = '''#!/usr/bin/env python3
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
'''
