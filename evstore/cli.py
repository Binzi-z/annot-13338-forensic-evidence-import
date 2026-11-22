"""Command-line entry point: python -m evstore <command> ..."""

from __future__ import annotations

import argparse
import json
import os
import sys

from .importer import Importer
from .repro import generate as repro_generate
from .repro import run_replay
from .scenario import build_scenario
from .store import Store
from .verifier import verify_store


def _keys_from_args(pairs: list[str]) -> dict[str, str]:
    out = {}
    for p in pairs or []:
        cust, _, b64 = p.partition("=")
        out[cust] = b64
    return out


def cmd_init(a) -> int:
    Store(a.root).init()
    print(json.dumps({"root": os.path.abspath(a.root), "generation": 0}))
    return 0


def cmd_import(a) -> int:
    keys = _keys_from_args(a.trusted_key)
    store = Store(a.root, trusted_keys=keys).open()
    res = Importer(store).import_packs(a.packs, timeout=a.lock_timeout)
    print(json.dumps(res.as_dict(), indent=2, sort_keys=True))
    return 0


def cmd_recover(a) -> int:
    store = Store(a.root, trusted_keys=_keys_from_args(a.trusted_key)).open(recover=False)
    print(json.dumps(store.recover().as_dict(), indent=2, sort_keys=True))
    return 0


def cmd_verify(a) -> int:
    rep = verify_store(a.root, _keys_from_args(a.trusted_key))
    print(json.dumps(rep.as_dict(), indent=2, sort_keys=True))
    return 0 if rep.ok else 1


def cmd_report(a) -> int:
    store = Store(a.root, trusted_keys=_keys_from_args(a.trusted_key)).open()
    print(json.dumps(store.report(), indent=2, sort_keys=True))
    return 0


def cmd_list(a) -> int:
    store = Store(a.root, trusted_keys=_keys_from_args(a.trusted_key)).open()
    print(json.dumps(store.list_packs(), indent=2, sort_keys=True))
    return 0


def cmd_find(a) -> int:
    store = Store(a.root, trusted_keys=_keys_from_args(a.trusted_key)).open()
    print(json.dumps(store.find_by_path(a.path), indent=2, sort_keys=True))
    return 0


def cmd_repro(a) -> int:
    with open(a.scenario, "rb") as fh:
        scenario = json.loads(fh.read().decode("utf-8"))
    with open(a.expect, "rb") as fh:
        expected = json.loads(fh.read().decode("utf-8"))
    actions = a.action or ["import", "verify", "report"]
    path = repro_generate(scenario, a.out, actions, expected, crash_at=a.crash_at,
                          note=a.note)
    print(json.dumps({"replay": path}))
    return 0


def cmd_replay(a) -> int:
    res = run_replay(a.bundle, a.workdir)
    print(json.dumps({
        "reproduced": res.get("reproduced"),
        "generation": res.get("generation"),
        "committed_packs": res.get("committed_packs"),
        "verification_ok": res.get("verification_ok"),
    }, sort_keys=True))
    return 0 if res.get("reproduced") else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="evstore", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("--root", required=True)
        sp.add_argument("--trusted-key", action="append", default=[],
                        metavar="CUSTODIAN=B64")

    sp = sub.add_parser("init"); add_common(sp); sp.set_defaults(fn=cmd_init)
    sp = sub.add_parser("import"); add_common(sp)
    sp.add_argument("packs", nargs="+")
    sp.add_argument("--lock-timeout", type=float, default=30.0)
    sp.set_defaults(fn=cmd_import)
    sp = sub.add_parser("recover"); add_common(sp); sp.set_defaults(fn=cmd_recover)
    sp = sub.add_parser("verify"); add_common(sp); sp.set_defaults(fn=cmd_verify)
    sp = sub.add_parser("report"); add_common(sp); sp.set_defaults(fn=cmd_report)
    sp = sub.add_parser("list"); add_common(sp); sp.set_defaults(fn=cmd_list)
    sp = sub.add_parser("find"); add_common(sp)
    sp.add_argument("path"); sp.set_defaults(fn=cmd_find)
    sp = sub.add_parser("repro")
    sp.add_argument("--scenario", required=True)
    sp.add_argument("--expect", required=True)
    sp.add_argument("--out", required=True)
    sp.add_argument("--action", action="append")
    sp.add_argument("--crash-at")
    sp.add_argument("--note", default="")
    sp.set_defaults(fn=cmd_repro)
    sp = sub.add_parser("replay")
    sp.add_argument("--bundle", required=True)
    sp.add_argument("--workdir", required=True)
    sp.set_defaults(fn=cmd_replay)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
