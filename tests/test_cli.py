"""CLI integration: init/import/verify/report/list/find and repro/replay."""

import json
import os

from conftest import hx
from evstore import cli
from evstore import scenario as scen


def _pack(tmp_path):
    scn = {"name": "cli", "packs": [{
        "custodian": "alice", "pack_id": "P", "created": 1,
        "files": [{"name": "a.bin", "path": "C:\\Ev\\a.bin",
                   "aliases": ["c:/ev/A.BIN"], "content_hex": hx("cli-data")}],
        "custody": {"steps": ["acquire", "transfer"]}}]}
    packs, keys = scen.build_scenario(scn, str(tmp_path / "in"))
    return packs["P"], keys


def test_cli_roundtrip(tmp_path, capsys):
    pack_dir, keys = _pack(tmp_path)
    root = str(tmp_path / "store")
    tk = [f"alice={keys['alice']}"]

    assert cli.main(["init", "--root", root]) == 0
    assert cli.main(["import", "--root", root, *sum((["--trusted-key", k] for k in tk), []),
                     pack_dir]) == 0
    capsys.readouterr()

    assert cli.main(["verify", "--root", root, "--trusted-key", tk[0]]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True

    assert cli.main(["list", "--root", root]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert len(listed) == 1 and listed[0]["custodian"] == "alice"

    assert cli.main(["find", "--root", root, "c:/EV/a.bin"]) == 0
    hits = json.loads(capsys.readouterr().out)
    assert len(hits) == 1

    assert cli.main(["report", "--root", root, "--trusted-key", tk[0]]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["generation"] == 1

    assert cli.main(["recover", "--root", root]) == 0
    json.loads(capsys.readouterr().out)


def test_cli_verify_detects_tamper(tmp_path, capsys):
    pack_dir, keys = _pack(tmp_path)
    root = str(tmp_path / "store")
    cli.main(["init", "--root", root])
    cli.main(["import", "--root", root, "--trusted-key", f"alice={keys['alice']}",
              pack_dir])
    capsys.readouterr()

    # corrupt the committed blob on disk
    store_dir = tmp_path / "store"
    blob_dir = store_dir / "blobs"
    victim = next(blob_dir.iterdir())
    victim.write_bytes(b"tampered")

    rc = cli.main(["verify", "--root", root, "--trusted-key", f"alice={keys['alice']}"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1 and out["ok"] is False


def test_cli_repro_and_replay(tmp_path, capsys):
    pack_dir, keys = _pack(tmp_path)
    scn = {"name": "cli", "packs": [{
        "custodian": "alice", "pack_id": "P", "created": 1,
        "files": [{"name": "a.bin", "path": "C:\\Ev\\a.bin",
                   "aliases": [], "content_hex": hx("cli-data")}],
        "custody": {"steps": ["acquire"]}}]}
    scn_path = tmp_path / "scn.json"
    scn_path.write_text(json.dumps(scn), encoding="utf-8")
    exp_path = tmp_path / "exp.json"
    exp_path.write_text(json.dumps({"verification_ok": True, "committed_packs": 1}),
                        encoding="utf-8")
    bundle = str(tmp_path / "bundle")
    assert cli.main(["repro", "--scenario", str(scn_path), "--expect", str(exp_path),
                     "--out", bundle]) == 0
    capsys.readouterr()
    assert cli.main(["replay", "--bundle", bundle,
                     "--workdir", str(tmp_path / "replay")]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["reproduced"] is True
