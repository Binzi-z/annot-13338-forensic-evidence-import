import os

from conftest import build_store, hx
from evstore.importer import Importer


def _scenario():
    return {
        "name": "smoke",
        "packs": [
            {
                "custodian": "alice",
                "pack_id": "P1",
                "created": 1700000000,
                "files": [
                    {"name": "a.txt", "path": "C:\\Evidence\\A.txt",
                     "aliases": ["c:/evidence/a.TXT"], "content_hex": hx("hello")},
                ],
                "custody": {"steps": ["acquire", "transfer", "verify"]},
            }
        ],
    }


def test_import_and_read(tmp_path):
    scn = _scenario()
    store, dirs, keys = build_store(tmp_path, scn)
    res = Importer(store).import_packs(dirs)
    assert res.added
    uid = res.added[0]
    pack = store.get_pack(uid)
    assert pack["custodian"] == "alice"
    data = store.get_file_bytes(uid, "a.txt")
    assert data == b"hello"
    assert store.find_by_path("C:/EVIDENCE/a.txt")[0]["pack_uid"] == uid


def test_not_committed_invisible(tmp_path):
    from evstore.errors import UncommittedError
    import pytest

    scn = _scenario()
    store, dirs, keys = build_store(tmp_path, scn)
    imp = Importer(store)
    staged = imp.stage_pack(dirs[0], txn_id="t1")
    # staged but not committed
    with pytest.raises(UncommittedError):
        store.get_pack(staged.pack_uid)
    assert store.find_by_path("C:\\Evidence\\A.txt") == []
