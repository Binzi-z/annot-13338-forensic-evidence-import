import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from evstore.scenario import build_scenario
from evstore.store import Store


def hx(s: str) -> str:
    return s.encode("utf-8").hex()


@pytest.fixture
def tmp_work(tmp_path):
    return str(tmp_path)


def build_store(tmp_path, scenario):
    """Materialise scenario packs into a temp area and return (store, dirs, keys)."""
    inputs = str(tmp_path / "inputs")
    packs, keys = build_scenario(scenario, inputs)
    store = Store(str(tmp_path / "store"), trusted_keys=keys).init()
    dirs = [packs[p["pack_id"]] for p in scenario["packs"]]
    return store, dirs, keys
