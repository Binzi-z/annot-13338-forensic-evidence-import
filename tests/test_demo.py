"""Run the top-level demo (`example.py`) and assert it completes cleanly.

Keeps the demo from silently rotting and exercises the full public flow:
parallel import -> report -> alias lookup -> independent verify -> repro replay.
"""

import os

import example


def test_demo_runs(tmp_path):
    assert example.main(work_dir=str(tmp_path / "demo")) == 0
