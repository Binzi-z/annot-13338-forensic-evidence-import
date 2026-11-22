import os
import subprocess
import sys
import textwrap
import time

import pytest


def test_subprocess_kill_mechanism(tmp_path):
    out = tmp_path / "out.txt"
    code = textwrap.dedent(f"""
        import time, os, sys
        with open(r"{out}", "w") as f:
            f.write("started")
            f.flush()
        time.sleep(30)
    """)
    p = subprocess.Popen([sys.executable, "-c", code])
    # wait for it to start
    for _ in range(200):
        if out.exists() and out.read_text() == "started":
            break
        time.sleep(0.01)
    assert out.exists()
    p.kill()
    rc = p.wait(timeout=10)
    assert rc != 0  # killed
    assert p.poll() is not None
