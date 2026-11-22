import json
import os
import subprocess
import sys
import textwrap

from conftest import build_store, hx


def test_lock_serializes_processes(tmp_path):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    lock = str(tmp_path / "LOCK")
    log = str(tmp_path / "log.txt")
    code = textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, r"{root}")
        from evstore.fsutil import FileLock
        tag = sys.argv[1]
        with FileLock(r"{lock}", timeout=30):
            with open(r"{log}", "a") as f:
                f.write("enter " + tag + "\\n"); f.flush()
            time.sleep(0.3)
            with open(r"{log}", "a") as f:
                f.write("exit " + tag + "\\n"); f.flush()
    """)
    procs = [subprocess.Popen([sys.executable, "-c", code, t]) for t in ("A", "B")]
    for p in procs:
        p.communicate(timeout=30)
    lines = [ln for ln in open(log).read().splitlines() if ln.strip()]
    # strictly nested: enter X, exit X, enter Y, exit Y
    assert lines[0].startswith("enter ") and lines[1].startswith("exit ")
    assert lines[0].split()[1] == lines[1].split()[1]
    assert lines[2].startswith("enter ") and lines[3].startswith("exit ")
    assert lines[2].split()[1] == lines[3].split()[1]
    assert lines[0].split()[1] != lines[2].split()[1]
