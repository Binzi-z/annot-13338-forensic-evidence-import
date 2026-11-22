import os
import subprocess
import sys
import textwrap

from evstore.fsutil import pid_alive


def test_pid_alive_sibling(tmp_path):
    # child that prints its pid and waits on stdin
    code = textwrap.dedent("""
        import sys
        sys.stdout.write(str(__import__('os').getpid()) + "\\n")
        sys.stdout.flush()
        sys.stdin.read()
    """)
    p = subprocess.Popen([sys.executable, "-c", code],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    pid = int(p.stdout.readline().strip())
    try:
        assert pid_alive(pid), f"sibling pid {pid} should be alive"
    finally:
        p.stdin.close()
        p.wait(timeout=10)
    assert not pid_alive(pid)
