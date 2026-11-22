"""Backwards-compatible shim: the demo now lives in :mod:`example`.

Kept only so `python _probe.py` still works for anyone who used the old name.
"""

from example import demo_scenario, main

__all__ = ["main", "demo_scenario"]

if __name__ == "__main__":
    raise SystemExit(main())
