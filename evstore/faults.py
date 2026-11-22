"""Named crash points shared by the importer and the store commit protocol.

A crash point can be triggered two ways via the environment:

* ``EVSTORE_CRASH_AT="after_index,after_audit"`` – raise :class:`InjectedCrash`
  at those points (soft crash: Python unwinds, finally blocks may run).
* ``EVSTORE_CRASH_HARD="1"`` – instead call ``os._exit(97)`` (hard kill: no
  unwinding, no flush, as close to power-loss as a test can get).

Soft vs hard matters: the hard kill is what proves the *on-disk* protocol (not
``finally`` cleanup) is what restores consistency.
"""

from __future__ import annotations

import os

# Protocol order.  Points inside ``stage_pack`` (no lock held) then inside the
# locked ``commit_staged`` sequence.
CRASHPOINTS = (
    "after_stage_begin",   # txn.json written, no payload copied yet
    "after_copy",          # payload streamed into staging, not yet verified
    "after_verify",        # verified, before any commit-side action
    "before_generation",   # blobs moved into blobs/, no generation written
    "after_generation",    # generation file written, index pointer not swapped
    "after_index",         # index pointer swapped (COMMITTED), audit not yet
    "after_audit",         # audit appended, staging not yet removed
)


class InjectedCrash(RuntimeError):
    def __init__(self, point: str):
        super().__init__(f"injected crash at {point}")
        self.point = point


def crashpoint(point: str) -> None:
    if point not in CRASHPOINTS:
        raise KeyError(f"unknown crash point {point!r}")
    targets = {p.strip() for p in os.environ.get("EVSTORE_CRASH_AT", "").split(",")
               if p.strip()}
    if point not in targets:
        return
    if os.environ.get("EVSTORE_CRASH_HARD") == "1":
        os._exit(97)
    raise InjectedCrash(point)
