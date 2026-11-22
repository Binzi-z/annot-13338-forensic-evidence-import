Reproduction bundle: demo-conflict
note: two custodians disagree over an aliased path

Replay with:
    python replay.py <workdir>

It rebuilds byte-identical inputs from scenario.json, runs the
recorded import/recover/verify/report actions, checks the recorded
expectation, and prints a JSON result. Exit code 0 == reproduced.
