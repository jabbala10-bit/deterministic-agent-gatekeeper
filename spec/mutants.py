"""Sabotage the core three ways and prove the suite notices each one.

Every mutant is applied to a temporary copy of the repository, never to the working tree, and the
copy is put first on PYTHONPATH so it shadows the editable install (checked before each run)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IGNORE = shutil.ignore_patterns(".venv", ".git", "__pycache__", ".pytest_cache", ".hypothesis", ".out")

MUTANTS: list[tuple[str, list[tuple[str, str, str]], list[str]]] = [
    ("engine reason order reaches the hashes", [
        ("src/gatekeeper/core/bundle.py",
         'reasons = tuple(sorted(self._ids.get(r, "unattributed") for r in result.diagnostics.reasons))',
         'reasons = tuple(self._ids.get(r, "unattributed") for r in result.diagnostics.reasons)'),
        ("src/gatekeeper/core/decide.py", "ordered = tuple(sorted(set(reasons)))", "ordered = tuple(dict.fromkeys(reasons))"),
    ], ["tests/test_cross_process.py", "tests/test_golden.py"]),
    ("gate fails open on evaluation errors", [
        ("src/gatekeeper/core/decide.py", "    if first.errors:", "    if False and first.errors:"),
        ("src/gatekeeper/core/bundle.py", 'return Evaluation(engine_decision == "Allow" and not errors,',
         'return Evaluation(engine_decision == "Allow",'),
    ], ["tests/test_golden.py", "tests/test_invariants.py"]),
    ("core reads the clock", [
        ("src/gatekeeper/core/decide.py", "import unicodedata\n", "import time\nimport unicodedata\n"),
    ], ["tests/test_invariants.py"]),
    ("budget is read outside the session lock", [
        ("src/gatekeeper/shell/gate.py",
         "        with session.transaction():\n            snapshot = session.state.snapshot(facts)\n",
         "        snapshot = session.state.snapshot(facts)\n        with session.transaction():\n"),
    ], ["tests/test_concurrency.py"]),
]


def main() -> int:
    survivors = 0
    for label, edits, tests in MUTANTS:
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "repo"
            shutil.copytree(ROOT, copy, ignore=IGNORE)
            for relative, old, new in edits:
                path = copy / relative
                text = path.read_text(encoding="utf-8")
                if text.count(old) != 1:
                    print(f"mutant '{label}' no longer applies to {relative}; update spec/mutants.py", file=sys.stderr)
                    return 2
                path.write_text(text.replace(old, new), encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(copy / "src"), str(copy)])}
            where = subprocess.run([sys.executable, "-c", "import gatekeeper; print(gatekeeper.__file__)"],
                                   cwd=copy, env=env, capture_output=True, text=True, check=True).stdout.strip()
            if not where.startswith(str(copy)):
                print(f"the mutated copy is not the code under test ({where})", file=sys.stderr)
                return 2
            result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", *tests],
                                    cwd=copy, env=env, capture_output=True, text=True)
            caught = result.returncode != 0
            survivors += not caught
            print(f"{'caught  ' if caught else 'SURVIVED'}  {label}")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
