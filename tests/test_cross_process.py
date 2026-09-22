"""Replayability across processes. Python randomises str hashing per process (PYTHONHASHSEED) and
the engine returns reasons in a per-process random order; neither may reach a decision hash."""

import os
import subprocess
import sys

import pytest

from spec.corpus import load_meta

SNIPPET = "from spec.corpus import corpus_digest; print(corpus_digest())"


@pytest.mark.parametrize("hash_seed", ["0", "1", "42", "random"])
def test_fresh_processes_rederive_the_identical_corpus(root, hash_seed):
    env = {**os.environ, "PYTHONHASHSEED": hash_seed}
    result = subprocess.run([sys.executable, "-c", SNIPPET], cwd=root, env=env,
                            capture_output=True, text=True, check=True)
    assert result.stdout.strip() == load_meta()["corpus_digest"]
