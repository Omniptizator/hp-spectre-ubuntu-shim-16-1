#!/usr/bin/env python3
"""Local tests never call sudo, firmware writers, or the live ESP."""

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
preferred = Path("/tmp/opencode")
if preferred.is_dir():
    tempfile.tempdir = str(preferred)
suite = unittest.defaultTestLoader.discover(str(ROOT / "tests/unit"))
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(not result.wasSuccessful())
