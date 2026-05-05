from __future__ import annotations

import sys
import unittest
from pathlib import Path


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo_root / "python" / "safebrowse_client" / "src"))
    sys.path.insert(0, str(repo_root / "python" / "safebrowse_model_guard" / "src"))
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite()
    suite.addTests(
        loader.discover(str(repo_root / "python" / "safebrowse_client" / "tests"), pattern="test_*.py")
    )
    suite.addTests(
        loader.discover(
            str(repo_root / "python" / "safebrowse_model_guard" / "tests"),
            pattern="test_*.py",
        )
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
