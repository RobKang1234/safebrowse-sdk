from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo_root / "python" / "safebrowse_model_guard" / "src"))
    from safebrowse_model_guard.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
