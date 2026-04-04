from __future__ import annotations

import json
import pickle
import shutil
from pathlib import Path
from typing import Any


BUNDLE_MANIFEST = "bundle.json"


def load_bundle_manifest(bundle_dir: str | Path) -> dict[str, Any]:
    path = Path(bundle_dir) / BUNDLE_MANIFEST
    return json.loads(path.read_text(encoding="utf-8"))


def write_bundle_manifest(bundle_dir: str | Path, manifest: dict[str, Any]) -> Path:
    directory = Path(bundle_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / BUNDLE_MANIFEST
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return path


def load_pickle(path: str | Path) -> Any:
    with Path(path).open("rb") as handle:
        return pickle.load(handle)


def write_pickle(path: str | Path, payload: Any) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as handle:
        pickle.dump(payload, handle)
    return target


def copy_component_file(source: str | Path, output_dir: str | Path, filename: str | None = None) -> Path:
    source_path = Path(source)
    destination_dir = Path(output_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / (filename or source_path.name)
    shutil.copy2(source_path, destination)
    return destination


def copy_component_tree(source: str | Path, output_dir: str | Path, dirname: str | None = None) -> Path:
    source_path = Path(source)
    destination_dir = Path(output_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / (dirname or source_path.name)
    shutil.copytree(source_path, destination, dirs_exist_ok=True)
    return destination


def create_demo_bundle(bundle_dir: str | Path) -> Path:
    directory = Path(bundle_dir)
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {
        "bundleVersion": "demo-bundle-v1",
        "featureSchemaVersion": "v1",
        "pipeline": {
            "runtimeMode": "python_sidecar",
            "enforcementMode": "tighten",
            "sentinelVersion": "heuristic-sentinel-v1",
            "expertVersion": "heuristic-expert-v1",
            "stackerVersion": "heuristic-stacker-v1",
        },
        "components": {
            "sentinel": {"backend": "heuristic"},
            "expert": {"backend": "heuristic"},
            "stacker": {"backend": "heuristic"},
        },
        "heuristics": {
            "deny_keywords": ["exfiltrate", "credential", "token leak", "send the data"],
            "approval_keywords": [
                "approve",
                "authorize",
                "payment",
                "billing",
                "finalize",
                "connector",
                "oauth",
            ],
            "shadow_replay_keywords": [
                "ignore previous instructions",
                "continue the workflow",
                "override instructions",
                "secret",
                "silently",
            ],
            "sentinel_threshold": 0.55,
        },
    }
    write_bundle_manifest(directory, manifest)
    return directory
