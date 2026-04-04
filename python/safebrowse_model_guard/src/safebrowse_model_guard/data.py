from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Iterator


DEFAULT_DATA_ROOT_ENV = "SAFEBROWSE_DATA_ROOT"


def default_data_root() -> Path:
    return Path.home() / ".safebrowse" / "private_data"


def load_manifest(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def resolve_data_root(explicit: str | Path | None = None) -> Path:
    if explicit is not None:
        return Path(explicit)
    value = os.environ.get(DEFAULT_DATA_ROOT_ENV)
    if value:
        return Path(value)
    return default_data_root()


def resolve_split_files(
    manifest: dict[str, Any],
    split: str,
    *,
    data_root: str | Path | None = None,
) -> list[Path]:
    storage = manifest.get("storage", {})
    dataset_subdir = storage.get("dataset_subdir", "prompt_injection_ml_dataset")
    root = resolve_data_root(data_root) / dataset_subdir
    files = storage.get("files", [])
    matches = [
        root / file_entry["relative_path"]
        for file_entry in files
        if file_entry.get("split") == split
    ]
    if not matches:
        raise FileNotFoundError(f"No files declared for split '{split}' in manifest.")
    return matches


def resolve_private_dataset_dir(manifest: dict[str, Any], *, data_root: str | Path | None = None) -> Path:
    storage = manifest.get("storage", {})
    dataset_subdir = storage.get("dataset_subdir", "prompt_injection_ml_dataset")
    return resolve_data_root(data_root) / dataset_subdir


def file_sha256(path: str | Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def collect_storage_entries(dataset_dir: str | Path) -> list[dict[str, Any]]:
    root = Path(dataset_dir)
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        split = "train"
        lower = path.as_posix().lower()
        if "/valid_" in lower or lower.startswith("valid_"):
            split = "valid"
        elif "/test_" in lower or lower.startswith("test_"):
            split = "test"
        elif "rendered_sample" in lower:
            split = "rendered_sample"
        entries.append(
            {
                "split": split,
                "relative_path": path.relative_to(root).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": file_sha256(path),
            }
        )
    return entries


def manifest_storage_summary(
    manifest: dict[str, Any], *, data_root: str | Path | None = None
) -> dict[str, Any]:
    dataset_dir = resolve_private_dataset_dir(manifest, data_root=data_root)
    files = manifest.get("storage", {}).get("files", [])
    missing = [
        entry["relative_path"]
        for entry in files
        if not (dataset_dir / entry["relative_path"]).is_file()
    ]
    return {
        "dataRoot": str(resolve_data_root(data_root)),
        "datasetDir": str(dataset_dir),
        "declaredFiles": len(files),
        "missingFiles": missing,
        "ready": len(files) > 0 and not missing,
    }


def iter_jsonl(paths: Iterable[Path]) -> Iterator[dict[str, Any]]:
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                yield json.loads(line)


def load_records(
    manifest_path: str | Path,
    split: str,
    *,
    limit: int | None = None,
    data_root: str | Path | None = None,
) -> list[dict[str, Any]]:
    manifest = load_manifest(manifest_path)
    paths = resolve_split_files(manifest, split, data_root=data_root)
    rows: list[dict[str, Any]] = []
    for row in iter_jsonl(paths):
        rows.append(row)
        if limit is not None and len(rows) >= limit:
            break
    return rows


def iter_records(
    manifest_path: str | Path,
    split: str,
    *,
    data_root: str | Path | None = None,
) -> Iterator[dict[str, Any]]:
    manifest = load_manifest(manifest_path)
    yield from iter_jsonl(resolve_split_files(manifest, split, data_root=data_root))
