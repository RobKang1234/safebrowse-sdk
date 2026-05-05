from __future__ import annotations

import gzip
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import pickle
import random
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Iterable, Iterator

from .bundle import (
    copy_component_file,
    copy_component_tree,
    load_pickle,
    write_bundle_manifest,
    write_pickle,
)
from .data import (
    load_manifest,
    manifest_record_count,
    manifest_storage_summary,
    resolve_private_dataset_dir,
    resolve_split_files,
)
from .features import (
    LABEL_TO_ID,
    RECIPE_CATEGORICAL_FIELDS,
    RECIPE_REASON_LABELS,
    chunk_text,
    encode_recipe_categorical,
    encode_recipe_numeric,
    encode_recipe_reason_targets,
    example_from_dataset_row,
    rank_chunks,
    recipe_categorical_values,
    softmax,
    structured_feature_dict,
)
from .recipe_model import (
    RecipeExpertConfig,
    build_recipe_expert_encoder,
    load_recipe_expert_artifact,
    save_recipe_expert_artifact,
    HierarchicalActionGuardModel,
)


_TRANSFORMER_ARTIFACT_CACHE: dict[str, dict[str, Any]] = {}
_DEFAULT_RANDOM_SEED = 7
_DEFAULT_SENTINEL_CHECKPOINT_BATCHES = 16
_DEFAULT_LATEST_CHECKPOINT_STEPS = 50
_DEFAULT_MILESTONE_CHECKPOINT_STEPS = 1000
_BOOTSTRAP_CHECKPOINT_STEPS = {25, 100}
_DEFAULT_RUN_LOG_MAX_BYTES = 512 * 1024
_DEFAULT_EVENT_LOG_MAX_BYTES = 512 * 1024
_DEFAULT_LOG_BACKUP_COUNT = 4
_DEFAULT_REPLAY_CHECKPOINT_ITEMS = 500
_DEFAULT_REPLAY_MILESTONE_ITEMS = 5000
_DEFAULT_STACKER_CHECKPOINT_ROWS = 250
_DEFAULT_STACKER_CHUNK_ROWS = 2000
_DEFAULT_STACKER_MILESTONE_ROWS = 10000


@dataclass
class IndexedRecord:
    index: int
    relative_path: str
    offset: int
    example_id: str
    label: str
    attack_family: str


@dataclass
class RecipeStage:
    name: str
    max_length: int
    epochs: float
    train_subset: int
    sampling: str
    batch_size: int
    gradient_accumulation_steps: int


@dataclass
class ExpertStagePlan:
    stage: RecipeStage
    plan_path: Path
    selected_indices: list[int]
    hard_negative_indices: list[int]


class RetentionWorker:
    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1)

    def submit(self, fn: Any, *args: Any) -> None:
        self._executor.submit(fn, *args)

    def close(self) -> None:
        self._executor.shutdown(wait=True)


class ExpertCheckpointManager:
    def __init__(
        self,
        *,
        stage_dir: Path,
        tokenizer: Any,
        config: RecipeExpertConfig,
        metadata_vocab: dict[str, dict[str, int]],
        latest_steps: int,
        milestone_steps: int,
    ) -> None:
        self.stage_dir = stage_dir
        self.tokenizer = tokenizer
        self.config = config
        self.metadata_vocab = metadata_vocab
        self.latest_steps = max(1, latest_steps)
        self.milestone_steps = max(self.latest_steps, milestone_steps)
        self.active_dir = stage_dir / "active"
        self.latest_dir = self.active_dir / "latest"
        self.milestone_dir = self.active_dir / "milestones"
        self.release_dir = stage_dir / "release"
        self.worker = RetentionWorker()

    def _write_rng_state(self, target: Path, *, torch_module: Any) -> None:
        payload = {
            "python": random.getstate(),
            "torch": torch_module.get_rng_state(),
            "cuda": torch_module.cuda.get_rng_state_all() if torch_module.cuda.is_available() else [],
        }
        torch_module.save(payload, target / "rng.pt")

    def _write_checkpoint(
        self,
        target: Path,
        *,
        model: Any,
        torch_module: Any,
        state_payload: dict[str, Any],
        optimizer: Any | None,
        scaler: Any | None,
        include_optimizer: bool,
    ) -> str:
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True, exist_ok=True)
        save_recipe_expert_artifact(
            target / "expert",
            model=model,
            tokenizer=self.tokenizer,
            config=self.config,
            metadata_vocab=self.metadata_vocab,
            include_tokenizer=False,
        )
        if include_optimizer and optimizer is not None:
            torch_module.save(optimizer.state_dict(), target / "optimizer.pt")
        if include_optimizer and scaler is not None and hasattr(scaler, "state_dict"):
            torch_module.save(scaler.state_dict(), target / "scaler.pt")
        self._write_rng_state(target, torch_module=torch_module)
        _write_json(target / "state.json", state_payload)
        digest = _hash_tree(target)
        _write_json(target / "manifest.json", {"hash": digest, "state": state_payload})
        return digest

    def save_resume_checkpoint(
        self,
        *,
        model: Any,
        torch_module: Any,
        state_payload: dict[str, Any],
        optimizer: Any | None,
        scaler: Any | None,
    ) -> str:
        tmp_path = self.active_dir / f".latest_tmp_{int(time.time() * 1000)}"
        digest = self._write_checkpoint(
            tmp_path,
            model=model,
            torch_module=torch_module,
            state_payload=state_payload,
            optimizer=optimizer,
            scaler=scaler,
            include_optimizer=True,
        )
        self.active_dir.mkdir(parents=True, exist_ok=True)
        _publish_directory(tmp_path, self.latest_dir)
        self.worker.submit(self._prune_active)
        return digest

    def save_milestone(
        self,
        *,
        model: Any,
        torch_module: Any,
        state_payload: dict[str, Any],
    ) -> str:
        milestone_path = self.milestone_dir / f"step-{int(state_payload['optimizerStep']):06d}"
        self.milestone_dir.mkdir(parents=True, exist_ok=True)
        return self._write_checkpoint(
            milestone_path,
            model=model,
            torch_module=torch_module,
            state_payload=state_payload,
            optimizer=None,
            scaler=None,
            include_optimizer=False,
        )

    def finalize_release(self, *, model: Any, tokenizer: Any) -> Path:
        target = self.release_dir / "expert"
        if target.exists():
            shutil.rmtree(target)
        save_recipe_expert_artifact(
            target,
            model=model,
            tokenizer=tokenizer,
            config=self.config,
            metadata_vocab=self.metadata_vocab,
            include_tokenizer=True,
        )
        return target

    def close(self) -> None:
        self.worker.close()

    def _prune_active(self) -> None:
        self.active_dir.mkdir(parents=True, exist_ok=True)
        for child in self.active_dir.iterdir():
            if child.name in {"latest", "milestones"}:
                continue
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)


class StateCheckpointManager:
    def __init__(
        self,
        *,
        stage_dir: Path,
        preserve_names: set[str] | None = None,
    ) -> None:
        self.stage_dir = stage_dir
        self.active_dir = stage_dir / "active"
        self.latest_dir = self.active_dir / "latest"
        self.milestone_dir = self.active_dir / "milestones"
        self.preserve_names = {"latest", "milestones", *(preserve_names or set())}
        self.worker = RetentionWorker()

    def _write_checkpoint(
        self,
        target: Path,
        *,
        state_payload: dict[str, Any],
        json_payloads: dict[str, Any] | None = None,
        pickle_payloads: dict[str, Any] | None = None,
    ) -> str:
        if target.exists():
            _remove_tree_with_retries(target)
        target.mkdir(parents=True, exist_ok=True)
        _write_json(target / "state.json", state_payload)
        for name, payload in (json_payloads or {}).items():
            _write_json(target / name, payload)
        for name, payload in (pickle_payloads or {}).items():
            _write_pickle_gz(target / name, payload)
        digest = _hash_tree(target)
        _write_json(target / "manifest.json", {"hash": digest, "state": state_payload})
        return digest

    def save_latest(
        self,
        *,
        state_payload: dict[str, Any],
        json_payloads: dict[str, Any] | None = None,
        pickle_payloads: dict[str, Any] | None = None,
    ) -> str:
        tmp_path = self.active_dir / f".latest_tmp_{int(time.time() * 1000)}"
        digest = self._write_checkpoint(
            tmp_path,
            state_payload=state_payload,
            json_payloads=json_payloads,
            pickle_payloads=pickle_payloads,
        )
        self.active_dir.mkdir(parents=True, exist_ok=True)
        _publish_directory(tmp_path, self.latest_dir)
        self.worker.submit(self._prune_active)
        return digest

    def save_milestone(
        self,
        *,
        step_key: int,
        state_payload: dict[str, Any],
        json_payloads: dict[str, Any] | None = None,
        pickle_payloads: dict[str, Any] | None = None,
    ) -> str:
        milestone_path = self.milestone_dir / f"step-{step_key:07d}"
        self.milestone_dir.mkdir(parents=True, exist_ok=True)
        return self._write_checkpoint(
            milestone_path,
            state_payload=state_payload,
            json_payloads=json_payloads,
            pickle_payloads=pickle_payloads,
        )

    def cleanup_completed(self, *, keep_milestones: bool = False) -> None:
        if not self.active_dir.exists():
            return
        for child in list(self.active_dir.iterdir()):
            if keep_milestones and child.name == "milestones":
                continue
            if child.is_dir():
                _remove_tree_with_retries(child, retries=3)
            else:
                child.unlink(missing_ok=True)
        if not keep_milestones and self.active_dir.exists():
            try:
                self.active_dir.rmdir()
            except OSError:
                pass

    def close(self) -> None:
        self.worker.close()

    def _prune_active(self) -> None:
        self.active_dir.mkdir(parents=True, exist_ok=True)
        for child in self.active_dir.iterdir():
            if child.name in self.preserve_names:
                continue
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)


def _require_training_dependencies() -> dict[str, Any]:
    try:
        from scipy.sparse import hstack, vstack  # type: ignore
        from sklearn.feature_extraction import DictVectorizer  # type: ignore
        from sklearn.feature_extraction.text import HashingVectorizer, TfidfVectorizer  # type: ignore
        from sklearn.linear_model import LogisticRegression, SGDClassifier  # type: ignore
        from sklearn.metrics import f1_score, log_loss, precision_recall_fscore_support, recall_score  # type: ignore
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError(
            "Training requires the optional 'train' dependencies. Install "
            "'python/safebrowse_model_guard[train]' before running train/evaluate commands."
        ) from exc

    try:
        from catboost import CatBoostClassifier  # type: ignore
    except ModuleNotFoundError:
        CatBoostClassifier = None

    try:
        import xgboost as xgb  # type: ignore
        from xgboost import XGBClassifier  # type: ignore
    except ModuleNotFoundError:
        xgb = None
        XGBClassifier = None

    return {
        "hstack": hstack,
        "vstack": vstack,
        "DictVectorizer": DictVectorizer,
        "HashingVectorizer": HashingVectorizer,
        "TfidfVectorizer": TfidfVectorizer,
        "LogisticRegression": LogisticRegression,
        "SGDClassifier": SGDClassifier,
        "CatBoostClassifier": CatBoostClassifier,
        "XGBClassifier": XGBClassifier,
        "xgboost": xgb,
        "f1_score": f1_score,
        "log_loss": log_loss,
        "precision_recall_fscore_support": precision_recall_fscore_support,
        "recall_score": recall_score,
    }


def _require_transformer_dependencies() -> dict[str, Any]:
    try:
        import torch
        from transformers import AutoTokenizer
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError(
            "Transformer expert training requires torch and transformers. "
            "Install the optional train dependencies before running ModernBERT training."
        ) from exc
    GradScaler = getattr(getattr(torch, "amp", None), "GradScaler", None)
    if GradScaler is None:  # pragma: no cover
        from torch.cuda.amp import GradScaler  # type: ignore
    return {"torch": torch, "GradScaler": GradScaler, "AutoTokenizer": AutoTokenizer}


def _rotate_with_backups(path: Path, *, backup_count: int) -> None:
    if backup_count <= 0:
        if path.exists():
            path.unlink()
        return
    oldest = path.with_name(f"{path.name}.{backup_count}")
    if oldest.exists():
        oldest.unlink()
    for index in range(backup_count - 1, 0, -1):
        source = path.with_name(f"{path.name}.{index}")
        target = path.with_name(f"{path.name}.{index + 1}")
        if source.exists():
            source.replace(target)
    if path.exists():
        path.replace(path.with_name(f"{path.name}.1"))


def _remove_tree_with_retries(path: str | Path, *, retries: int = 5, delay_seconds: float = 0.2) -> None:
    target = Path(path)
    if not target.exists():
        return
    last_error: BaseException | None = None
    for attempt in range(retries):
        try:
            shutil.rmtree(target)
            return
        except FileNotFoundError:
            return
        except PermissionError as exc:
            last_error = exc
            time.sleep(delay_seconds * (attempt + 1))
    if last_error is not None:
        raise last_error


def _publish_directory(source: str | Path, target: str | Path, *, retries: int = 5, delay_seconds: float = 0.2) -> None:
    source_path = Path(source)
    target_path = Path(target)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    last_error: BaseException | None = None
    for attempt in range(retries):
        try:
            if target_path.exists():
                _remove_tree_with_retries(target_path, retries=1, delay_seconds=delay_seconds)
            source_path.rename(target_path)
            return
        except FileNotFoundError:
            if target_path.exists():
                return
            raise
        except (PermissionError, OSError) as exc:
            last_error = exc
            time.sleep(delay_seconds * (attempt + 1))
    _remove_tree_with_retries(target_path, retries=retries, delay_seconds=delay_seconds)
    for attempt in range(retries):
        try:
            shutil.copytree(source_path, target_path)
            _remove_tree_with_retries(source_path, retries=retries, delay_seconds=delay_seconds)
            return
        except FileExistsError:
            _remove_tree_with_retries(target_path, retries=1, delay_seconds=delay_seconds)
        except PermissionError as exc:
            last_error = exc
            time.sleep(delay_seconds * (attempt + 1))
    if last_error is not None:
        raise last_error


def _append_text_with_retention(
    path: str | Path,
    text: str,
    *,
    max_bytes: int,
    backup_count: int,
) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    encoded = text.encode("utf-8")
    if target.exists() and target.stat().st_size + len(encoded) > max_bytes:
        _rotate_with_backups(target, backup_count=backup_count)
    with target.open("ab") as handle:
        handle.write(encoded)
    return target


def _maybe_report(message: str, *, run_log_path: str | Path | None = None) -> None:
    line = message.rstrip("\n") + "\n"
    if run_log_path is not None:
        _append_text_with_retention(
            run_log_path,
            line,
            max_bytes=_DEFAULT_RUN_LOG_MAX_BYTES,
            backup_count=_DEFAULT_LOG_BACKUP_COUNT,
        )
    if sys.stdout is not None and sys.stdout.isatty():
        print(message, flush=True)


def _mlflow_client() -> Any | None:
    try:
        import mlflow
    except ModuleNotFoundError:
        return None
    if mlflow.active_run() is None and not os.environ.get("MLFLOW_RUN_ID"):
        return None
    return mlflow


def _mlflow_log_metrics(payload: dict[str, Any], *, step: int | None = None) -> None:
    mlflow = _mlflow_client()
    if mlflow is None:
        return
    metrics: dict[str, float] = {}
    for key, value in payload.items():
        if value is None:
            continue
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            continue
        if math.isfinite(numeric):
            metrics[key] = numeric
    if not metrics:
        return
    if step is None:
        mlflow.log_metrics(metrics)
        return
    for key, value in metrics.items():
        mlflow.log_metric(key, value, step=step)


def _mlflow_set_tags(payload: dict[str, Any]) -> None:
    mlflow = _mlflow_client()
    if mlflow is None:
        return
    tags = {str(key): str(value) for key, value in payload.items() if value is not None}
    if tags:
        mlflow.set_tags(tags)


def _mlflow_log_dict(payload: dict[str, Any], artifact_file: str) -> None:
    mlflow = _mlflow_client()
    if mlflow is None:
        return
    mlflow.log_dict(payload, artifact_file)


def _write_json(path: str | Path, payload: dict[str, Any]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return target


def _append_jsonl(path: str | Path, payload: dict[str, Any]) -> Path:
    return _append_text_with_retention(
        path,
        json.dumps(payload) + "\n",
        max_bytes=_DEFAULT_EVENT_LOG_MAX_BYTES,
        backup_count=_DEFAULT_LOG_BACKUP_COUNT,
    )


def _load_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_pickle_gz(path: str | Path, payload: Any) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(target, "wb") as handle:
        pickle.dump(payload, handle, protocol=pickle.HIGHEST_PROTOCOL)
    return target


def _load_pickle_gz(path: str | Path) -> Any:
    with gzip.open(Path(path), "rb") as handle:
        return pickle.load(handle)


def _hash_tree(root: str | Path) -> str:
    digest = hashlib.sha256()
    path = Path(root)
    if path.is_file():
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    for child in sorted(path.rglob("*")):
        if not child.is_file():
            continue
        digest.update(child.relative_to(path).as_posix().encode("utf-8"))
        with child.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    return digest.hexdigest()


def _git_sha() -> str:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except Exception:  # pragma: no cover
        return "unknown"


def _dependency_versions() -> dict[str, str]:
    versions = {"python": platform.python_version()}
    for package_name in ["torch", "transformers", "peft", "xgboost", "catboost", "scikit-learn"]:
        try:
            versions[package_name] = importlib.metadata.version(package_name)
        except importlib.metadata.PackageNotFoundError:
            continue
    return versions


def _dataset_root_for_manifest(manifest_path: str | Path, *, data_root: str | Path | None = None) -> Path:
    manifest = load_manifest(manifest_path)
    return resolve_private_dataset_dir(manifest, data_root=data_root)


def _iter_examples(
    manifest_path: str | Path,
    split: str,
    *,
    data_root: str | Path | None = None,
    skip: int = 0,
    limit: int | None = None,
) -> Iterable[Any]:
    emitted = 0
    skipped = 0
    manifest = load_manifest(manifest_path)
    for path in resolve_split_files(manifest, split, data_root=data_root):
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                if skipped < skip:
                    skipped += 1
                    continue
                yield example_from_dataset_row(json.loads(line))
                emitted += 1
                if limit is not None and emitted >= limit:
                    return


def _total_examples(
    manifest_path: str | Path,
    split: str,
    *,
    data_root: str | Path | None = None,
    limit: int | None = None,
) -> int | None:
    manifest = load_manifest(manifest_path)
    total = manifest_record_count(manifest, split)
    if total is None:
        counted = 0
        for _relative_path, _offset, _row in _iter_records_with_offsets(
            manifest_path,
            split,
            data_root=data_root,
            limit=limit,
        ):
            counted += 1
        return counted
    return min(total, limit) if limit is not None else total


def prepare_data(
    manifest_path: str | Path,
    *,
    output_dir: str | Path,
    data_root: str | Path | None = None,
) -> dict[str, Any]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    summary = manifest_storage_summary(load_manifest(manifest_path), data_root=data_root)
    target = output_path / "prepared_data_summary.json"
    target.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return {"preparedDataSummary": str(target), **summary}


def _load_recipe(recipe_path: str | Path) -> dict[str, Any]:
    return _load_json(recipe_path)


def _safe_stage_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in {"_", "-"} else "_" for char in value)


def _iter_records_with_offsets(
    manifest_path: str | Path,
    split: str,
    *,
    data_root: str | Path | None = None,
    limit: int | None = None,
) -> Iterator[tuple[str, int, dict[str, Any]]]:
    manifest = load_manifest(manifest_path)
    emitted = 0
    for path in resolve_split_files(manifest, split, data_root=data_root):
        relative = path.relative_to(path.parents[1]).as_posix()
        with path.open("r", encoding="utf-8") as handle:
            while True:
                offset = handle.tell()
                line = handle.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                yield relative, offset, json.loads(line)
                emitted += 1
                if limit is not None and emitted >= limit:
                    return


def _build_index(
    manifest_path: str | Path,
    split: str,
    *,
    data_root: str | Path | None = None,
    limit: int | None = None,
    output_path: str | Path | None = None,
) -> list[IndexedRecord]:
    records: list[IndexedRecord] = []
    for relative_path, offset, row in _iter_records_with_offsets(
        manifest_path,
        split,
        data_root=data_root,
        limit=limit,
    ):
        label = str(row.get("expected_label", "allow_read_only"))
        if label not in LABEL_TO_ID:
            continue
        records.append(
            IndexedRecord(
                index=len(records),
                relative_path=relative_path,
                offset=offset,
                example_id=str(row.get("id", len(records))),
                label=label,
                attack_family=str(row.get("attack_family", "none")),
            )
        )
    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as handle:
            for item in records:
                handle.write(
                    json.dumps(
                        {
                            "index": item.index,
                            "relative_path": item.relative_path,
                            "offset": item.offset,
                            "example_id": item.example_id,
                            "label": item.label,
                            "attack_family": item.attack_family,
                        }
                    )
                    + "\n"
                )
    return records


def _read_record_by_index(dataset_root: str | Path, index_records: list[IndexedRecord], index: int) -> dict[str, Any]:
    record = index_records[index]
    path = Path(dataset_root) / record.relative_path
    with path.open("r", encoding="utf-8") as handle:
        handle.seek(record.offset)
        return json.loads(handle.readline())


def _iter_examples_from_index_plan(
    dataset_root: str | Path,
    index_records: list[IndexedRecord],
    selected_indices: list[int],
) -> Iterator[Any]:
    for record_index in selected_indices:
        yield example_from_dataset_row(_read_record_by_index(dataset_root, index_records, record_index))


def _format_chunk_text(example: Any, context_chunk: str) -> str:
    return "\n".join(
        [
            f"[GOAL] {example.goal}",
            f"[SETUP] {example.setup}",
            f"[ACTION] {example.candidate_action}",
            (
                f"[META] surface={example.surface} lang={example.lang} "
                f"domain={example.domain} channels={','.join(example.channels)}"
            ),
            f"[CONTEXT] {context_chunk}",
        ]
    )


def _top_ranked_chunks(
    example: Any,
    *,
    top_k_chunks: int,
    sentinel_probability: float = 0.0,
) -> list[str]:
    base_context = example.context or example.text
    chunks = chunk_text(base_context)
    ranked = rank_chunks(
        chunks,
        example.goal,
        example.candidate_action,
        sentinel_probability=sentinel_probability,
    )
    selected = [chunk for _, chunk in ranked[:top_k_chunks]] if ranked else chunks[:top_k_chunks]
    selected = selected or [base_context]
    return [_format_chunk_text(example, chunk) for chunk in selected]


def _hierarchical_text(example: Any, *, top_k_chunks: int = 3, sentinel_probability: float = 0.0) -> str:
    return "\n\n".join(
        _top_ranked_chunks(example, top_k_chunks=top_k_chunks, sentinel_probability=sentinel_probability)
    )


def _write_plan_indices(path: str | Path, indices: list[int]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        for index in indices:
            handle.write(f"{index}\n")
    return target


def _shuffled(values: list[int], *, seed: int) -> list[int]:
    rng = random.Random(seed)
    copy = list(values)
    rng.shuffle(copy)
    return copy


def _take_weighted_indices(
    hard: list[int],
    normal: list[int],
    *,
    quota: int,
    seed: int,
    hard_multiplier: int = 2,
) -> list[int]:
    pool = list(normal)
    for _ in range(max(1, hard_multiplier)):
        pool.extend(hard)
    if not pool:
        return []
    pool = _shuffled(pool, seed=seed)
    if len(pool) >= quota:
        return pool[:quota]
    expanded: list[int] = []
    while len(expanded) < quota:
        expanded.extend(pool)
    return expanded[:quota]


def _scaled_label_quotas(total: int, label_distribution: dict[str, int]) -> dict[str, int]:
    total_distribution = sum(int(value) for value in label_distribution.values()) or 1
    ordered_labels = list(LABEL_TO_ID.keys())
    quotas: dict[str, int] = {}
    assigned = 0
    for label in ordered_labels[:-1]:
        raw = total * int(label_distribution.get(label, 0)) / total_distribution
        quota = int(math.floor(raw))
        quotas[label] = quota
        assigned += quota
    quotas[ordered_labels[-1]] = max(0, total - assigned)
    return quotas


def _load_recipe_stages(recipe: dict[str, Any]) -> list[RecipeStage]:
    stages: list[RecipeStage] = []
    batch_config = recipe.get("rtx4060ti_8gb_profile", {}).get("deep_model_batching", {})
    for item in recipe.get("training_plan", {}).get("phase_2_deep_curriculum", []):
        max_length = int(item["max_length"])
        batch_key = f"{max_length}_tokens"
        batch_profile = batch_config.get(batch_key, {})
        stages.append(
            RecipeStage(
                name=str(item["stage"]),
                max_length=max_length,
                epochs=float(item["epochs"]),
                train_subset=int(item["train_subset"]),
                sampling=str(item.get("sampling", "")),
                batch_size=int(batch_profile.get("per_device_batch_size", 1)),
                gradient_accumulation_steps=int(batch_profile.get("gradient_accumulation_steps", 1)),
            )
        )
    if not stages:
        raise RuntimeError("Recipe did not declare any deep curriculum stages.")
    return stages


def _select_stage_indices(
    index_records: list[IndexedRecord],
    *,
    stage: RecipeStage,
    hard_families: set[str],
    label_distribution: dict[str, int],
    seed: int,
) -> list[int]:
    by_label_hard: dict[str, list[int]] = {label: [] for label in LABEL_TO_ID}
    by_label_normal: dict[str, list[int]] = {label: [] for label in LABEL_TO_ID}
    for item in index_records:
        bucket = by_label_hard if item.attack_family in hard_families else by_label_normal
        bucket[item.label].append(item.index)

    if "balanced by label" in stage.sampling:
        base_quota = stage.train_subset // max(1, len(LABEL_TO_ID))
        remainder = stage.train_subset - (base_quota * len(LABEL_TO_ID))
        quotas = {label: base_quota for label in LABEL_TO_ID}
        for label in list(LABEL_TO_ID.keys())[:remainder]:
            quotas[label] += 1
    elif "sampled negatives" in stage.sampling:
        quotas = _scaled_label_quotas(stage.train_subset, label_distribution)
    else:
        quotas = {label: 0 for label in LABEL_TO_ID}
        for item in index_records[: stage.train_subset]:
            quotas[item.label] += 1

    selected: list[int] = []
    for offset, label in enumerate(LABEL_TO_ID.keys(), start=1):
        quota = quotas.get(label, 0)
        selected.extend(
            _take_weighted_indices(
                by_label_hard[label],
                by_label_normal[label],
                quota=quota,
                seed=seed + offset,
                hard_multiplier=2,
            )
        )
    return _shuffled(selected, seed=seed + 100)


def _write_stage_plan(
    output_dir: str | Path,
    *,
    stage: RecipeStage,
    selected_indices: list[int],
    hard_negative_indices: list[int] | None = None,
) -> ExpertStagePlan:
    stage_dir = Path(output_dir) / _safe_stage_name(stage.name)
    stage_dir.mkdir(parents=True, exist_ok=True)
    plan_path = _write_plan_indices(stage_dir / "plan.txt", selected_indices)
    if hard_negative_indices is None:
        hard_negative_indices = []
    _write_json(
        stage_dir / "plan_summary.json",
        {
            "stage": stage.name,
            "maxLength": stage.max_length,
            "epochs": stage.epochs,
            "trainSubset": stage.train_subset,
            "batchSize": stage.batch_size,
            "gradientAccumulationSteps": stage.gradient_accumulation_steps,
            "planEntries": len(selected_indices),
            "hardNegativeReplayEntries": len(hard_negative_indices),
        },
    )
    return ExpertStagePlan(stage=stage, plan_path=plan_path, selected_indices=selected_indices, hard_negative_indices=hard_negative_indices)


def _save_progress(output_path: Path, payload: dict[str, Any]) -> None:
    _write_json(output_path / "progress.json", {"updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **payload})


def _save_status(output_path: Path, payload: dict[str, Any]) -> None:
    _write_json(output_path / "status.json", {"updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **payload})


def _mark_run_failed(
    output_path: Path,
    *,
    fallback_step: str,
    fallback_stage: str | None,
    error: BaseException,
) -> None:
    try:
        current_status = _load_json(output_path / "status.json") if (output_path / "status.json").is_file() else {}
    except Exception:
        current_status = {}
    try:
        current_progress = _load_json(output_path / "progress.json") if (output_path / "progress.json").is_file() else {}
    except Exception:
        current_progress = {}
    current_step = str(current_status.get("currentStep") or fallback_step)
    current_stage = current_progress.get("currentStage") or current_status.get("currentStage") or fallback_stage
    message = f"{type(error).__name__}: {error}"
    _save_status(
        output_path,
        {
            "currentStep": current_step,
            "currentStage": current_stage,
            "state": "failed",
            "errorMessage": message,
        },
    )
    _save_progress(
        output_path,
        {
            **current_progress,
            "currentStage": current_stage,
            "state": "failed",
            "errorMessage": message,
        },
    )
    _append_jsonl(
        output_path / "events.jsonl",
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "type": "run_failed",
            "currentStep": current_step,
            "currentStage": current_stage,
            "errorMessage": message,
        },
    )


def _score_dual_sentinel_artifact(
    sentinel_artifact: dict[str, Any],
    example: Any,
) -> dict[str, float]:
    deps = _require_training_dependencies()
    hstack = deps["hstack"]
    xgb = deps.get("xgboost")

    lexical = sentinel_artifact["lexical"]
    structured = sentinel_artifact["structured"]

    lexical_matrix = hstack(
        [
            lexical["char_vectorizer"].transform([example.text]),
            lexical["word_vectorizer"].transform([example.text]),
        ],
        format="csr",
    )
    lexical_classifier = lexical["classifier"]
    if hasattr(lexical_classifier, "predict_proba"):
        lexical_probability = float(lexical_classifier.predict_proba(lexical_matrix)[0][1])
    else:
        lexical_probability = 1.0 / (1.0 + math.exp(-float(lexical_classifier.decision_function(lexical_matrix)[0])))

    structured_matrix = hstack(
        [
            structured["dict_vectorizer"].transform([structured_feature_dict(example.structured)]),
            structured["text_vectorizer"].transform([_hierarchical_text(example, top_k_chunks=3)]),
        ],
        format="csr",
    ).astype("float32")
    structured_classifier = structured["classifier"]
    if structured["backend"].startswith("xgboost_binary") and xgb is not None:
        booster = structured.get("_booster")
        if booster is None:
            classifier_payload = structured_classifier
            if isinstance(classifier_payload, xgb.Booster):
                booster = classifier_payload
            else:
                booster = xgb.Booster()
                booster.load_model(bytearray(classifier_payload))
            structured["_booster"] = booster
        structured_probability = float(booster.predict(xgb.DMatrix(structured_matrix))[0])
    elif structured["backend"] == "catboost_binary_cpu":
        structured_probability = float(structured_classifier.predict_proba(structured_matrix.toarray())[0][1])
    elif hasattr(structured_classifier, "predict_proba"):
        structured_probability = float(structured_classifier.predict_proba(structured_matrix)[0][1])
    else:
        structured_probability = 1.0 / (
            1.0 + math.exp(-float(structured_classifier.decision_function(structured_matrix)[0]))
        )

    return {
        "lexical": lexical_probability,
        "structured": structured_probability,
        "max": max(lexical_probability, structured_probability),
        "threshold": float(sentinel_artifact.get("threshold", 0.55)),
    }


def _select_threat_threshold_from_rows(
    rows: list[tuple[float, int]],
    *,
    minimum_recall: float,
) -> tuple[float, float]:
    if not rows:
        return 0.55, 1.0
    candidate_thresholds = sorted({score for score, _ in rows}, reverse=True)
    best_threshold = candidate_thresholds[-1]
    best_recall = 0.0
    for threshold in candidate_thresholds:
        gold = sum(label for _, label in rows) or 1
        true_positive = sum(1 for score, label in rows if label == 1 and score >= threshold)
        recall = true_positive / gold
        if recall >= minimum_recall:
            return float(threshold), float(recall)
        if recall > best_recall:
            best_threshold = threshold
            best_recall = recall
    return float(best_threshold), float(best_recall)


def _choose_threat_threshold(
    valid_examples: Iterable[Any],
    sentinel_artifact: dict[str, Any],
    *,
    minimum_recall: float,
    progress_callback: Callable[[int], None] | None = None,
) -> tuple[float, float]:
    rows: list[tuple[float, int]] = []
    for example in valid_examples:
        if example.threat_positive is None:
            continue
        rows.append((_score_dual_sentinel_artifact(sentinel_artifact, example)["max"], int(example.threat_positive)))
        if progress_callback is not None and (len(rows) <= 4 or len(rows) % 2048 == 0):
            progress_callback(len(rows))
    if not rows:
        return 0.55, 1.0
    if progress_callback is not None:
        progress_callback(len(rows))
    return _select_threat_threshold_from_rows(rows, minimum_recall=minimum_recall)


def train_sentinel(
    manifest_path: str | Path,
    *,
    output_dir: str | Path,
    data_root: str | Path | None = None,
    limit: int | None = None,
    threat_threshold: float = 0.55,
    checkpoint_dir: str | Path | None = None,
    checkpoint_batches: int = _DEFAULT_SENTINEL_CHECKPOINT_BATCHES,
    resume: bool = False,
    recipe_mode: str = "dual",
    progress_root: str | Path | None = None,
) -> dict[str, Any]:
    deps = _require_training_dependencies()
    HashingVectorizer = deps["HashingVectorizer"]
    DictVectorizer = deps["DictVectorizer"]
    SGDClassifier = deps["SGDClassifier"]
    XGBClassifier = deps["XGBClassifier"]
    CatBoostClassifier = deps["CatBoostClassifier"]
    hstack = deps["hstack"]
    vstack = deps["vstack"]
    xgb = deps["xgboost"]

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    progress_output_path = Path(progress_root) if progress_root is not None else output_path
    checkpoint_root = Path(checkpoint_dir) if checkpoint_dir is not None else output_path / "active" / "latest"
    state_path = checkpoint_root / "state.json"
    structured_checkpoint_path = checkpoint_root / "structured.pkl"
    threshold_cache_path = checkpoint_root / "threshold_rows.pkl"
    total_train_examples = _total_examples(manifest_path, "train", data_root=data_root, limit=limit) or 0
    total_valid_examples = _total_examples(manifest_path, "valid", data_root=data_root, limit=limit) or 0
    lexical_batch_size = 2048
    processed_batches = 0
    partial_records_seen = 0
    sentinel_started_monotonic = time.perf_counter()
    bootstrap_report_batches = {1, 2, 4, 8, 16}
    progress_heartbeat_seconds = 10.0
    last_progress_report_monotonic = sentinel_started_monotonic
    events_path = progress_output_path / "events.jsonl"
    run_log_path = progress_output_path / "run.log"
    progress_lock = RLock()
    structured_phase = "pending"
    structured_vocab_records_seen = 0
    structured_vectorize_records_seen = 0
    structured_train_pass = 0
    structured_train_round = 0
    threshold_records_seen = 0
    resume_state = _load_json(state_path) if resume and state_path.is_file() else {}
    resume_phase = str(resume_state.get("phase") or "")
    direct_structured_resume = bool(
        resume
        and structured_checkpoint_path.is_file()
        and resume_phase in {"structured_train", "threshold_tuning", "complete"}
    )

    def _structured_fraction_locked() -> float:
        if total_train_examples <= 0:
            valid_fraction = min(1.0, threshold_records_seen / max(1, total_valid_examples)) if total_valid_examples else 1.0
            return 1.0 if structured_phase == "complete" else valid_fraction
        if structured_phase == "pending":
            return 0.0
        if structured_phase == "structured_vocab":
            return 0.35 * min(1.0, structured_vocab_records_seen / total_train_examples)
        if structured_phase == "structured_vectorize":
            return 0.35 + 0.45 * min(1.0, structured_vectorize_records_seen / total_train_examples)
        if structured_phase == "structured_train":
            return 0.80 + 0.10 * min(1.0, structured_train_round / 200.0)
        if structured_phase == "threshold_tuning":
            valid_fraction = min(1.0, threshold_records_seen / max(1, total_valid_examples)) if total_valid_examples else 1.0
            return 0.90 + 0.10 * valid_fraction
        if structured_phase == "complete":
            return 1.0
        return 0.0

    def report_sentinel_progress(
        *,
        state: str,
        phase: str,
        threshold: float | None = None,
        threshold_recall: float | None = None,
        include_throughput: bool = True,
    ) -> None:
        with progress_lock:
            lexical_records_seen = min(total_train_examples, max(partial_records_seen, processed_batches * lexical_batch_size))
            phase_records_seen = lexical_records_seen
            phase_total_records = total_train_examples
            phase_unit = "examples"
            display_progress_text = (
                f"lexical: {lexical_records_seen:,} / {total_train_examples:,} examples"
                if total_train_examples
                else "lexical: waiting"
            )
            if phase == "structured_vocab":
                phase_records_seen = structured_vocab_records_seen
                phase_total_records = total_train_examples
                display_progress_text = (
                    f"structured vocab: {structured_vocab_records_seen:,} / {total_train_examples:,} examples"
                    if total_train_examples
                    else "structured vocab: waiting"
                )
            elif phase == "structured_vectorize":
                phase_records_seen = structured_vectorize_records_seen
                phase_total_records = total_train_examples
                display_progress_text = (
                    f"structured vectorize: {structured_vectorize_records_seen:,} / {total_train_examples:,} examples"
                    if total_train_examples
                    else "structured vectorize: waiting"
                )
            elif phase == "structured_train":
                phase_records_seen = structured_vectorize_records_seen
                phase_total_records = total_train_examples
                display_progress_text = (
                    f"structured train: pass {max(1, structured_train_pass)}, "
                    f"round {structured_train_round:,} / 200, "
                    f"{structured_vectorize_records_seen:,} / {total_train_examples:,} examples streamed"
                    if total_train_examples
                    else f"structured train: pass {max(1, structured_train_pass)}, round {structured_train_round:,} / 200"
                )
            elif phase == "threshold_tuning":
                phase_records_seen = threshold_records_seen
                phase_total_records = total_valid_examples
                display_progress_text = (
                    f"threshold tuning: {threshold_records_seen:,} / {total_valid_examples:,} validation examples"
                    if total_valid_examples
                    else "threshold tuning: scoring validation examples"
                )
            elif phase == "complete":
                phase_records_seen = phase_total_records = max(1, total_valid_examples or total_train_examples)
                display_progress_text = "complete"
            lexical_fraction = min(1.0, lexical_records_seen / max(1, total_train_examples)) if total_train_examples else 1.0
            stage_fraction = 0.5 * lexical_fraction + 0.5 * _structured_fraction_locked()
        elapsed_seconds = max(time.perf_counter() - sentinel_started_monotonic, 1e-9)
        progress_payload: dict[str, Any] = {
            "currentStage": "phase_1_ml_sentinel",
            "optimizerStep": processed_batches,
            "recordsSeen": phase_records_seen,
            "totalTargetRecords": phase_total_records,
            "currentItems": phase_records_seen,
            "totalItems": phase_total_records,
            "lastCheckpointPath": str(checkpoint_root) if checkpoint_root.exists() else None,
            "lastCheckpointAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) if checkpoint_root.exists() else None,
            "state": state,
            "phase": phase,
            "unit": phase_unit,
            "displayProgressText": display_progress_text,
            "processedBatches": processed_batches,
            "batchSize": lexical_batch_size,
            "progressFraction": stage_fraction,
            "examplesPerSecond": (phase_records_seen / elapsed_seconds if phase_records_seen else 0.0)
            if include_throughput and phase_total_records
            else None,
            "batchesPerSecond": (processed_batches / elapsed_seconds if processed_batches else 0.0) if include_throughput else None,
            "lexicalRecordsSeen": lexical_records_seen,
            "structuredVocabRecordsSeen": structured_vocab_records_seen,
            "structuredVectorizeRecordsSeen": structured_vectorize_records_seen,
            "structuredTrainPass": structured_train_pass,
            "structuredTrainRound": structured_train_round,
            "thresholdRecordsSeen": threshold_records_seen,
        }
        if threshold is not None:
            progress_payload["threshold"] = float(threshold)
        if threshold_recall is not None:
            progress_payload["thresholdRecall"] = float(threshold_recall)
        _save_progress(progress_output_path, progress_payload)
        _append_jsonl(
            events_path,
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "type": "sentinel_progress",
                "state": state,
                "phase": phase,
                "processedBatches": processed_batches,
                "recordsSeen": phase_records_seen,
                "totalTargetRecords": phase_total_records,
                "threshold": threshold,
                "thresholdRecall": threshold_recall,
                "displayProgressText": display_progress_text,
            },
        )
        throughput_text = (
            f", {progress_payload['examplesPerSecond']:.2f} ex/s"
            if isinstance(progress_payload.get("examplesPerSecond"), (int, float))
            else ""
        )
        _maybe_report(
            f"[sentinel:{phase}] state={state} records={phase_records_seen}/{phase_total_records} "
            f"batches={processed_batches}{throughput_text}",
            run_log_path=run_log_path,
        )
        _mlflow_log_metrics(
            {
                "sentinel.records_seen": phase_records_seen,
                "sentinel.total_target_records": phase_total_records,
                "sentinel.processed_batches": processed_batches,
                "sentinel.progress_fraction": progress_payload["progressFraction"],
                "sentinel.threshold": threshold,
                "sentinel.threshold_recall": threshold_recall,
            },
            step=processed_batches,
        )

    def update_threshold_progress(count: int) -> None:
        nonlocal structured_phase, threshold_records_seen
        with progress_lock:
            structured_phase = "threshold_tuning"
            threshold_records_seen = count
        _write_json(
            state_path,
            {
                "phase": "threshold_tuning",
                "processedBatches": processed_batches,
                "structuredTrainPass": structured_train_pass,
                "structuredTrainRound": structured_train_round,
                "structuredVectorizeRecordsSeen": structured_vectorize_records_seen,
                "thresholdRecordsSeen": threshold_records_seen,
            },
        )
        report_sentinel_progress(state="running", phase="threshold_tuning", include_throughput=False)

    def choose_threat_threshold_with_resume(sentinel_artifact: dict[str, Any]) -> tuple[float, float]:
        rows: list[tuple[float, int]] = []
        processed = 0
        threshold_last_report_monotonic = time.perf_counter()
        if resume and threshold_cache_path.is_file():
            try:
                threshold_cache = load_pickle(threshold_cache_path)
            except Exception:
                threshold_cache = None
            if isinstance(threshold_cache, dict):
                cached_rows = threshold_cache.get("rows") or []
                rows = [(float(score), int(label)) for score, label in cached_rows]
                processed = int(threshold_cache.get("processed", len(rows)))
        if processed:
            update_threshold_progress(processed)
        for example in _iter_examples(
            manifest_path,
            "valid",
            data_root=data_root,
            limit=limit,
            skip=processed,
            ):
            if example.threat_positive is None:
                continue
            rows.append((_score_dual_sentinel_artifact(sentinel_artifact, example)["max"], int(example.threat_positive)))
            processed += 1
            now_monotonic = time.perf_counter()
            if (
                processed <= 4
                or processed % 2048 == 0
                or now_monotonic - threshold_last_report_monotonic >= progress_heartbeat_seconds
            ):
                write_pickle(threshold_cache_path, {"rows": rows, "processed": processed})
                update_threshold_progress(processed)
                threshold_last_report_monotonic = now_monotonic
        write_pickle(threshold_cache_path, {"rows": rows, "processed": processed})
        update_threshold_progress(processed)
        return _select_threat_threshold_from_rows(rows, minimum_recall=0.995)

    def train_structured_sentinel() -> dict[str, Any]:
        nonlocal structured_phase, structured_vocab_records_seen, structured_vectorize_records_seen, structured_train_pass, structured_train_round, threshold_records_seen
        if direct_structured_resume:
            structured_artifact = load_pickle(structured_checkpoint_path)
            resumed_phase = "threshold_tuning" if resume_phase in {"structured_train", "threshold_tuning"} else "structured_train"
            with progress_lock:
                structured_phase = resumed_phase
                structured_vocab_records_seen = int(resume_state.get("structuredVocabRecordsSeen", total_train_examples))
                structured_vectorize_records_seen = int(
                    resume_state.get("structuredVectorizeRecordsSeen", total_train_examples)
                )
                structured_train_pass = int(resume_state.get("structuredTrainPass", max(1, structured_train_pass)))
                structured_train_round = int(resume_state.get("structuredTrainRound", 200))
                threshold_records_seen = int(resume_state.get("thresholdRecordsSeen", 0))
            report_sentinel_progress(
                state="running",
                phase=resumed_phase,
                include_throughput=False,
            )
            return structured_artifact
        text_vectorizer = HashingVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            n_features=2**14,
            alternate_sign=False,
            norm="l2",
        )
        dict_vectorizer = DictVectorizer(sparse=True)

        def _iter_structured_rows(split: str) -> Iterable[dict[str, Any]]:
            nonlocal structured_phase, structured_vocab_records_seen
            for example in _iter_examples(manifest_path, split, data_root=data_root, limit=limit):
                if split == "train":
                    with progress_lock:
                        structured_phase = "structured_vocab"
                        structured_vocab_records_seen += 1
                        if structured_vocab_records_seen <= 4 or structured_vocab_records_seen % structured_batch_size == 0:
                            report_sentinel_progress(state="running", phase="structured_vocab")
                yield structured_feature_dict(example.structured)

        def _iter_structured_texts(split: str) -> Iterable[str]:
            for example in _iter_examples(manifest_path, split, data_root=data_root, limit=limit):
                yield _hierarchical_text(example, top_k_chunks=3)

        def _iter_threat_labels(split: str) -> Iterable[int]:
            for example in _iter_examples(manifest_path, split, data_root=data_root, limit=limit):
                yield int(example.threat_positive or 0)

        structured_batch_size = 4096
        with progress_lock:
            structured_phase = "structured_vocab"
            structured_vocab_records_seen = 0
            structured_vectorize_records_seen = 0
        report_sentinel_progress(state="running", phase="structured_vocab", include_throughput=False)
        dict_vectorizer.fit(_iter_structured_rows("train"))
        with progress_lock:
            structured_phase = "structured_vectorize"
            structured_vocab_records_seen = total_train_examples
            structured_vectorize_records_seen = 0
        _write_json(
            checkpoint_root / "state.json",
            {
                "phase": "structured_vocab_complete",
                "processedBatches": processed_batches,
                "structuredVocabRecordsSeen": structured_vocab_records_seen,
            },
        )
        train_device = "cpu"
        if recipe_mode == "dual" and xgb is not None:
            try:
                train_device = "cuda" if _require_transformer_dependencies()["torch"].cuda.is_available() else "cpu"
            except RuntimeError:
                train_device = "cpu"

            class StructuredBatchIter(xgb.DataIter):
                def __init__(self) -> None:
                    self._pass_index = 0
                    self._processed_examples = 0
                    self._iterator: Iterator[Any] | None = None
                    super().__init__()
                    self.reset()

                def reset(self) -> None:
                    self._pass_index += 1
                    self._processed_examples = 0
                    self._iterator = iter(_iter_examples(manifest_path, "train", data_root=data_root, limit=limit))
                    with progress_lock:
                        nonlocal structured_phase, structured_vectorize_records_seen, structured_train_pass, structured_train_round
                        structured_phase = "structured_train"
                        structured_vectorize_records_seen = 0
                        structured_train_pass = self._pass_index
                        structured_train_round = 0
                    _write_json(
                        checkpoint_root / "state.json",
                        {
                            "phase": "structured_train",
                            "processedBatches": processed_batches,
                            "structuredTrainPass": structured_train_pass,
                            "structuredTrainRound": structured_train_round,
                            "structuredVectorizeRecordsSeen": structured_vectorize_records_seen,
                        },
                    )
                    report_sentinel_progress(state="running", phase="structured_train", include_throughput=False)

                def next(self, input_data: Callable[..., None]) -> int:
                    rows_batch: list[dict[str, Any]] = []
                    texts_batch: list[str] = []
                    labels_batch: list[int] = []
                    assert self._iterator is not None
                    while len(rows_batch) < structured_batch_size:
                        try:
                            example = next(self._iterator)
                        except StopIteration:
                            break
                        rows_batch.append(structured_feature_dict(example.structured))
                        texts_batch.append(_hierarchical_text(example, top_k_chunks=3))
                        labels_batch.append(int(example.threat_positive or 0))
                    if not rows_batch:
                        return 0
                    matrix = hstack(
                        [
                            dict_vectorizer.transform(rows_batch),
                            text_vectorizer.transform(texts_batch),
                        ],
                        format="csr",
                    ).astype("float32")
                    input_data(data=matrix, label=labels_batch)
                    self._processed_examples += len(labels_batch)
                    with progress_lock:
                        nonlocal structured_phase, structured_vectorize_records_seen, structured_train_pass
                        structured_phase = "structured_train"
                        structured_vectorize_records_seen = self._processed_examples
                        structured_train_pass = self._pass_index
                    if self._processed_examples <= structured_batch_size or self._processed_examples % structured_batch_size == 0:
                        _write_json(
                            checkpoint_root / "state.json",
                            {
                                "phase": "structured_train",
                                "processedBatches": processed_batches,
                                "structuredTrainPass": structured_train_pass,
                                "structuredTrainRound": structured_train_round,
                                "structuredVectorizeRecordsSeen": structured_vectorize_records_seen,
                            },
                        )
                        report_sentinel_progress(state="running", phase="structured_train")
                    return 1

                def cleanup(self) -> None:
                    return None

            class StructuredTrainProgressCallback(xgb.callback.TrainingCallback):
                def after_iteration(self, model: Any, epoch: int, evals_log: Any) -> bool:
                    nonlocal structured_phase, structured_vectorize_records_seen, structured_train_round
                    with progress_lock:
                        structured_phase = "structured_train"
                        structured_vectorize_records_seen = total_train_examples
                        structured_train_round = epoch + 1
                    if structured_train_round <= 3 or structured_train_round % 5 == 0 or structured_train_round == 200:
                        _write_json(
                            checkpoint_root / "state.json",
                            {
                                "phase": "structured_train",
                                "processedBatches": processed_batches,
                                "structuredTrainPass": structured_train_pass,
                                "structuredTrainRound": structured_train_round,
                                "structuredVectorizeRecordsSeen": structured_vectorize_records_seen,
                            },
                        )
                        report_sentinel_progress(state="running", phase="structured_train", include_throughput=False)
                    return False

            batch_iter = StructuredBatchIter()
            try:
                dtrain = xgb.QuantileDMatrix(batch_iter, max_bin=256)
                structured_classifier = xgb.train(
                    {
                        "objective": "binary:logistic",
                        "eval_metric": "aucpr",
                        "max_depth": 8,
                        "learning_rate": 0.05,
                        "subsample": 0.8,
                        "colsample_bytree": 0.6,
                        "min_child_weight": 2,
                        "max_bin": 256,
                        "tree_method": "hist",
                        "device": train_device,
                        "nthread": max(1, (os.cpu_count() or 2) - 1),
                        "seed": _DEFAULT_RANDOM_SEED,
                    },
                    dtrain,
                    num_boost_round=200,
                    verbose_eval=False,
                    callbacks=[StructuredTrainProgressCallback()],
                )
            finally:
                batch_iter.cleanup()
            with progress_lock:
                structured_phase = "structured_train"
                structured_vectorize_records_seen = total_train_examples
                structured_train_round = 200
            _write_json(
                checkpoint_root / "state.json",
                {
                    "phase": "structured_train",
                    "processedBatches": processed_batches,
                    "structuredTrainPass": structured_train_pass,
                    "structuredTrainRound": structured_train_round,
                    "structuredVectorizeRecordsSeen": structured_vectorize_records_seen,
                },
            )
            report_sentinel_progress(state="running", phase="structured_train", include_throughput=False)
            structured_backend = "xgboost_binary"
        elif CatBoostClassifier is not None:
            report_sentinel_progress(state="running", phase="structured_vectorize", include_throughput=False)
            train_labels: list[int] = []
            structured_blocks: list[Any] = []
            rows_batch: list[dict[str, Any]] = []
            texts_batch: list[str] = []
            processed_examples = 0
            for example in _iter_examples(manifest_path, "train", data_root=data_root, limit=limit):
                rows_batch.append(structured_feature_dict(example.structured))
                texts_batch.append(_hierarchical_text(example, top_k_chunks=3))
                train_labels.append(int(example.threat_positive or 0))
                processed_examples += 1
                if len(rows_batch) < structured_batch_size:
                    continue
                structured_blocks.append(
                    hstack(
                        [
                            dict_vectorizer.transform(rows_batch),
                            text_vectorizer.transform(texts_batch),
                        ],
                        format="csr",
                    ).astype("float32")
                )
                with progress_lock:
                    structured_vectorize_records_seen = processed_examples
                rows_batch = []
                texts_batch = []
                if processed_examples <= structured_batch_size or processed_examples % structured_batch_size == 0:
                    _write_json(
                        checkpoint_root / "state.json",
                        {
                            "phase": "structured_vectorize",
                            "processedBatches": processed_batches,
                            "structuredVectorizeRecordsSeen": structured_vectorize_records_seen,
                        },
                    )
                    report_sentinel_progress(state="running", phase="structured_vectorize")
            if rows_batch:
                structured_blocks.append(
                    hstack(
                        [
                            dict_vectorizer.transform(rows_batch),
                            text_vectorizer.transform(texts_batch),
                        ],
                        format="csr",
                    ).astype("float32")
                )
                with progress_lock:
                    structured_vectorize_records_seen = processed_examples
                _write_json(
                    checkpoint_root / "state.json",
                    {
                        "phase": "structured_vectorize",
                        "processedBatches": processed_batches,
                        "structuredVectorizeRecordsSeen": structured_vectorize_records_seen,
                    },
                )
                report_sentinel_progress(state="running", phase="structured_vectorize")
            if not structured_blocks:
                raise RuntimeError("Structured sentinel received no train examples.")
            structured_matrix = vstack(structured_blocks, format="csr").astype("float32")
            if processed_examples != len(train_labels):
                raise RuntimeError(
                    f"Structured sentinel row/label mismatch: rows={processed_examples} labels={len(train_labels)}."
                )
            with progress_lock:
                structured_phase = "structured_train"
                structured_vectorize_records_seen = processed_examples
            _write_json(
                checkpoint_root / "state.json",
                {
                    "phase": "structured_train",
                    "processedBatches": processed_batches,
                    "structuredVectorizeRecordsSeen": structured_vectorize_records_seen,
                },
            )
            report_sentinel_progress(state="running", phase="structured_train", include_throughput=False)
            structured_classifier = CatBoostClassifier(
                task_type="CPU",
                loss_function="Logloss",
                depth=6,
                learning_rate=0.08,
                iterations=200,
                allow_writing_files=False,
                verbose=False,
            )
            structured_backend = "catboost_binary_cpu"
            structured_classifier.fit(structured_matrix.toarray(), train_labels)
        else:
            report_sentinel_progress(state="running", phase="structured_vectorize", include_throughput=False)
            train_labels = []
            structured_blocks = []
            rows_batch = []
            texts_batch = []
            processed_examples = 0
            for example in _iter_examples(manifest_path, "train", data_root=data_root, limit=limit):
                rows_batch.append(structured_feature_dict(example.structured))
                texts_batch.append(_hierarchical_text(example, top_k_chunks=3))
                train_labels.append(int(example.threat_positive or 0))
                processed_examples += 1
                if len(rows_batch) < structured_batch_size:
                    continue
                structured_blocks.append(
                    hstack(
                        [
                            dict_vectorizer.transform(rows_batch),
                            text_vectorizer.transform(texts_batch),
                        ],
                        format="csr",
                    ).astype("float32")
                )
                with progress_lock:
                    structured_vectorize_records_seen = processed_examples
                rows_batch = []
                texts_batch = []
                if processed_examples <= structured_batch_size or processed_examples % structured_batch_size == 0:
                    _write_json(
                        checkpoint_root / "state.json",
                        {
                            "phase": "structured_vectorize",
                            "processedBatches": processed_batches,
                            "structuredVectorizeRecordsSeen": structured_vectorize_records_seen,
                        },
                    )
                    report_sentinel_progress(state="running", phase="structured_vectorize")
            if rows_batch:
                structured_blocks.append(
                    hstack(
                        [
                            dict_vectorizer.transform(rows_batch),
                            text_vectorizer.transform(texts_batch),
                        ],
                        format="csr",
                    ).astype("float32")
                )
                with progress_lock:
                    structured_vectorize_records_seen = processed_examples
                _write_json(
                    checkpoint_root / "state.json",
                    {
                        "phase": "structured_vectorize",
                        "processedBatches": processed_batches,
                        "structuredVectorizeRecordsSeen": structured_vectorize_records_seen,
                    },
                )
                report_sentinel_progress(state="running", phase="structured_vectorize")
            if not structured_blocks:
                raise RuntimeError("Structured sentinel received no train examples.")
            structured_matrix = vstack(structured_blocks, format="csr").astype("float32")
            if processed_examples != len(train_labels):
                raise RuntimeError(
                    f"Structured sentinel row/label mismatch: rows={processed_examples} labels={len(train_labels)}."
                )
            with progress_lock:
                structured_phase = "structured_train"
                structured_vectorize_records_seen = processed_examples
            _write_json(
                checkpoint_root / "state.json",
                {
                    "phase": "structured_train",
                    "processedBatches": processed_batches,
                    "structuredVectorizeRecordsSeen": structured_vectorize_records_seen,
                },
            )
            report_sentinel_progress(state="running", phase="structured_train", include_throughput=False)
            structured_classifier = SGDClassifier(loss="log_loss", alpha=1e-5, random_state=_DEFAULT_RANDOM_SEED)
            structured_backend = "sgd_binary_fallback"
            structured_classifier.fit(structured_matrix, train_labels)

        return {
            "dict_vectorizer": dict_vectorizer,
            "text_vectorizer": text_vectorizer,
            "classifier": structured_classifier.save_raw(raw_format="json")
            if structured_backend.startswith("xgboost_binary")
            else structured_classifier,
            "backend": structured_backend,
            "train_device": train_device if structured_backend.startswith("xgboost_binary") else "cpu",
            "inference_device": "cpu",
        }

    _save_status(
        progress_output_path,
        {
            "currentStep": "train_recipe" if progress_root is not None else "train_sentinel",
            "currentStage": "phase_1_ml_sentinel",
            "state": "running",
            "resume": resume,
            "startedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        },
    )
    _mlflow_set_tags(
        {
            "model_guard.current_stage": "phase_1_ml_sentinel",
            "model_guard.recipe_mode": recipe_mode,
        }
    )
    _append_jsonl(
        events_path,
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "type": "stage_started",
            "stage": "phase_1_ml_sentinel",
            "resume": resume,
        },
    )
    _maybe_report("starting phase_1_ml_sentinel dual sentinel training", run_log_path=run_log_path)
    char_vectorizer = HashingVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 6),
        n_features=2**18,
        alternate_sign=False,
        norm="l2",
    )
    word_vectorizer = HashingVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        n_features=2**16,
        alternate_sign=False,
        norm="l2",
    )
    lexical_classifier = SGDClassifier(loss="log_loss", alpha=1e-5, random_state=_DEFAULT_RANDOM_SEED)
    fit_started = False
    if resume and state_path.is_file() and (checkpoint_root / "lexical.pkl").is_file():
        lexical_payload = load_pickle(checkpoint_root / "lexical.pkl")
        char_vectorizer = lexical_payload["char_vectorizer"]
        word_vectorizer = lexical_payload["word_vectorizer"]
        lexical_classifier = lexical_payload["classifier"]
        processed_batches = int(resume_state.get("processedBatches", 0))
        fit_started = processed_batches > 0
    partial_records_seen = processed_batches * lexical_batch_size
    structured_future_executor = ThreadPoolExecutor(max_workers=1)
    structured_future = structured_future_executor.submit(train_structured_sentinel)
    if not direct_structured_resume:
        report_sentinel_progress(state="running", phase="lexical", include_throughput=not (resume and processed_batches > 0))

    texts: list[str] = []
    labels: list[int] = []
    lexical_skip = processed_batches * lexical_batch_size
    for example_index, example in enumerate(
        _iter_examples(manifest_path, "train", data_root=data_root, limit=limit, skip=lexical_skip),
        start=lexical_skip,
    ):
        texts.append(example.text)
        labels.append(int(example.threat_positive or 0))
        partial_records_seen = example_index + 1
        now_monotonic = time.perf_counter()
        if now_monotonic - last_progress_report_monotonic >= progress_heartbeat_seconds:
            report_sentinel_progress(state="running", phase="lexical")
            last_progress_report_monotonic = now_monotonic
        if len(texts) < lexical_batch_size:
            continue
        batch_index = example_index // lexical_batch_size
        matrix = hstack([char_vectorizer.transform(texts), word_vectorizer.transform(texts)], format="csr")
        lexical_classifier.partial_fit(matrix, labels, classes=[0, 1] if not fit_started else None)
        fit_started = True
        processed_batches = batch_index + 1
        partial_records_seen = processed_batches * lexical_batch_size
        texts = []
        labels = []
        if processed_batches in bootstrap_report_batches or processed_batches % max(1, checkpoint_batches) == 0:
            checkpoint_root.mkdir(parents=True, exist_ok=True)
            write_pickle(
                checkpoint_root / "lexical.pkl",
                {
                    "char_vectorizer": char_vectorizer,
                    "word_vectorizer": word_vectorizer,
                    "classifier": lexical_classifier,
                },
            )
            _write_json(checkpoint_root / "state.json", {"phase": "lexical", "processedBatches": processed_batches})
            report_sentinel_progress(state="running", phase="lexical")
            last_progress_report_monotonic = now_monotonic
        elif now_monotonic - last_progress_report_monotonic >= progress_heartbeat_seconds:
            report_sentinel_progress(state="running", phase="lexical")
            last_progress_report_monotonic = now_monotonic
    if texts:
        matrix = hstack([char_vectorizer.transform(texts), word_vectorizer.transform(texts)], format="csr")
        lexical_classifier.partial_fit(matrix, labels, classes=[0, 1] if not fit_started else None)
        processed_batches += 1
        partial_records_seen = min(total_train_examples, processed_batches * lexical_batch_size)
        checkpoint_root.mkdir(parents=True, exist_ok=True)
        write_pickle(
            checkpoint_root / "lexical.pkl",
            {
                "char_vectorizer": char_vectorizer,
                "word_vectorizer": word_vectorizer,
                "classifier": lexical_classifier,
            },
        )
        _write_json(checkpoint_root / "state.json", {"phase": "lexical", "processedBatches": processed_batches})
        report_sentinel_progress(state="running", phase="lexical")

    lexical_artifact = {
        "char_vectorizer": char_vectorizer,
        "word_vectorizer": word_vectorizer,
        "classifier": lexical_classifier,
        "backend": "hashing_sgd_log_loss",
    }
    write_pickle(checkpoint_root / "lexical.pkl", lexical_artifact)
    if not direct_structured_resume:
        _write_json(checkpoint_root / "state.json", {"phase": "lexical_complete", "processedBatches": processed_batches})
    if not direct_structured_resume:
        report_sentinel_progress(state="running", phase="structured_vocab", include_throughput=False)
    structured_artifact = structured_future.result()
    structured_future_executor.shutdown(wait=True)
    _maybe_report(
        f"[sentinel:structured] backend={structured_artifact['backend']} "
        f"train_device={structured_artifact.get('train_device', 'cpu')}",
        run_log_path=run_log_path,
    )
    write_pickle(checkpoint_root / "structured.pkl", structured_artifact)
    sentinel_artifact = {"lexical": lexical_artifact, "structured": structured_artifact}
    with progress_lock:
        structured_phase = "threshold_tuning"
        threshold_records_seen = 0
    update_threshold_progress(threshold_records_seen)
    tuned_threshold, tuned_recall = choose_threat_threshold_with_resume(sentinel_artifact)
    sentinel_artifact["threshold"] = max(tuned_threshold, threat_threshold)
    sentinel_artifact["thresholdRecall"] = tuned_recall
    artifact_path = write_pickle(output_path / "sentinel.pkl", sentinel_artifact)
    with progress_lock:
        structured_phase = "complete"
        threshold_records_seen = total_valid_examples
    _write_json(checkpoint_root / "state.json", {"phase": "complete", "processedBatches": processed_batches, "threshold": sentinel_artifact["threshold"]})
    if threshold_cache_path.exists():
        threshold_cache_path.unlink()

    summary = {
        "artifact": str(artifact_path),
        "backend": "dual_ml_sentinel",
        "lexicalBackend": lexical_artifact["backend"],
        "structuredBackend": structured_artifact["backend"],
        "threshold": float(sentinel_artifact["threshold"]),
        "thresholdRecall": float(tuned_recall),
        "examples": total_train_examples,
        "batches": processed_batches,
        "batchSize": lexical_batch_size,
        "recipeMode": recipe_mode,
        "checkpointDir": str(checkpoint_root),
    }
    _write_json(output_path / "summary.json", summary)
    _mlflow_log_dict(summary, "summaries/sentinel_summary.json")
    _save_status(
        progress_output_path,
        {
            "currentStep": "train_recipe" if progress_root is not None else "train_sentinel",
            "currentStage": "phase_1_ml_sentinel",
            "state": "completed",
            "resume": resume,
        },
    )
    _append_jsonl(
        events_path,
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "type": "stage_completed",
            "stage": "phase_1_ml_sentinel",
            "threshold": summary["threshold"],
            "thresholdRecall": summary["thresholdRecall"],
            "structuredBackend": summary["structuredBackend"],
        },
    )
    report_sentinel_progress(
        state="completed",
        phase="complete",
        threshold=summary["threshold"],
        threshold_recall=summary["thresholdRecall"],
    )
    return summary


def _build_metadata_vocab(
    dataset_root: Path,
    index_records: list[IndexedRecord],
    selected_indices: list[int],
) -> dict[str, dict[str, int]]:
    vocab = {field: {"unknown": 0} for field in RECIPE_CATEGORICAL_FIELDS}
    seen = set[int]()
    for record_index in selected_indices:
        if record_index in seen:
            continue
        seen.add(record_index)
        example = example_from_dataset_row(_read_record_by_index(dataset_root, index_records, record_index))
        values = recipe_categorical_values(example)
        for field in RECIPE_CATEGORICAL_FIELDS:
            value = values.get(field, "unknown")
            if value not in vocab[field]:
                vocab[field][value] = len(vocab[field])
    return vocab


def _build_stage_state_payload(
    *,
    stage_name: str | None,
    records_seen: int,
    micro_batches_seen: int,
    optimizer_steps: int,
    total_target_records: int,
    batch_size: int,
    gradient_accumulation_steps: int,
    top_k_chunks: int,
    max_length: int,
    latest_loss: float,
    moving_average_loss: float,
    last_checkpoint_path: str | None,
    state: str,
    mean_confidence: float | None = None,
    gradient_norm: float | None = None,
    label_entropy: float | None = None,
    examples_per_second: float | None = None,
    batches_per_second: float | None = None,
    consecutive_nonfinite_gradients: int | None = None,
    current_label_counts: dict[str, int] | None = None,
    last_batch_build_seconds: float | None = None,
    moving_average_batch_build_seconds: float | None = None,
    last_optimizer_step_seconds: float | None = None,
    moving_average_optimizer_step_seconds: float | None = None,
    last_checkpoint_write_seconds: float | None = None,
    gpu_memory_allocated_mb: float | None = None,
    gpu_memory_reserved_mb: float | None = None,
) -> dict[str, Any]:
    payload = {
        "stageName": stage_name,
        "currentStage": stage_name,
        "recordsSeen": records_seen,
        "microBatchesSeen": micro_batches_seen,
        "optimizerStep": optimizer_steps,
        "totalTargetRecords": total_target_records,
        "batchSize": batch_size,
        "gradientAccumulationSteps": gradient_accumulation_steps,
        "topKChunks": top_k_chunks,
        "maxLength": max_length,
        "latestLoss": latest_loss,
        "movingAverageLoss": moving_average_loss,
        "lastCheckpointPath": last_checkpoint_path,
        "lastCheckpointAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) if last_checkpoint_path else None,
        "progressFraction": (records_seen / total_target_records) if total_target_records else None,
        "state": state,
    }
    if mean_confidence is not None:
        payload["meanConfidence"] = mean_confidence
    if gradient_norm is not None:
        payload["gradientNorm"] = gradient_norm
    if label_entropy is not None:
        payload["labelEntropy"] = label_entropy
    if examples_per_second is not None:
        payload["examplesPerSecond"] = examples_per_second
    if batches_per_second is not None:
        payload["batchesPerSecond"] = batches_per_second
    if consecutive_nonfinite_gradients is not None:
        payload["consecutiveNonfiniteGradients"] = consecutive_nonfinite_gradients
    if current_label_counts is not None:
        payload["currentLabelCounts"] = current_label_counts
    if last_batch_build_seconds is not None:
        payload["lastBatchBuildSeconds"] = last_batch_build_seconds
    if moving_average_batch_build_seconds is not None:
        payload["movingAverageBatchBuildSeconds"] = moving_average_batch_build_seconds
    if last_optimizer_step_seconds is not None:
        payload["lastOptimizerStepSeconds"] = last_optimizer_step_seconds
    if moving_average_optimizer_step_seconds is not None:
        payload["movingAverageOptimizerStepSeconds"] = moving_average_optimizer_step_seconds
    if last_checkpoint_write_seconds is not None:
        payload["lastCheckpointWriteSeconds"] = last_checkpoint_write_seconds
    if gpu_memory_allocated_mb is not None:
        payload["gpuMemoryAllocatedMb"] = gpu_memory_allocated_mb
    if gpu_memory_reserved_mb is not None:
        payload["gpuMemoryReservedMb"] = gpu_memory_reserved_mb
    return payload


def _hash_index_plan(indices: list[int]) -> str:
    digest = hashlib.sha256()
    for value in indices:
        digest.update(f"{value}\n".encode("utf-8"))
    return digest.hexdigest()


def _load_checkpoint_state(checkpoint_dir: Path) -> tuple[dict[str, Any], Path] | None:
    latest_state_path = checkpoint_dir / "active" / "latest" / "state.json"
    if latest_state_path.is_file():
        return _load_json(latest_state_path), latest_state_path.parent
    milestone_root = checkpoint_dir / "active" / "milestones"
    if not milestone_root.is_dir():
        return None
    state_paths = sorted(milestone_root.glob("step-*/state.json"))
    if not state_paths:
        return None
    newest = state_paths[-1]
    return _load_json(newest), newest.parent


def _replay_checkpoint_payload(
    *,
    records_seen: int,
    total_target_records: int,
    selected_indices_hash: str,
    hard_negative_indices: list[int],
) -> dict[str, Any]:
    return {
        "schemaVersion": "hard_negative_replay_v1",
        "recordsSeen": records_seen,
        "totalTargetRecords": total_target_records,
        "selectedIndicesHash": selected_indices_hash,
        "hardNegativeIndices": hard_negative_indices,
    }


def _load_stacker_chunk_payloads(
    chunks_dir: Path,
    *,
    committed_rows: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    feature_rows: list[dict[str, Any]] = []
    labels: list[str] = []
    if committed_rows <= 0 or not chunks_dir.is_dir():
        return feature_rows, labels
    for chunk_path in sorted(chunks_dir.glob("chunk-*.pkl.gz")):
        payload = _load_pickle_gz(chunk_path)
        end_row = int(payload.get("endRow", 0))
        if end_row > committed_rows:
            continue
        feature_rows.extend(payload.get("featureRows", []))
        labels.extend(payload.get("labels", []))
    return feature_rows, labels


def _write_stacker_chunk(
    chunks_dir: Path,
    *,
    start_row: int,
    feature_rows: list[dict[str, Any]],
    labels: list[str],
) -> Path:
    end_row = start_row + len(feature_rows) - 1
    target = chunks_dir / f"chunk-{end_row:07d}.pkl.gz"
    payload = {
        "startRow": start_row,
        "endRow": end_row,
        "featureRows": feature_rows,
        "labels": labels,
    }
    return _write_pickle_gz(target, payload)


def _stacker_checkpoint_payload(
    *,
    records_seen: int,
    total_target_records: int,
    committed_rows: int,
    chunk_rows: int,
    feature_row_count: int,
) -> dict[str, Any]:
    return {
        "schemaVersion": "stacker_cache_v1",
        "recordsSeen": records_seen,
        "totalTargetRecords": total_target_records,
        "committedRows": committed_rows,
        "chunkRows": chunk_rows,
        "stackerFeatureRows": feature_row_count,
    }


def _load_rng_state(path: Path, *, torch_module: Any) -> None:
    if not path.is_file():
        return
    payload = torch_module.load(path, map_location="cpu")
    random.setstate(payload["python"])
    torch_module.set_rng_state(payload["torch"])
    if torch_module.cuda.is_available() and payload.get("cuda"):
        torch_module.cuda.set_rng_state_all(payload["cuda"])


def _load_stage_checkpoint(stage_dir: Path, *, device: Any, torch_module: Any) -> dict[str, Any] | None:
    latest_dir = stage_dir / "active" / "latest"
    if not latest_dir.is_dir():
        return None
    state = _load_json(latest_dir / "state.json")
    model, tokenizer, config, metadata_vocab = load_recipe_expert_artifact(latest_dir / "expert", device=device)
    optimizer_state = torch_module.load(latest_dir / "optimizer.pt", map_location=device) if (latest_dir / "optimizer.pt").is_file() else None
    scaler_state = torch_module.load(latest_dir / "scaler.pt", map_location=device) if (latest_dir / "scaler.pt").is_file() else None
    _load_rng_state(latest_dir / "rng.pt", torch_module=torch_module)
    return {
        "model": model,
        "tokenizer": tokenizer,
        "config": config,
        "metadata_vocab": metadata_vocab,
        "state": state,
        "optimizer_state": optimizer_state,
        "scaler_state": scaler_state,
        "hash": _load_json(latest_dir / "manifest.json").get("hash"),
    }


def _train_smoke_expert(
    manifest_path: str | Path,
    *,
    output_dir: str | Path,
    data_root: str | Path | None = None,
    limit: int | None = None,
    backbone: str,
    top_k_chunks: int,
    selected_indices: list[int] | None = None,
    index_records: list[IndexedRecord] | None = None,
    stage_name: str | None = None,
    sentinel_artifact: dict[str, Any] | None = None,
    progress_root: str | Path | None = None,
) -> dict[str, Any]:
    deps = _require_training_dependencies()
    DictVectorizer = deps["DictVectorizer"]
    TfidfVectorizer = deps["TfidfVectorizer"]
    SGDClassifier = deps["SGDClassifier"]
    hstack = deps["hstack"]

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    progress_output_path = Path(progress_root) if progress_root is not None else output_path
    if index_records is None:
        index_records = _build_index(manifest_path, "train", data_root=data_root, limit=limit)
    if selected_indices is None:
        selected_indices = list(range(len(index_records)))
    dataset_root = _dataset_root_for_manifest(manifest_path, data_root=data_root)
    if not selected_indices:
        raise RuntimeError("Expert training plan is empty; no train examples were indexed for the requested split.")

    text_vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=120_000)
    dict_vectorizer = DictVectorizer(sparse=True)
    classifier = SGDClassifier(loss="log_loss", alpha=1e-5, random_state=_DEFAULT_RANDOM_SEED)
    texts: list[str] = []
    rows: list[dict[str, Any]] = []
    labels: list[str] = []
    for example in _iter_examples_from_index_plan(dataset_root, index_records, selected_indices):
        sentinel_probability = _score_dual_sentinel_artifact(sentinel_artifact, example)["max"] if sentinel_artifact else 0.0
        texts.append(_hierarchical_text(example, top_k_chunks=top_k_chunks, sentinel_probability=sentinel_probability))
        row = structured_feature_dict(example.structured)
        row["sentinel_probability"] = sentinel_probability
        rows.append(row)
        labels.append(example.decision_label or "allow_read_only")

    _save_status(
        progress_output_path,
        {
            "currentStep": "train_recipe" if progress_root is not None else "train_expert",
            "currentStage": stage_name,
            "state": "running",
            "resume": False,
            "startedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        },
    )

    matrix = hstack([dict_vectorizer.fit_transform(rows), text_vectorizer.fit_transform(texts)], format="csr")
    classifier.fit(matrix, labels)
    artifact_path = write_pickle(
        output_path / "expert.pkl",
        {
            "dict_vectorizer": dict_vectorizer,
            "text_vectorizer": text_vectorizer,
            "classifier": classifier,
            "label_order": list(getattr(classifier, "classes_", sorted(set(labels)))),
            "intended_backbone": backbone,
            "top_k_chunks": top_k_chunks,
        },
    )
    summary = {
        "artifact": str(artifact_path),
        "backend": "recipe_hierarchical_smoke",
        "examples": len(labels),
        "intendedBackbone": backbone,
        "topKChunks": top_k_chunks,
        "stageName": stage_name,
        "peftMethod": "smoke",
        "aggregation": "transformer_encoder_summary_token",
        "metadataFusion": True,
        "heads": ["decision", "binaryThreat", "reason", "embedding"],
        "pooledEmbeddingDim": 128,
        "finalCheckpointPath": None,
        "finalCheckpointHash": None,
        "retentionOutcome": "none_smoke_backend",
    }
    _write_json(output_path / "summary.json", summary)
    _save_progress(
        progress_output_path,
        {
            "currentStage": stage_name,
            "optimizerStep": 1,
            "recordsSeen": len(labels),
            "totalTargetRecords": len(labels),
            "lastCheckpointPath": None,
            "lastCheckpointAt": None,
            "state": "completed",
            "progressFraction": 1.0 if labels else None,
        },
    )
    _save_status(
        progress_output_path,
        {
            "currentStep": "train_recipe" if progress_root is not None else "train_expert",
            "currentStage": stage_name,
            "state": "completed",
            "resume": False,
        },
    )
    return summary


def _should_write_latest(step: int, latest_interval: int) -> bool:
    return step in _BOOTSTRAP_CHECKPOINT_STEPS or step % max(1, latest_interval) == 0


def _label_entropy(batch_labels: list[int]) -> float:
    total = len(batch_labels) or 1
    counts = Counter(batch_labels)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log(probability + 1e-12)
    return entropy


def _degenerate_signal(
    *,
    optimizer_step: int,
    moving_average_loss: float,
    gradient_norm: float,
    label_entropy: float,
) -> bool:
    return optimizer_step >= 25 and moving_average_loss < 1e-8 and gradient_norm < 1e-8 and label_entropy > 0.1


def _score_recipe_expert_artifact(expert_dir: str | Path, example: Any, sentinel_artifact: dict[str, Any] | None = None) -> dict[str, Any]:
    deps = _require_transformer_dependencies()
    torch = deps["torch"]

    summary = _load_json(Path(expert_dir) / "summary.json")
    backend = str(summary.get("backend"))
    if backend == "recipe_hierarchical_smoke":
        artifact = load_pickle(Path(expert_dir) / "expert.pkl")
        dict_vectorizer = artifact["dict_vectorizer"]
        text_vectorizer = artifact["text_vectorizer"]
        classifier = artifact["classifier"]
        label_order = artifact["label_order"]
        sentinel_probability = _score_dual_sentinel_artifact(sentinel_artifact, example)["max"] if sentinel_artifact else 0.0
        matrix = _require_training_dependencies()["hstack"](
            [
                dict_vectorizer.transform([structured_feature_dict(example.structured) | {"sentinel_probability": sentinel_probability}]),
                text_vectorizer.transform([_hierarchical_text(example, top_k_chunks=int(summary.get("topKChunks", 3)), sentinel_probability=sentinel_probability)]),
            ],
            format="csr",
        )
        raw = classifier.decision_function(matrix)
        if hasattr(raw, "tolist"):
            raw = raw.tolist()
        logits = [float(value) for value in (raw[0] if isinstance(raw[0], list) else raw)]
        probabilities = softmax({label_order[index]: logits[index] for index in range(len(label_order))})
        dense = matrix.toarray()[0]
        pooled = [float(value) for value in dense[:128]]
        if len(pooled) < 128:
            pooled.extend([0.0] * (128 - len(pooled)))
        return {"probabilities": probabilities, "logits": logits[: len(LABEL_TO_ID)], "pooledEmbedding": pooled}

    cache_key = str((Path(expert_dir) / "release" / "expert").resolve())
    cached = _TRANSFORMER_ARTIFACT_CACHE.get(cache_key)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if cached is None:
        model, tokenizer, config, metadata_vocab = load_recipe_expert_artifact(Path(expert_dir) / "release" / "expert", device=device)
        cached = {"model": model, "tokenizer": tokenizer, "config": config, "metadata_vocab": metadata_vocab}
        _TRANSFORMER_ARTIFACT_CACHE[cache_key] = cached

    model = cached["model"]
    tokenizer = cached["tokenizer"]
    config = cached["config"]
    metadata_vocab = cached["metadata_vocab"]
    sentinel_probability = _score_dual_sentinel_artifact(sentinel_artifact, example)["max"] if sentinel_artifact else 0.0
    chunks = _top_ranked_chunks(example, top_k_chunks=int(config.top_k_chunks), sentinel_probability=sentinel_probability)
    if len(chunks) < int(config.top_k_chunks):
        chunks = chunks + [chunks[-1]] * (int(config.top_k_chunks) - len(chunks))
    encoded = tokenizer(chunks, truncation=True, padding=True, max_length=int(config.max_length), return_tensors="pt")
    encoded = {key: value.to(device) for key, value in encoded.items()}
    metadata_categorical = torch.tensor([encode_recipe_categorical(example, metadata_vocab)], dtype=torch.long, device=device)
    metadata_numeric = torch.tensor([encode_recipe_numeric(example)], dtype=torch.float32, device=device)
    with torch.no_grad():
        outputs = model(
            input_ids=encoded["input_ids"],
            attention_mask=encoded["attention_mask"],
            metadata_categorical=metadata_categorical,
            metadata_numeric=metadata_numeric,
        )
        logits = outputs["decision_logits"][0].detach().cpu().tolist()
        probabilities = softmax({label: float(logits[index]) for label, index in LABEL_TO_ID.items()})
        pooled = outputs["pooled_embedding"][0].detach().cpu().tolist()
    return {"probabilities": probabilities, "logits": logits, "pooledEmbedding": pooled}


def train_expert(
    manifest_path: str | Path,
    *,
    output_dir: str | Path,
    data_root: str | Path | None = None,
    limit: int | None = None,
    backbone: str = "answerdotai/ModernBERT-base",
    backend: str = "transformers",
    max_length: int = 1024,
    top_k_chunks: int = 3,
    epochs: float = 1.0,
    batch_size: int = 1,
    gradient_accumulation_steps: int = 1,
    learning_rate: float = 2e-5,
    selected_indices: list[int] | None = None,
    index_records: list[IndexedRecord] | None = None,
    checkpoint_dir: str | Path | None = None,
    checkpoint_steps: int = _DEFAULT_LATEST_CHECKPOINT_STEPS,
    milestone_checkpoint_steps: int = _DEFAULT_MILESTONE_CHECKPOINT_STEPS,
    resume: bool = False,
    stage_name: str | None = None,
    sentinel_dir: str | Path | None = None,
    use_dora: bool = False,
    progress_root: str | Path | None = None,
    max_optimizer_steps: int | None = None,
) -> dict[str, Any]:
    if backend == "smoke":
        sentinel_artifact = load_pickle(Path(sentinel_dir) / "sentinel.pkl") if sentinel_dir else None
        return _train_smoke_expert(
            manifest_path,
            output_dir=output_dir,
            data_root=data_root,
            limit=limit,
            backbone=backbone,
            top_k_chunks=top_k_chunks,
            selected_indices=selected_indices,
            index_records=index_records,
            stage_name=stage_name,
            sentinel_artifact=sentinel_artifact,
            progress_root=progress_root,
        )

    transform_deps = _require_transformer_dependencies()
    torch = transform_deps["torch"]
    GradScaler = transform_deps["GradScaler"]
    AutoTokenizer = transform_deps["AutoTokenizer"]
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    progress_output_path = Path(progress_root) if progress_root is not None else output_path.parent

    sentinel_artifact = load_pickle(Path(sentinel_dir) / "sentinel.pkl") if sentinel_dir else None
    if index_records is None:
        index_records = _build_index(manifest_path, "train", data_root=data_root, limit=limit)
    if selected_indices is None:
        selected_indices = list(range(len(index_records)))
    dataset_root = _dataset_root_for_manifest(manifest_path, data_root=data_root)
    total_plan_entries = len(selected_indices)
    if total_plan_entries == 0:
        raise RuntimeError("Expert training plan is empty; no train examples were indexed for the requested split.")
    total_target_records = max(1, int(math.ceil(total_plan_entries * epochs)))
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    autocast_dtype = None
    use_grad_scaler = False
    if device.type == "cuda":
        autocast_dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
        use_grad_scaler = autocast_dtype == torch.float16
    scaler = GradScaler(device.type, enabled=use_grad_scaler)

    checkpoint = _load_stage_checkpoint(output_path, device=device, torch_module=torch) if resume else None
    if checkpoint is not None:
        model = checkpoint["model"]
        tokenizer = checkpoint["tokenizer"]
        config = checkpoint["config"]
        metadata_vocab = checkpoint["metadata_vocab"]
        start_records_seen = int(checkpoint["state"].get("recordsSeen", 0))
        optimizer_steps = int(checkpoint["state"].get("optimizerStep", 0))
        micro_batches_seen = int(checkpoint["state"].get("microBatchesSeen", 0))
        total_loss = float(checkpoint["state"].get("movingAverageLoss", 0.0)) * max(1, micro_batches_seen)
        optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)
        if checkpoint["optimizer_state"] is not None:
            optimizer.load_state_dict(checkpoint["optimizer_state"])
        if checkpoint["scaler_state"] is not None:
            scaler.load_state_dict(checkpoint["scaler_state"])
    else:
        tokenizer = AutoTokenizer.from_pretrained(backbone)
        encoder = build_recipe_expert_encoder(backbone, use_dora=use_dora, lora_rank=16, lora_alpha=32, lora_dropout=0.05)
        metadata_vocab = _build_metadata_vocab(dataset_root, index_records, selected_indices)
        config = RecipeExpertConfig(
            backbone=backbone,
            top_k_chunks=top_k_chunks,
            max_length=max_length,
            categorical_vocab_sizes={field: len(metadata_vocab[field]) for field in RECIPE_CATEGORICAL_FIELDS},
            use_dora=use_dora,
        )
        model = HierarchicalActionGuardModel(encoder=encoder, config=config)
        start_records_seen = 0
        optimizer_steps = 0
        micro_batches_seen = 0
        total_loss = 0.0
        optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)

    model.to(device)
    model.train()
    if hasattr(model.encoder, "gradient_checkpointing_enable"):
        model.encoder.gradient_checkpointing_enable()

    checkpoint_manager = ExpertCheckpointManager(
        stage_dir=output_path,
        tokenizer=tokenizer,
        config=config,
        metadata_vocab=metadata_vocab,
        latest_steps=checkpoint_steps,
        milestone_steps=milestone_checkpoint_steps,
    )

    def iter_training_records(start_position: int) -> Iterator[Any]:
        seen = 0
        while seen < total_target_records - start_position:
            plan_index = (start_position + seen) % total_plan_entries
            record_index = selected_indices[plan_index]
            yield example_from_dataset_row(_read_record_by_index(dataset_root, index_records, record_index))
            seen += 1

    def iter_batches(start_position: int) -> Iterator[tuple[int, list[Any]]]:
        current_examples: list[Any] = []
        records_consumed = start_position
        for example in iter_training_records(start_position):
            current_examples.append(example)
            records_consumed += 1
            if len(current_examples) >= batch_size:
                yield records_consumed, current_examples
                current_examples = []
        if current_examples:
            yield records_consumed, current_examples

    def build_batch(batch_examples: list[Any]) -> dict[str, Any]:
        chunk_texts: list[str] = []
        metadata_categorical: list[list[int]] = []
        metadata_numeric: list[list[float]] = []
        labels: list[int] = []
        threat_labels: list[float] = []
        reason_labels: list[list[float]] = []
        label_names: list[str] = []
        for example in batch_examples:
            sentinel_probability = _score_dual_sentinel_artifact(sentinel_artifact, example)["max"] if sentinel_artifact else 0.0
            chunks = _top_ranked_chunks(example, top_k_chunks=top_k_chunks, sentinel_probability=sentinel_probability)
            if len(chunks) < top_k_chunks:
                chunks = chunks + [chunks[-1]] * (top_k_chunks - len(chunks))
            chunk_texts.extend(chunks[:top_k_chunks])
            metadata_categorical.append(encode_recipe_categorical(example, metadata_vocab))
            metadata_numeric.append(encode_recipe_numeric(example))
            labels.append(LABEL_TO_ID[example.decision_label or "allow_read_only"])
            label_names.append(example.decision_label or "allow_read_only")
            threat_labels.append(float(example.threat_positive or 0))
            reason_labels.append(encode_recipe_reason_targets(example))
        encoded = tokenizer(chunk_texts, truncation=True, padding=True, max_length=max_length, return_tensors="pt")
        return {
            "input_ids": encoded["input_ids"].to(device),
            "attention_mask": encoded["attention_mask"].to(device),
            "metadata_categorical": torch.tensor(metadata_categorical, dtype=torch.long, device=device),
            "metadata_numeric": torch.tensor(metadata_numeric, dtype=torch.float32, device=device),
            "labels": torch.tensor(labels, dtype=torch.long, device=device),
            "threat_labels": torch.tensor(threat_labels, dtype=torch.float32, device=device),
            "reason_labels": torch.tensor(reason_labels, dtype=torch.float32, device=device),
            "label_names": label_names,
        }

    _save_status(
        progress_output_path,
        {
            "currentStep": "train_recipe" if stage_name else "train_expert",
            "currentStage": stage_name,
            "state": "running",
            "resume": resume,
            "startedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        },
    )
    stage_metric_prefix = f"expert.{_safe_stage_name(stage_name or 'default')}"
    run_log_path = progress_output_path / "run.log"
    _mlflow_set_tags(
        {
            "model_guard.current_stage": stage_name or "train_expert",
            "model_guard.expert_backbone": backbone,
            "model_guard.expert_backend": backend,
            "model_guard.peft_method": "dora" if use_dora else "lora",
        }
    )
    _save_progress(
        progress_output_path,
        _build_stage_state_payload(
            stage_name=stage_name,
            records_seen=start_records_seen,
            micro_batches_seen=micro_batches_seen,
            optimizer_steps=optimizer_steps,
            total_target_records=total_target_records,
            batch_size=batch_size,
            gradient_accumulation_steps=gradient_accumulation_steps,
            top_k_chunks=top_k_chunks,
            max_length=max_length,
            latest_loss=0.0,
            moving_average_loss=0.0,
            last_checkpoint_path=str(checkpoint_manager.latest_dir) if checkpoint_manager.latest_dir.exists() else None,
            state="running",
            consecutive_nonfinite_gradients=0,
        ),
    )
    _maybe_report(
        f"starting recipe expert training on {device} for {total_target_records} records "
        f"({total_plan_entries} plan entries, stage={stage_name or 'default'})",
        run_log_path=run_log_path,
    )

    optimizer.zero_grad(set_to_none=True)
    records_seen = start_records_seen
    accumulation_counter = 0
    last_reported_step = optimizer_steps
    recent_losses: deque[float] = deque(maxlen=25)
    recent_confidences: deque[float] = deque(maxlen=25)
    recent_batch_build_seconds: deque[float] = deque(maxlen=25)
    recent_optimizer_step_seconds: deque[float] = deque(maxlen=25)
    consecutive_nonfinite_gradients = 0
    training_started_monotonic = time.perf_counter()
    latest_checkpoint_write_seconds = 0.0
    paused_early = False

    for records_seen, batch_examples in iter_batches(start_records_seen):
        batch_build_started = time.perf_counter()
        batch = build_batch(batch_examples)
        batch_build_seconds = time.perf_counter() - batch_build_started
        recent_batch_build_seconds.append(batch_build_seconds)
        with torch.autocast(device_type=device.type, dtype=autocast_dtype, enabled=device.type == "cuda"):
            outputs = model(
                input_ids=batch["input_ids"],
                attention_mask=batch["attention_mask"],
                metadata_categorical=batch["metadata_categorical"],
                metadata_numeric=batch["metadata_numeric"],
                labels=batch["labels"],
                threat_labels=batch["threat_labels"],
                reason_labels=batch["reason_labels"],
            )
            loss = outputs["loss"]
        scaled_loss = loss / max(1, gradient_accumulation_steps)
        if device.type == "cuda":
            scaler.scale(scaled_loss).backward()
        else:
            scaled_loss.backward()
        raw_loss = float(loss.detach().cpu())
        total_loss += raw_loss
        micro_batches_seen += 1
        accumulation_counter += 1
        recent_losses.append(raw_loss)
        confidence = float(torch.softmax(outputs["decision_logits"], dim=-1).max(dim=-1).values.mean().detach().cpu())
        recent_confidences.append(confidence)

        should_step = accumulation_counter >= max(1, gradient_accumulation_steps) or records_seen >= total_target_records
        gradient_norm = 0.0
        if should_step:
            optimizer_step_started = time.perf_counter()
            if use_grad_scaler:
                scaler.unscale_(optimizer)
            for parameter in model.parameters():
                if parameter.grad is not None:
                    gradient_norm += float(parameter.grad.detach().data.norm(2).cpu()) ** 2
            gradient_norm = math.sqrt(gradient_norm)
            if not math.isfinite(gradient_norm):
                consecutive_nonfinite_gradients += 1
                if use_grad_scaler:
                    scaler.step(optimizer)
                    scaler.update()
                    optimizer.zero_grad(set_to_none=True)
                    accumulation_counter = 0
                    if consecutive_nonfinite_gradients == 1 or consecutive_nonfinite_gradients % 5 == 0:
                        _maybe_report(
                            f"non-finite gradients encountered in {stage_name or 'expert'} at optimizer_step {optimizer_steps + 1}; allowing GradScaler recovery ({consecutive_nonfinite_gradients} consecutive)",
                            run_log_path=run_log_path,
                        )
                    if consecutive_nonfinite_gradients >= 10:
                        raise RuntimeError(
                            f"Non-finite gradients persisted in {stage_name or 'expert'} for {consecutive_nonfinite_gradients} consecutive optimizer steps."
                        )
                    continue
                raise RuntimeError(
                    f"Non-finite gradient norm detected in {stage_name or 'expert'} at optimizer_step {optimizer_steps + 1}."
                )
            consecutive_nonfinite_gradients = 0
            if _degenerate_signal(
                optimizer_step=optimizer_steps + 1,
                moving_average_loss=sum(recent_losses) / max(1, len(recent_losses)),
                gradient_norm=gradient_norm,
                label_entropy=_label_entropy([LABEL_TO_ID[label] for label in batch["label_names"]]),
            ):
                raise RuntimeError(
                    f"Degenerate training signal detected in {stage_name or 'expert'}: "
                    f"moving_avg_loss={sum(recent_losses) / max(1, len(recent_losses)):.10f}, "
                    f"gradient_norm={gradient_norm:.10f}"
                )
            if use_grad_scaler:
                scaler.step(optimizer)
                scaler.update()
            else:
                optimizer.step()
            optimizer.zero_grad(set_to_none=True)
            optimizer_steps += 1
            accumulation_counter = 0

            moving_average_loss = sum(recent_losses) / max(1, len(recent_losses))
            current_label_counts = dict(Counter(batch["label_names"]))
            current_label_entropy = _label_entropy([LABEL_TO_ID[label] for label in batch["label_names"]])
            elapsed_seconds = max(time.perf_counter() - training_started_monotonic, 1e-9)
            optimizer_step_seconds = time.perf_counter() - optimizer_step_started
            recent_optimizer_step_seconds.append(optimizer_step_seconds)
            gpu_memory_allocated_mb = None
            gpu_memory_reserved_mb = None
            if device.type == "cuda":
                gpu_memory_allocated_mb = float(torch.cuda.memory_allocated(device) / (1024 * 1024))
                gpu_memory_reserved_mb = float(torch.cuda.memory_reserved(device) / (1024 * 1024))
            state_payload = _build_stage_state_payload(
                stage_name=stage_name,
                records_seen=records_seen,
                micro_batches_seen=micro_batches_seen,
                optimizer_steps=optimizer_steps,
                total_target_records=total_target_records,
                batch_size=batch_size,
                gradient_accumulation_steps=gradient_accumulation_steps,
                top_k_chunks=top_k_chunks,
                max_length=max_length,
                latest_loss=raw_loss,
                moving_average_loss=moving_average_loss,
                last_checkpoint_path=str(checkpoint_manager.latest_dir),
                state="running",
                mean_confidence=sum(recent_confidences) / max(1, len(recent_confidences)),
                gradient_norm=gradient_norm,
                label_entropy=current_label_entropy,
                examples_per_second=records_seen / elapsed_seconds if records_seen else 0.0,
                batches_per_second=optimizer_steps / elapsed_seconds if optimizer_steps else 0.0,
                consecutive_nonfinite_gradients=consecutive_nonfinite_gradients,
                current_label_counts=current_label_counts,
                last_batch_build_seconds=batch_build_seconds,
                moving_average_batch_build_seconds=sum(recent_batch_build_seconds) / max(1, len(recent_batch_build_seconds)),
                last_optimizer_step_seconds=optimizer_step_seconds,
                moving_average_optimizer_step_seconds=sum(recent_optimizer_step_seconds) / max(1, len(recent_optimizer_step_seconds)),
                last_checkpoint_write_seconds=latest_checkpoint_write_seconds if latest_checkpoint_write_seconds > 0 else None,
                gpu_memory_allocated_mb=gpu_memory_allocated_mb,
                gpu_memory_reserved_mb=gpu_memory_reserved_mb,
            )
            if _should_write_latest(optimizer_steps, checkpoint_steps):
                checkpoint_write_started = time.perf_counter()
                checkpoint_hash = checkpoint_manager.save_resume_checkpoint(
                    model=model,
                    torch_module=torch,
                    state_payload=state_payload,
                    optimizer=optimizer,
                    scaler=scaler if use_grad_scaler else None,
                )
                latest_checkpoint_write_seconds = time.perf_counter() - checkpoint_write_started
                state_payload["lastCheckpointWriteSeconds"] = latest_checkpoint_write_seconds
                _save_progress(progress_output_path, state_payload | {"lastCheckpointHash": checkpoint_hash})
                _mlflow_log_metrics(
                    {
                        f"{stage_metric_prefix}.records_seen": records_seen,
                        f"{stage_metric_prefix}.target_records": total_target_records,
                        f"{stage_metric_prefix}.optimizer_step": optimizer_steps,
                        f"{stage_metric_prefix}.latest_loss": raw_loss,
                        f"{stage_metric_prefix}.moving_average_loss": moving_average_loss,
                        f"{stage_metric_prefix}.mean_confidence": sum(recent_confidences) / max(1, len(recent_confidences)),
                        f"{stage_metric_prefix}.gradient_norm": gradient_norm,
                        f"{stage_metric_prefix}.progress_fraction": state_payload.get("progressFraction"),
                        f"{stage_metric_prefix}.consecutive_nonfinite_gradients": consecutive_nonfinite_gradients,
                        f"{stage_metric_prefix}.batch_build_seconds": batch_build_seconds,
                        f"{stage_metric_prefix}.optimizer_step_seconds": optimizer_step_seconds,
                        f"{stage_metric_prefix}.checkpoint_write_seconds": latest_checkpoint_write_seconds,
                    },
                    step=optimizer_steps,
                )
            if optimizer_steps % checkpoint_manager.milestone_steps == 0:
                checkpoint_manager.save_milestone(model=model, torch_module=torch, state_payload=state_payload)
            if max_optimizer_steps is not None and optimizer_steps >= max_optimizer_steps and records_seen < total_target_records:
                paused_early = True
                _save_status(
                    progress_output_path,
                    {
                        "currentStep": "train_recipe" if stage_name else "train_expert",
                        "currentStage": stage_name,
                        "state": "paused",
                        "resume": True,
                        "startedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    },
                )
                _save_progress(progress_output_path, state_payload | {"state": "paused"})
                break

        if optimizer_steps == 1 or optimizer_steps % 25 == 0:
            if optimizer_steps != last_reported_step:
                moving_average_loss = sum(recent_losses) / max(1, len(recent_losses))
                _maybe_report(
                    (
                        f"stage {stage_name or 'default'}, optimizer_step {optimizer_steps}, "
                        f"records {records_seen}/{total_target_records}, "
                        f"last_loss={raw_loss:.8f}, moving_avg_loss={moving_average_loss:.8f}, "
                        f"mean_confidence={sum(recent_confidences) / max(1, len(recent_confidences)):.6f}, "
                        f"gradient_norm={gradient_norm:.6f}"
                    ),
                    run_log_path=run_log_path,
                )
                last_reported_step = optimizer_steps
        if paused_early:
            break

    if micro_batches_seen == 0:
        raise RuntimeError("No chunk samples were produced for recipe expert training.")

    if paused_early:
        checkpoint_manager.close()
        return {
            "artifact_dir": None,
            "backend": "peft_hierarchical_modernbert_recipe",
            "examples": records_seen,
            "intendedBackbone": backbone,
            "topKChunks": top_k_chunks,
            "maxLength": max_length,
            "epochs": epochs,
            "batchSize": batch_size,
            "gradientAccumulationSteps": gradient_accumulation_steps,
            "learningRate": learning_rate,
            "device": str(device),
            "stageName": stage_name,
            "planEntries": total_plan_entries,
            "checkpointDir": str(output_path / "active"),
            "peftMethod": config.peft_method,
            "useDoRA": use_dora,
            "state": "paused",
            "retentionOutcome": "latest_plus_sparse_milestones",
        }

    final_moving_average = sum(recent_losses) / max(1, len(recent_losses))
    final_elapsed_seconds = max(time.perf_counter() - training_started_monotonic, 1e-9)
    final_gpu_memory_allocated_mb = None
    final_gpu_memory_reserved_mb = None
    if device.type == "cuda":
        final_gpu_memory_allocated_mb = float(torch.cuda.memory_allocated(device) / (1024 * 1024))
        final_gpu_memory_reserved_mb = float(torch.cuda.memory_reserved(device) / (1024 * 1024))
    final_state = _build_stage_state_payload(
        stage_name=stage_name,
        records_seen=records_seen,
        micro_batches_seen=micro_batches_seen,
        optimizer_steps=optimizer_steps,
        total_target_records=total_target_records,
        batch_size=batch_size,
        gradient_accumulation_steps=gradient_accumulation_steps,
        top_k_chunks=top_k_chunks,
        max_length=max_length,
        latest_loss=recent_losses[-1] if recent_losses else 0.0,
        moving_average_loss=final_moving_average,
        last_checkpoint_path=str(checkpoint_manager.latest_dir),
        state="completed",
        mean_confidence=sum(recent_confidences) / max(1, len(recent_confidences)),
        gradient_norm=gradient_norm if math.isfinite(gradient_norm) else None,
        label_entropy=current_label_entropy if "current_label_entropy" in locals() else None,
        examples_per_second=records_seen / final_elapsed_seconds if records_seen else 0.0,
        batches_per_second=optimizer_steps / final_elapsed_seconds if optimizer_steps else 0.0,
        consecutive_nonfinite_gradients=consecutive_nonfinite_gradients,
        current_label_counts=current_label_counts if "current_label_counts" in locals() else None,
        last_batch_build_seconds=recent_batch_build_seconds[-1] if recent_batch_build_seconds else None,
        moving_average_batch_build_seconds=sum(recent_batch_build_seconds) / max(1, len(recent_batch_build_seconds)) if recent_batch_build_seconds else None,
        last_optimizer_step_seconds=recent_optimizer_step_seconds[-1] if recent_optimizer_step_seconds else None,
        moving_average_optimizer_step_seconds=sum(recent_optimizer_step_seconds) / max(1, len(recent_optimizer_step_seconds)) if recent_optimizer_step_seconds else None,
        last_checkpoint_write_seconds=latest_checkpoint_write_seconds if latest_checkpoint_write_seconds > 0 else None,
        gpu_memory_allocated_mb=final_gpu_memory_allocated_mb,
        gpu_memory_reserved_mb=final_gpu_memory_reserved_mb,
    )
    final_checkpoint_hash = checkpoint_manager.save_resume_checkpoint(
        model=model,
        torch_module=torch,
        state_payload=final_state,
        optimizer=optimizer,
        scaler=scaler if use_grad_scaler else None,
    )
    checkpoint_manager.save_milestone(model=model, torch_module=torch, state_payload=final_state)
    release_path = checkpoint_manager.finalize_release(model=model, tokenizer=tokenizer)
    checkpoint_manager.close()

    summary = {
        "artifact_dir": "release/expert",
        "backend": "peft_hierarchical_modernbert_recipe",
        "examples": records_seen,
        "intendedBackbone": backbone,
        "topKChunks": top_k_chunks,
        "maxLength": max_length,
        "epochs": epochs,
        "batchSize": batch_size,
        "gradientAccumulationSteps": gradient_accumulation_steps,
        "learningRate": learning_rate,
        "device": str(device),
        "averageLoss": final_moving_average,
        "aggregation": config.aggregation,
        "stageName": stage_name,
        "planEntries": total_plan_entries,
        "checkpointDir": str(output_path / "active"),
        "peftMethod": config.peft_method,
        "useDoRA": use_dora,
        "metadataFusion": True,
        "heads": ["decision", "binaryThreat", "reason", "embedding"],
        "finalCheckpointHash": final_checkpoint_hash,
        "finalCheckpointPath": str(checkpoint_manager.latest_dir),
        "releaseArtifactDir": str(release_path),
        "featureSchemaVersion": config.feature_schema_version,
        "retentionOutcome": "latest_plus_sparse_milestones",
        "pooledEmbeddingDim": 128,
    }
    _write_json(output_path / "summary.json", summary)
    _save_progress(progress_output_path, final_state | {"lastCheckpointHash": final_checkpoint_hash})
    _mlflow_log_metrics(
        {
            f"{stage_metric_prefix}.average_loss": final_moving_average,
            f"{stage_metric_prefix}.records_seen": records_seen,
            f"{stage_metric_prefix}.optimizer_step": optimizer_steps,
            f"{stage_metric_prefix}.progress_fraction": 1.0,
        },
        step=optimizer_steps,
    )
    _mlflow_log_dict(summary, f"summaries/expert_{_safe_stage_name(stage_name or 'default')}.json")
    return summary


def _collect_hard_negative_indices(
    expert_dir: str | Path,
    *,
    dataset_root: str | Path,
    index_records: list[IndexedRecord],
    selected_indices: list[int],
    sentinel_artifact: dict[str, Any] | None,
    run_log_path: str | Path | None = None,
    progress_root: str | Path | None = None,
    resume: bool = False,
    checkpoint_items: int = _DEFAULT_REPLAY_CHECKPOINT_ITEMS,
    milestone_items: int = _DEFAULT_REPLAY_MILESTONE_ITEMS,
) -> list[int]:
    replay_checkpoint_manager: StateCheckpointManager | None = None
    replay_checkpoint_root = Path(progress_root) / "hard_negative_replay" if progress_root is not None else None
    selected_indices_hash = _hash_index_plan(selected_indices)
    hard_negative_indices: list[int] = []
    total = len(selected_indices)
    resume_processed = 0
    if replay_checkpoint_root is not None:
        replay_checkpoint_manager = StateCheckpointManager(stage_dir=replay_checkpoint_root)
    if resume and replay_checkpoint_root is not None:
        checkpoint_state = _load_checkpoint_state(replay_checkpoint_root)
        if checkpoint_state is not None:
            state_payload, checkpoint_path = checkpoint_state
            if (
                state_payload.get("schemaVersion") == "hard_negative_replay_v1"
                and state_payload.get("selectedIndicesHash") == selected_indices_hash
            ):
                resume_processed = int(state_payload.get("recordsSeen", 0))
                hard_negative_indices = [int(value) for value in state_payload.get("hardNegativeIndices", [])]
                if progress_root is not None:
                    _save_progress(
                        Path(progress_root),
                        {
                            "currentStage": "long_context",
                            "state": "running",
                            "recordsSeen": resume_processed,
                            "totalTargetRecords": total,
                            "progressFraction": (resume_processed / total) if total else None,
                            "phase": "hard_negative_replay",
                            "hardNegativeReplayCount": len(hard_negative_indices),
                            "lastCheckpointPath": str(checkpoint_path),
                            "lastCheckpointAt": state_payload.get("lastCheckpointAt"),
                        },
                    )
    last_checkpoint_path: str | None = None
    bootstrap_positions = {1, 100}
    for position, record_index in enumerate(selected_indices[resume_processed:], start=resume_processed + 1):
        example = example_from_dataset_row(_read_record_by_index(dataset_root, index_records, record_index))
        prediction = _score_recipe_expert_artifact(expert_dir, example, sentinel_artifact=sentinel_artifact)
        predicted_label = max(prediction["probabilities"].items(), key=lambda item: item[1])[0]
        gold_label = example.decision_label or "allow_read_only"
        is_hard_negative = (
            (gold_label != "allow_read_only" and predicted_label == "allow_read_only")
            or (gold_label == "deny" and predicted_label == "require_shadow_replay")
            or (
                gold_label == "require_user_approval"
                and predicted_label in {"require_shadow_replay", "deny"}
            )
        )
        if is_hard_negative:
            hard_negative_indices.append(record_index)
        if replay_checkpoint_manager is not None and (
            position in bootstrap_positions or position % max(1, checkpoint_items) == 0
        ):
            checkpoint_payload = _replay_checkpoint_payload(
                records_seen=position,
                total_target_records=total,
                selected_indices_hash=selected_indices_hash,
                hard_negative_indices=hard_negative_indices,
            )
            checkpoint_payload["lastCheckpointAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            replay_checkpoint_manager.save_latest(state_payload=checkpoint_payload)
            last_checkpoint_path = str(replay_checkpoint_manager.latest_dir)
            if position % max(1, milestone_items) == 0:
                replay_checkpoint_manager.save_milestone(step_key=position, state_payload=checkpoint_payload)
            if progress_root is not None:
                _save_progress(
                    Path(progress_root),
                    {
                        "currentStage": "long_context",
                        "state": "running",
                        "recordsSeen": position,
                        "totalTargetRecords": total,
                        "progressFraction": (position / total) if total else None,
                        "phase": "hard_negative_replay",
                        "hardNegativeReplayCount": len(hard_negative_indices),
                        "lastCheckpointPath": last_checkpoint_path,
                        "lastCheckpointAt": checkpoint_payload["lastCheckpointAt"],
                    },
                )
        if position == 1 or position % 2000 == 0:
            _maybe_report(
                f"scored {position}/{total} stage examples for hard-negative replay; found {len(hard_negative_indices)}",
                run_log_path=run_log_path,
            )
    if replay_checkpoint_manager is not None:
        final_payload = _replay_checkpoint_payload(
            records_seen=total,
            total_target_records=total,
            selected_indices_hash=selected_indices_hash,
            hard_negative_indices=hard_negative_indices,
        )
        final_payload["lastCheckpointAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        replay_checkpoint_manager.save_latest(state_payload=final_payload)
        _write_json(
            replay_checkpoint_root / "summary.json",
            {
                "recordsSeen": total,
                "totalTargetRecords": total,
                "hardNegativeReplayCount": len(hard_negative_indices),
                "selectedIndicesHash": selected_indices_hash,
                "retentionOutcome": "active_checkpoint_pruned_after_completion",
            },
        )
        replay_checkpoint_manager.cleanup_completed(keep_milestones=False)
        replay_checkpoint_manager.close()
    return hard_negative_indices


def _stacker_feature_row(
    example: Any,
    *,
    sentinel_scores: dict[str, float],
    expert_output: dict[str, Any],
) -> dict[str, Any]:
    features = structured_feature_dict(example.structured)
    features["sentinel_lexical_probability"] = float(sentinel_scores["lexical"])
    features["sentinel_structured_probability"] = float(sentinel_scores["structured"])
    features["sentinel_or_probability"] = float(sentinel_scores["max"])
    for label, index in LABEL_TO_ID.items():
        features[f"expert_logit_{label}"] = float(expert_output["logits"][index])
        features[f"expert_prob_{label}"] = float(expert_output["probabilities"].get(label, 0.0))
    for index, value in enumerate(expert_output["pooledEmbedding"]):
        features[f"expert_embedding_{index:03d}"] = float(value)
    return features


def _fit_binary_calibrator(train_scores: list[float], train_labels: list[int]) -> dict[str, Any]:
    deps = _require_training_dependencies()
    LogisticRegression = deps["LogisticRegression"]
    if len(set(train_labels)) < 2:
        return {"kind": "identity"}
    model = LogisticRegression(random_state=_DEFAULT_RANDOM_SEED, max_iter=200)
    model.fit([[score] for score in train_scores], train_labels)
    return {"kind": "platt", "model": model}


def _search_temperature(logits: list[list[float]], labels: list[str]) -> float:
    deps = _require_training_dependencies()
    log_loss = deps["log_loss"]
    label_order = list(LABEL_TO_ID.keys())
    numeric_labels = [LABEL_TO_ID[label] for label in labels]
    best_temperature = 1.0
    best_loss = float("inf")
    for temperature in [0.5, 0.75, 1.0, 1.25, 1.5, 2.0]:
        probabilities: list[list[float]] = []
        for row in logits:
            scaled = {label_order[index]: row[index] / temperature for index in range(len(label_order))}
            normalized = softmax(scaled)
            probabilities.append([normalized[label] for label in label_order])
        loss = float(log_loss(numeric_labels, probabilities, labels=list(range(len(label_order)))))
        if loss < best_loss:
            best_loss = loss
            best_temperature = temperature
    return best_temperature


def train_stacker(
    manifest_path: str | Path,
    *,
    sentinel_dir: str | Path,
    expert_dir: str | Path,
    output_dir: str | Path,
    data_root: str | Path | None = None,
    limit: int | None = None,
    progress_root: str | Path | None = None,
    resume: bool = False,
    checkpoint_rows: int = _DEFAULT_STACKER_CHECKPOINT_ROWS,
    chunk_rows: int = _DEFAULT_STACKER_CHUNK_ROWS,
    milestone_rows: int = _DEFAULT_STACKER_MILESTONE_ROWS,
) -> dict[str, Any]:
    deps = _require_training_dependencies()
    DictVectorizer = deps["DictVectorizer"]
    SGDClassifier = deps["SGDClassifier"]
    CatBoostClassifier = deps["CatBoostClassifier"]
    XGBClassifier = deps["XGBClassifier"]

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    progress_output_path = Path(progress_root) if progress_root is not None else output_path
    sentinel_artifact = load_pickle(Path(sentinel_dir) / "sentinel.pkl")
    checkpoint_manager = StateCheckpointManager(stage_dir=output_path, preserve_names={"chunks"})
    chunks_dir = output_path / "active" / "chunks"
    feature_rows: list[dict[str, Any]] = []
    labels: list[str] = []
    pending_rows: list[dict[str, Any]] = []
    pending_labels: list[str] = []
    committed_rows = 0
    resume_processed = 0
    last_checkpoint_path: str | None = None
    last_checkpoint_at: str | None = None
    total_train_examples = _total_examples(manifest_path, "train", data_root=data_root, limit=limit) or 0

    if resume:
        checkpoint_state = _load_checkpoint_state(output_path)
        if checkpoint_state is not None:
            state_payload, checkpoint_path = checkpoint_state
            if state_payload.get("schemaVersion") == "stacker_cache_v1":
                committed_rows = int(state_payload.get("committedRows", 0))
                feature_rows, labels = _load_stacker_chunk_payloads(chunks_dir, committed_rows=committed_rows)
                pending_path = checkpoint_path / "pending.pkl.gz"
                if pending_path.is_file():
                    pending_payload = _load_pickle_gz(pending_path)
                    pending_rows = list(pending_payload.get("featureRows", []))
                    pending_labels = [str(value) for value in pending_payload.get("labels", [])]
                    feature_rows.extend(pending_rows)
                    labels.extend(pending_labels)
                recovered_rows = len(feature_rows)
                requested_resume_rows = int(state_payload.get("recordsSeen", recovered_rows))
                if committed_rows > 0 and recovered_rows < committed_rows:
                    _maybe_report(
                        "stacker checkpoint cache incomplete; restarting stacker from scratch for correctness",
                        run_log_path=progress_output_path / "run.log" if progress_root is not None else None,
                    )
                    committed_rows = 0
                    feature_rows = []
                    labels = []
                    pending_rows = []
                    pending_labels = []
                    resume_processed = 0
                    last_checkpoint_path = None
                    last_checkpoint_at = None
                else:
                    resume_processed = requested_resume_rows
                    last_checkpoint_path = str(checkpoint_path)
                    last_checkpoint_at = state_payload.get("lastCheckpointAt")

    _save_progress(
        progress_output_path,
        {
            "currentStage": "phase_3_stacker" if progress_root is not None else "train_stacker",
            "state": "running",
            "recordsSeen": resume_processed,
            "totalTargetRecords": total_train_examples,
            "progressFraction": (resume_processed / total_train_examples) if total_train_examples else None,
            "lastCheckpointPath": last_checkpoint_path,
            "lastCheckpointAt": last_checkpoint_at,
            "stackerFeatureRows": len(feature_rows),
        },
    )

    def persist_stacker_checkpoint(processed_rows: int) -> None:
        nonlocal last_checkpoint_path, last_checkpoint_at
        checkpoint_payload = _stacker_checkpoint_payload(
            records_seen=processed_rows,
            total_target_records=total_train_examples,
            committed_rows=committed_rows,
            chunk_rows=chunk_rows,
            feature_row_count=len(feature_rows),
        )
        checkpoint_payload["lastCheckpointAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        pickle_payloads = None
        if pending_rows:
            pickle_payloads = {"pending.pkl.gz": {"featureRows": pending_rows, "labels": pending_labels}}
        checkpoint_manager.save_latest(state_payload=checkpoint_payload, pickle_payloads=pickle_payloads)
        last_checkpoint_path = str(checkpoint_manager.latest_dir)
        last_checkpoint_at = checkpoint_payload["lastCheckpointAt"]
        if processed_rows % max(1, milestone_rows) == 0:
            checkpoint_manager.save_milestone(
                step_key=processed_rows,
                state_payload=checkpoint_payload,
                pickle_payloads=pickle_payloads,
            )
        _save_progress(
            progress_output_path,
            {
                "currentStage": "phase_3_stacker" if progress_root is not None else "train_stacker",
                "state": "running",
                "recordsSeen": processed_rows,
                "totalTargetRecords": total_train_examples,
                "progressFraction": (processed_rows / total_train_examples) if total_train_examples else None,
                "lastCheckpointPath": last_checkpoint_path,
                "lastCheckpointAt": last_checkpoint_at,
                "stackerFeatureRows": len(feature_rows),
            },
        )

    bootstrap_positions = {1, 100}

    try:
        for example_index, example in enumerate(
            _iter_examples(
                manifest_path,
                "train",
                data_root=data_root,
                limit=limit,
                skip=resume_processed,
            ),
            start=resume_processed + 1,
        ):
            if example.decision_label not in LABEL_TO_ID:
                continue
            sentinel_scores = _score_dual_sentinel_artifact(sentinel_artifact, example)
            expert_output = _score_recipe_expert_artifact(expert_dir, example, sentinel_artifact=sentinel_artifact)
            feature_row = _stacker_feature_row(example, sentinel_scores=sentinel_scores, expert_output=expert_output)
            label = example.decision_label or "allow_read_only"
            feature_rows.append(feature_row)
            labels.append(label)
            pending_rows.append(feature_row)
            pending_labels.append(label)
            if len(pending_rows) >= max(1, chunk_rows):
                chunks_dir.mkdir(parents=True, exist_ok=True)
                _write_stacker_chunk(
                    chunks_dir,
                    start_row=committed_rows + 1,
                    feature_rows=pending_rows,
                    labels=pending_labels,
                )
                committed_rows += len(pending_rows)
                pending_rows = []
                pending_labels = []
            if example_index in bootstrap_positions or example_index % max(1, checkpoint_rows) == 0:
                persist_stacker_checkpoint(example_index)
        if pending_rows:
            chunks_dir.mkdir(parents=True, exist_ok=True)
            _write_stacker_chunk(
                chunks_dir,
                start_row=committed_rows + 1,
                feature_rows=pending_rows,
                labels=pending_labels,
            )
            committed_rows += len(pending_rows)
            pending_rows = []
            pending_labels = []
        if feature_rows:
            persist_stacker_checkpoint(len(feature_rows))

        vectorizer = DictVectorizer(sparse=False)
        matrix = vectorizer.fit_transform(feature_rows)
        backend = "sklearn_multiclass"
        if CatBoostClassifier is not None:
            classifier = CatBoostClassifier(
                task_type="CPU",
                loss_function="MultiClass",
                depth=6,
                learning_rate=0.08,
                iterations=200,
                allow_writing_files=False,
                verbose=False,
            )
            classifier.fit(matrix, labels)
            backend = "catboost_multiclass_cpu"
        elif XGBClassifier is not None:
            classifier = XGBClassifier(
                objective="multi:softprob",
                num_class=len(LABEL_TO_ID),
                n_estimators=200,
                max_depth=6,
                learning_rate=0.08,
                tree_method="hist",
                device="cpu",
                random_state=_DEFAULT_RANDOM_SEED,
            )
            classifier.fit(matrix, [LABEL_TO_ID[label] for label in labels])
            backend = "xgboost_multiclass_cpu"
        else:
            classifier = SGDClassifier(loss="log_loss", alpha=1e-5, random_state=_DEFAULT_RANDOM_SEED)
            classifier.fit(matrix, labels)

        valid_scores: list[float] = []
        valid_binary_labels: list[int] = []
        valid_logits: list[list[float]] = []
        valid_labels: list[str] = []
        for example in _iter_examples(manifest_path, "valid", data_root=data_root, limit=limit):
            if example.decision_label not in LABEL_TO_ID:
                continue
            sentinel_scores = _score_dual_sentinel_artifact(sentinel_artifact, example)
            expert_output = _score_recipe_expert_artifact(expert_dir, example, sentinel_artifact=sentinel_artifact)
            valid_scores.append(float(sentinel_scores["max"]))
            valid_binary_labels.append(int(example.threat_positive or 0))
            valid_logits.append([float(value) for value in expert_output["logits"][: len(LABEL_TO_ID)]])
            valid_labels.append(example.decision_label or "allow_read_only")

        calibration = {
            "expertTemperature": _search_temperature(valid_logits, valid_labels) if valid_logits else 1.0,
            "binaryThreatCalibrator": _fit_binary_calibrator(valid_scores, valid_binary_labels),
        }

        artifact_path = write_pickle(
            output_path / "stacker.pkl",
            {"vectorizer": vectorizer, "classifier": classifier, "label_order": list(getattr(classifier, "classes_", sorted(set(labels))))},
        )
        calibration_path = write_pickle(output_path / "calibration.pkl", calibration)
        summary = {
            "artifact": str(artifact_path),
            "calibrationArtifact": str(calibration_path),
            "backend": backend,
            "examples": len(labels),
            "inputs": [
                "sentinel_lexical_probability",
                "sentinel_structured_probability",
                "sentinel_or_probability",
                "expert_logits",
                "expert_pooled_embeddings",
                "structured_features",
            ],
            "calibration": {
                "expertTemperature": calibration["expertTemperature"],
                "binaryThreatCalibrator": calibration["binaryThreatCalibrator"]["kind"],
            },
            "retentionOutcome": "active_cache_pruned_after_completion",
        }
        _write_json(output_path / "summary.json", summary)
        _mlflow_log_metrics(
            {
                "stacker.examples": len(labels),
                "stacker.expert_temperature": calibration["expertTemperature"],
            }
        )
        _mlflow_log_dict(summary, "summaries/stacker_summary.json")
        checkpoint_manager.cleanup_completed(keep_milestones=False)
        _save_progress(
            progress_output_path,
            {
                "currentStage": "phase_3_stacker" if progress_root is not None else "train_stacker",
                "state": "completed",
                "recordsSeen": len(feature_rows),
                "totalTargetRecords": total_train_examples,
                "progressFraction": 1.0 if total_train_examples else None,
                "lastCheckpointPath": None,
                "lastCheckpointAt": None,
                "stackerFeatureRows": len(feature_rows),
                "stackerBackend": backend,
            },
        )
        return summary
    finally:
        checkpoint_manager.close()


def package_runtime_bundle(
    sentinel_dir: str | Path,
    expert_dir: str | Path,
    stacker_dir: str | Path,
    *,
    output_dir: str | Path,
    bundle_version: str,
    recipe_path: str | Path | None = None,
) -> dict[str, Any]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    sentinel_summary = _load_json(Path(sentinel_dir) / "summary.json")
    expert_summary = _load_json(Path(expert_dir) / "summary.json")
    stacker_summary = _load_json(Path(stacker_dir) / "summary.json")

    copy_component_file(sentinel_summary["artifact"], output_path, "sentinel.pkl")
    if expert_summary["backend"] == "peft_hierarchical_modernbert_recipe":
        copy_component_tree(Path(expert_dir) / "release" / "expert", output_path, "expert_release")
    else:
        copy_component_file(expert_summary["artifact"], output_path, "expert.pkl")
    copy_component_file(stacker_summary["artifact"], output_path, "stacker.pkl")
    copy_component_file(stacker_summary["calibrationArtifact"], output_path, "calibration.pkl")
    if recipe_path is not None and Path(recipe_path).is_file():
        copy_component_file(recipe_path, output_path, "recipe.json")

    manifest = {
        "bundleVersion": bundle_version,
        "featureSchemaVersion": "recipe_v1",
        "gitSha": _git_sha(),
        "pipeline": {
            "runtimeMode": "python_sidecar",
            "enforcementMode": "tighten",
            "sentinelVersion": sentinel_summary["backend"],
            "expertVersion": expert_summary["backend"],
            "stackerVersion": stacker_summary["backend"],
        },
        "components": {
            "sentinel": {"backend": sentinel_summary["backend"], "artifact": "sentinel.pkl"},
            "expert": {
                "backend": expert_summary["backend"],
                "artifact_dir": "expert_release" if expert_summary["backend"] == "peft_hierarchical_modernbert_recipe" else None,
                "artifact": None if expert_summary["backend"] == "peft_hierarchical_modernbert_recipe" else "expert.pkl",
                "top_k_chunks": expert_summary.get("topKChunks", 3),
                "max_length": expert_summary.get("maxLength", 1024),
                "pooledEmbeddingDim": expert_summary.get("pooledEmbeddingDim", 128),
                "peftMethod": expert_summary.get("peftMethod"),
            },
            "stacker": {"backend": stacker_summary["backend"], "artifact": "stacker.pkl"},
            "calibration": {"artifact": "calibration.pkl"},
        },
        "thresholds": {"binaryThreat": sentinel_summary.get("threshold", 0.55)},
        "stageSummaries": {"sentinel": sentinel_summary, "expert": expert_summary, "stacker": stacker_summary},
    }
    manifest_path = write_bundle_manifest(output_path, manifest)
    _write_json(
        output_path / "manifest.json",
        {
            "bundleVersion": bundle_version,
            "recipePath": str(recipe_path) if recipe_path is not None else None,
            "recipeHash": _hash_tree(recipe_path) if recipe_path is not None and Path(recipe_path).is_file() else None,
            "gitSha": _git_sha(),
            "dependencyVersions": _dependency_versions(),
            "componentHashes": {
                "sentinel": _hash_tree(output_path / "sentinel.pkl") if (output_path / "sentinel.pkl").is_file() else None,
                "expert": _hash_tree(output_path / "expert_release") if (output_path / "expert_release").is_dir() else None,
                "stacker": _hash_tree(output_path / "stacker.pkl") if (output_path / "stacker.pkl").is_file() else None,
                "calibration": _hash_tree(output_path / "calibration.pkl") if (output_path / "calibration.pkl").is_file() else None,
            },
            "stageSummaries": {
                "sentinel": sentinel_summary,
                "expert": expert_summary,
                "stacker": stacker_summary,
            },
            "calibration": stacker_summary.get("calibration"),
            "retentionOutcome": "latest_plus_sparse_milestones",
        },
    )
    return {"bundleDir": str(output_path), "bundleManifest": str(manifest_path)}


def evaluate(
    manifest_path: str | Path,
    *,
    bundle_dir: str | Path,
    split: str,
    data_root: str | Path | None = None,
    limit: int | None = None,
    output_path: str | Path | None = None,
    progress_root: str | Path | None = None,
) -> dict[str, Any]:
    deps = _require_training_dependencies()
    f1_score = deps["f1_score"]
    precision_recall_fscore_support = deps["precision_recall_fscore_support"]
    recall_score = deps["recall_score"]
    from .runtime import ModelGuardRuntime

    runtime = ModelGuardRuntime(bundle_dir)
    gold_labels: list[str] = []
    predicted_labels: list[str] = []
    gold_threat: list[int] = []
    predicted_threat: list[int] = []
    progress_output_path = Path(progress_root) if progress_root is not None else None
    total_examples = _total_examples(manifest_path, split, data_root=data_root, limit=limit) or 0
    progress_stage = f"phase_5_evaluate_{split}" if progress_root is not None else f"evaluate_{split}"
    if progress_output_path is not None:
        _save_progress(
            progress_output_path,
            {
                "currentStage": progress_stage,
                "state": "running",
                "recordsSeen": 0,
                "totalTargetRecords": total_examples,
                "progressFraction": 0.0 if total_examples else None,
                "lastCheckpointPath": None,
                "lastCheckpointAt": None,
                "evaluationSplit": split,
            },
        )

    for example_index, example in enumerate(_iter_examples(manifest_path, split, data_root=data_root, limit=limit), start=1):
        request = {
            "session": {
                "sessionId": "eval-session",
                "taskId": "eval-task",
                "userGoal": "Evaluate a candidate action safely.",
                "allowedOrigins": ["https://example.test"],
                "allowedVerbs": ["GET"],
                "allowedPathClasses": ["content_read", "docs_navigation", "workflow_continue"],
                "approvalRequiredPathClasses": ["admin", "payment", "connector_setup"],
            },
            "observation": {
                "observationId": example.example_id,
                "sourceOrigin": "https://example.test",
                "frameOrigin": "https://example.test",
                "surfaceType": "html_visible",
                "parseStatus": "compiled",
                "visibleText": example.text[:4000],
                "contextText": example.text[:24000],
                "suspicionFlags": [],
                "matchedPatternIds": [],
                "riskFindings": [],
                "semanticAuthorityFindings": [],
                "policyFindings": [],
                "blockedChannels": [],
                "channelFlags": {"visible": True, "hidden": False},
                "secretRedactionCount": 0,
                "captureAttestation": {
                    "captureMethod": "rendered_dom",
                    "visibilityAttested": True,
                    "frameCoverage": "full",
                    "shadowDomCoverage": "full",
                    "unsupportedSubtrees": [],
                    "evidenceHash": "eval",
                },
                "contextChars": len(example.text),
            },
            "targets": [
                {
                    "kind": "navigate",
                    "targetUrl": "https://example.test/payments/finalize",
                    "targetOrigin": "https://example.test",
                    "targetPathClass": "payment",
                    "sourceSpanIds": ["eval-span"],
                }
            ],
            "structuredFeatures": structured_feature_dict(example.structured),
        }
        scored = runtime.score_observation(request)
        predicted = scored["assessment"]["calibratedDecisionLabel"]
        gold = example.decision_label or "allow_read_only"
        gold_labels.append(gold)
        predicted_labels.append(predicted)
        gold_threat.append(0 if gold == "allow_read_only" else 1)
        predicted_threat.append(0 if predicted == "allow_read_only" else 1)
        if progress_output_path is not None and (example_index == 1 or example_index % 250 == 0):
            _save_progress(
                progress_output_path,
                {
                    "currentStage": progress_stage,
                    "state": "running",
                    "recordsSeen": example_index,
                    "totalTargetRecords": total_examples,
                    "progressFraction": (example_index / total_examples) if total_examples else None,
                    "lastCheckpointPath": None,
                    "lastCheckpointAt": None,
                    "evaluationSplit": split,
                },
            )

    threat_recall = float(recall_score(gold_threat, predicted_threat))
    threat_false_negative_rate = float(sum(1 for gold, predicted in zip(gold_threat, predicted_threat, strict=False) if gold == 1 and predicted == 0) / max(1, sum(gold_threat)))
    macro_f1 = float(f1_score(gold_labels, predicted_labels, average="macro"))
    per_label = precision_recall_fscore_support(gold_labels, predicted_labels, labels=list(LABEL_TO_ID.keys()), zero_division=0)
    metrics = {
        "split": split,
        "examples": len(gold_labels),
        "threatRecall": threat_recall,
        "threatFalseNegativeRate": threat_false_negative_rate,
        "macroF1": macro_f1,
        "perLabelRecall": {label: float(per_label[1][index]) for index, label in enumerate(list(LABEL_TO_ID.keys()))},
    }
    if output_path is not None:
        Path(output_path).write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    _mlflow_log_metrics(
        {
            f"evaluate.{split}.examples": len(gold_labels),
            f"evaluate.{split}.threat_recall": threat_recall,
            f"evaluate.{split}.threat_false_negative_rate": threat_false_negative_rate,
            f"evaluate.{split}.macro_f1": macro_f1,
        }
    )
    if progress_output_path is not None:
        _save_progress(
            progress_output_path,
            {
                "currentStage": progress_stage,
                "state": "completed",
                "recordsSeen": len(gold_labels),
                "totalTargetRecords": total_examples,
                "progressFraction": 1.0 if total_examples else None,
                "lastCheckpointPath": None,
                "lastCheckpointAt": None,
                "evaluationSplit": split,
                "validThreatRecall": threat_recall if split == "valid" else None,
                "testThreatRecall": threat_recall if split == "test" else None,
                "validMacroF1": macro_f1 if split == "valid" else None,
                "testMacroF1": macro_f1 if split == "test" else None,
            },
        )
    return metrics


def _completed_stage_summary(stage_dir: Path) -> dict[str, Any] | None:
    summary_path = stage_dir / "summary.json"
    if not summary_path.is_file():
        return None
    summary = _load_json(summary_path)
    if summary.get("backend") == "recipe_hierarchical_smoke":
        return summary
    final_path = Path(summary.get("finalCheckpointPath", ""))
    final_hash = summary.get("finalCheckpointHash")
    if not final_path.is_dir() or not final_hash:
        return None
    manifest_path = final_path / "manifest.json"
    if not manifest_path.is_file():
        return None
    if _load_json(manifest_path).get("hash") != final_hash:
        return None
    return summary


def train_recipe(
    manifest_path: str | Path,
    *,
    recipe_path: str | Path,
    output_dir: str | Path,
    data_root: str | Path | None = None,
    backbone: str = "answerdotai/ModernBERT-base",
    backend: str = "transformers",
    threat_threshold: float = 0.55,
    checkpoint_steps: int = _DEFAULT_LATEST_CHECKPOINT_STEPS,
    milestone_checkpoint_steps: int = _DEFAULT_MILESTONE_CHECKPOINT_STEPS,
    bundle_version: str | None = None,
    resume: bool = False,
    use_dora: bool = False,
) -> dict[str, Any]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    run_log_path = output_path / "run.log"
    recipe = _load_recipe(recipe_path)
    stages = _load_recipe_stages(recipe)
    _maybe_report(
        f"starting train_recipe with {Path(recipe_path).name} into {output_path}",
        run_log_path=run_log_path,
    )
    _mlflow_set_tags(
        {
            "model_guard.recipe_version": recipe.get("version"),
            "model_guard.backbone": backbone,
            "model_guard.backend": backend,
            "model_guard.current_stage": "phase_1_ml_sentinel",
        }
    )
    train_limit = min(
        int(
            recipe.get(
                "dataset_profile",
                {},
            ).get("train_records", _total_examples(manifest_path, "train", data_root=data_root) or 0)
        ),
        _total_examples(manifest_path, "train", data_root=data_root) or 0,
    )
    valid_limit = int(
        recipe.get("dataset_profile", {}).get("valid_records", _total_examples(manifest_path, "valid", data_root=data_root) or 0)
    )
    test_limit = int(
        recipe.get("dataset_profile", {}).get("test_records", _total_examples(manifest_path, "test", data_root=data_root) or 0)
    )

    _save_status(
        output_path,
        {
            "currentStep": "train_recipe",
            "currentStage": "phase_1_ml_sentinel",
            "state": "running",
            "resume": resume,
            "startedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        },
    )
    _save_progress(
        output_path,
        {
            "currentStage": "phase_1_ml_sentinel",
            "optimizerStep": 0,
            "recordsSeen": 0,
            "totalTargetRecords": train_limit,
            "lastCheckpointPath": None,
            "lastCheckpointAt": None,
            "progressFraction": 0.0 if train_limit else None,
            "state": "running",
        },
    )

    sentinel_dir = output_path / "sentinel"
    if resume and (sentinel_dir / "summary.json").is_file():
        sentinel_summary = _load_json(sentinel_dir / "summary.json")
        _maybe_report("reusing completed phase_1_ml_sentinel summary", run_log_path=run_log_path)
    else:
        sentinel_summary = train_sentinel(
            manifest_path,
            output_dir=sentinel_dir,
            data_root=data_root,
            limit=train_limit,
            threat_threshold=threat_threshold,
            resume=resume,
            recipe_mode="dual",
            progress_root=output_path,
        )
    sentinel_artifact = load_pickle(Path(sentinel_summary["artifact"]))

    index_dir = output_path / "index"
    index_records = _build_index(manifest_path, "train", data_root=data_root, limit=train_limit, output_path=index_dir / "train_index.jsonl")
    label_distribution = {label: sum(1 for item in index_records if item.label == label) for label in LABEL_TO_ID}
    hard_families = set(recipe.get("dataset_profile", {}).get("high_confusion_attack_families_to_oversample", []))
    dataset_root = _dataset_root_for_manifest(manifest_path, data_root=data_root)

    stage_summaries: list[dict[str, Any]] = []
    plan_root = output_path / "expert" / "plans"
    expert_root = output_path / "expert"
    previous_stage_dir: Path | None = None

    for offset, stage in enumerate(stages[:-1], start=1):
        selected_indices = _select_stage_indices(index_records, stage=stage, hard_families=hard_families, label_distribution=label_distribution, seed=_DEFAULT_RANDOM_SEED + offset)
        _write_stage_plan(plan_root, stage=stage, selected_indices=selected_indices)
        stage_dir = expert_root / _safe_stage_name(stage.name)
        completed = _completed_stage_summary(stage_dir) if resume else None
        if completed is not None:
            stage_summary = completed
            _maybe_report(f"reusing completed expert stage {stage.name}", run_log_path=run_log_path)
        else:
            stage_summary = train_expert(
                manifest_path,
                output_dir=stage_dir,
                data_root=data_root,
                limit=train_limit,
                backbone=backbone,
                backend=backend,
                max_length=stage.max_length,
                top_k_chunks=int(recipe.get("deep_architecture", {}).get("chunking", {}).get("top_k_chunks", 3)),
                epochs=stage.epochs,
                batch_size=stage.batch_size,
                gradient_accumulation_steps=stage.gradient_accumulation_steps,
                learning_rate=2e-5,
                selected_indices=selected_indices,
                index_records=index_records,
                checkpoint_steps=checkpoint_steps,
                milestone_checkpoint_steps=milestone_checkpoint_steps,
                resume=resume,
                stage_name=stage.name,
                sentinel_dir=sentinel_dir,
                use_dora=use_dora,
                progress_root=output_path,
            )
        stage_summaries.append(stage_summary)
        previous_stage_dir = stage_dir

    final_stage = stages[-1]
    final_selected_indices = _select_stage_indices(index_records, stage=final_stage, hard_families=hard_families, label_distribution=label_distribution, seed=_DEFAULT_RANDOM_SEED + 999)
    hard_negative_indices: list[int] = []
    if previous_stage_dir is not None:
        replay_root = output_path / "hard_negative_replay"
        replay_selected_hash = _hash_index_plan(final_selected_indices)
        completed_replay_summary = None
        if resume and (replay_root / "summary.json").is_file():
            try:
                replay_summary = _load_json(replay_root / "summary.json")
            except Exception:
                replay_summary = None
            if isinstance(replay_summary, dict) and replay_summary.get("selectedIndicesHash") == replay_selected_hash:
                completed_replay_summary = replay_summary
        _save_status(
            output_path,
            {
                "currentStep": "hard_negative_replay",
                "currentStage": "long_context",
                "state": "running",
                "resume": resume,
            },
        )
        _save_progress(
            output_path,
            {
                "currentStage": "long_context",
                "state": "running",
                "recordsSeen": 0,
                "totalTargetRecords": len(final_selected_indices),
                "progressFraction": 0.0 if final_selected_indices else None,
                "phase": "hard_negative_replay",
                "hardNegativeReplayCount": 0,
                "lastCheckpointPath": None,
                "lastCheckpointAt": None,
            },
        )
        if completed_replay_summary is not None:
            hard_negative_indices = []
            _maybe_report("reusing completed hard-negative replay summary", run_log_path=run_log_path)
            _save_progress(
                output_path,
                {
                    "currentStage": "long_context",
                    "state": "completed",
                    "recordsSeen": int(completed_replay_summary.get("recordsSeen", len(final_selected_indices))),
                    "totalTargetRecords": len(final_selected_indices),
                    "progressFraction": 1.0 if final_selected_indices else None,
                    "phase": "hard_negative_replay",
                    "hardNegativeReplayCount": int(completed_replay_summary.get("hardNegativeReplayCount", 0)),
                    "lastCheckpointPath": None,
                    "lastCheckpointAt": None,
                },
            )
        else:
            hard_negative_indices = _collect_hard_negative_indices(
                previous_stage_dir,
                dataset_root=dataset_root,
                index_records=index_records,
                selected_indices=final_selected_indices,
                sentinel_artifact=sentinel_artifact,
                run_log_path=run_log_path,
                progress_root=output_path,
                resume=resume,
            )
    replay_factor = int(recipe.get("training_plan", {}).get("phase_3_hard_negative_mining", {}).get("replay_factor", 3))
    final_indices = list(final_selected_indices)
    for _ in range(max(0, replay_factor - 1)):
        final_indices.extend(hard_negative_indices)
    _write_stage_plan(plan_root, stage=final_stage, selected_indices=final_indices, hard_negative_indices=hard_negative_indices)
    final_stage_dir = expert_root / _safe_stage_name(final_stage.name)
    completed_final = _completed_stage_summary(final_stage_dir) if resume else None
    if completed_final is not None:
        final_stage_summary = completed_final
        _maybe_report(f"reusing completed expert stage {final_stage.name}", run_log_path=run_log_path)
    else:
        final_stage_summary = train_expert(
            manifest_path,
            output_dir=final_stage_dir,
            data_root=data_root,
            limit=train_limit,
            backbone=backbone,
            backend=backend,
            max_length=final_stage.max_length,
            top_k_chunks=int(recipe.get("deep_architecture", {}).get("chunking", {}).get("top_k_chunks", 3)),
            epochs=final_stage.epochs,
            batch_size=final_stage.batch_size,
            gradient_accumulation_steps=final_stage.gradient_accumulation_steps,
            learning_rate=2e-5,
            selected_indices=final_indices,
            index_records=index_records,
            checkpoint_steps=checkpoint_steps,
            milestone_checkpoint_steps=milestone_checkpoint_steps,
            resume=resume,
            stage_name=final_stage.name,
            sentinel_dir=sentinel_dir,
            use_dora=use_dora,
            progress_root=output_path,
        )
    stage_summaries.append(final_stage_summary)

    stacker_dir = output_path / "stacker"
    _save_status(
        output_path,
        {
            "currentStep": "train_stacker",
            "currentStage": "phase_3_stacker",
            "state": "running",
            "resume": resume,
        },
    )
    _save_progress(
        output_path,
        {
            "currentStage": "phase_3_stacker",
            "state": "running",
            "recordsSeen": 0,
            "totalTargetRecords": train_limit,
            "progressFraction": 0.0 if train_limit else None,
            "hardNegativeReplayCount": len(hard_negative_indices),
        },
    )
    if resume and (stacker_dir / "summary.json").is_file():
        stacker_summary = _load_json(stacker_dir / "summary.json")
        _maybe_report("reusing completed phase_3_stacker summary", run_log_path=run_log_path)
    else:
        stacker_summary = train_stacker(
            manifest_path,
            sentinel_dir=sentinel_dir,
            expert_dir=final_stage_dir,
            output_dir=stacker_dir,
            data_root=data_root,
            limit=train_limit,
            progress_root=output_path,
            resume=resume,
        )

    _save_status(
        output_path,
        {
            "currentStep": "package_runtime_bundle",
            "currentStage": "phase_4_package_bundle",
            "state": "running",
            "resume": resume,
        },
    )
    _save_progress(
        output_path,
        {
            "currentStage": "phase_4_package_bundle",
            "state": "running",
            "recordsSeen": 0,
            "totalTargetRecords": train_limit,
            "progressFraction": 0.0 if train_limit else None,
            "stackerBackend": stacker_summary.get("backend"),
        },
    )
    bundle_summary = package_runtime_bundle(
        sentinel_dir,
        final_stage_dir,
        stacker_dir,
        output_dir=output_path / "bundle",
        bundle_version=bundle_version or f"recipe-{Path(recipe_path).stem}",
        recipe_path=recipe_path,
    )
    _maybe_report(
        f"packaged runtime bundle {(bundle_summary or {}).get('bundleVersion')}",
        run_log_path=run_log_path,
    )
    _save_status(
        output_path,
        {
            "currentStep": "evaluate",
            "currentStage": "phase_5_evaluate_valid",
            "state": "running",
            "resume": resume,
        },
    )
    _save_progress(
        output_path,
        {
            "currentStage": "phase_5_evaluate_valid",
            "state": "running",
            "recordsSeen": 0,
            "totalTargetRecords": valid_limit,
            "progressFraction": 0.0 if valid_limit else None,
            "bundleDir": (bundle_summary or {}).get("bundleDir"),
        },
    )
    valid_metrics = evaluate(
        manifest_path,
        bundle_dir=output_path / "bundle",
        split="valid",
        data_root=data_root,
        limit=valid_limit,
        progress_root=output_path,
    )
    _save_status(
        output_path,
        {
            "currentStep": "evaluate",
            "currentStage": "phase_5_evaluate_test",
            "state": "running",
            "resume": resume,
        },
    )
    _save_progress(
        output_path,
        {
            "currentStage": "phase_5_evaluate_test",
            "state": "running",
            "recordsSeen": 0,
            "totalTargetRecords": test_limit,
            "progressFraction": 0.0 if test_limit else None,
            "validThreatRecall": valid_metrics.get("threatRecall"),
            "validMacroF1": valid_metrics.get("macroF1"),
        },
    )
    test_metrics = evaluate(
        manifest_path,
        bundle_dir=output_path / "bundle",
        split="test",
        data_root=data_root,
        limit=test_limit,
        progress_root=output_path,
    )
    _maybe_report(
        f"completed train_recipe validThreatRecall={valid_metrics.get('threatRecall')} "
        f"testThreatRecall={test_metrics.get('threatRecall')}",
        run_log_path=run_log_path,
    )

    summary = {
        "recipeVersion": recipe.get("version"),
        "manifest": str(manifest_path),
        "recipePath": str(recipe_path),
        "trainLimit": train_limit,
        "validLimit": valid_limit,
        "testLimit": test_limit,
        "sentinel": sentinel_summary,
        "expertStages": stage_summaries,
        "hardNegativeReplayCount": len(hard_negative_indices),
        "stacker": stacker_summary,
        "bundle": bundle_summary,
        "metrics": {"valid": valid_metrics, "test": test_metrics},
    }
    _write_json(output_path / "recipe_summary.json", summary)
    _mlflow_log_metrics(
        {
            "recipe.train_limit": train_limit,
            "recipe.valid_limit": valid_limit,
            "recipe.test_limit": test_limit,
            "recipe.hard_negative_replay_count": len(hard_negative_indices),
        }
    )
    _mlflow_log_dict(summary, "summaries/recipe_summary.json")
    _save_status(
        output_path,
        {
            "currentStep": "train_recipe",
            "currentStage": "completed",
            "state": "completed",
            "resume": resume,
        },
    )
    final_checkpoint_path = final_stage_summary.get("finalCheckpointPath")
    _save_progress(
        output_path,
        {
            "currentStage": "completed",
            "optimizerStep": 0,
            "recordsSeen": train_limit,
            "totalTargetRecords": train_limit,
            "lastCheckpointPath": final_checkpoint_path,
            "lastCheckpointAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) if final_checkpoint_path else None,
            "progressFraction": 1.0 if train_limit else None,
            "validThreatRecall": valid_metrics.get("threatRecall"),
            "validMacroF1": valid_metrics.get("macroF1"),
            "testThreatRecall": test_metrics.get("threatRecall"),
            "testMacroF1": test_metrics.get("macroF1"),
            "state": "completed",
        },
    )
    return summary
