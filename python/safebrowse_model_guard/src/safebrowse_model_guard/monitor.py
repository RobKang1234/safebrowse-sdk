from __future__ import annotations

import argparse
import json
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


def _decode_json_file(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    raw = path.read_bytes()
    last_error: Exception | None = None
    for encoding in ("utf-8-sig", "utf-16", "utf-16-le", "utf-8"):
        try:
            decoded = raw.decode(encoding)
            return json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    return None


def _tail_jsonl(path: Path, *, limit: int = 50) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    items: deque[dict[str, Any]] = deque(maxlen=limit)
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-16", "utf-16-le", "utf-8"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            items.append(value)
    return list(items)


def _read_log_chunk(path: Path, *, offset: int) -> dict[str, Any]:
    if not path.is_file():
        return {"text": "", "nextOffset": 0, "reset": False, "size": 0}
    size = path.stat().st_size
    reset = False
    if offset > size:
        offset = 0
        reset = True
    with path.open("rb") as handle:
        handle.seek(offset)
        raw = handle.read()
        next_offset = handle.tell()
    text = raw.decode("utf-8", errors="replace").replace("\x00", "")
    return {"text": text, "nextOffset": next_offset, "reset": reset, "size": size}


def _expert_stage_summaries(run_dir: Path, recipe_summary: dict[str, Any] | None) -> list[dict[str, Any]]:
    expert_root = run_dir / "expert"
    stages: list[dict[str, Any]] = []
    if expert_root.is_dir():
        for child in sorted(expert_root.iterdir()):
            if not child.is_dir() or child.name == "plans":
                continue
            summary = _decode_json_file(child / "summary.json")
            if summary is None:
                continue
            stages.append({"stageDir": str(child), **summary})
    if not stages and recipe_summary is not None:
        for item in recipe_summary.get("expertStages") or []:
            if isinstance(item, dict):
                stages.append(item)
    return stages


def _stage_plan_summaries(run_dir: Path) -> list[dict[str, Any]]:
    plan_root = run_dir / "expert" / "plans"
    if not plan_root.is_dir():
        return []
    plans: list[dict[str, Any]] = []
    for child in sorted(plan_root.iterdir()):
        if not child.is_dir():
            continue
        summary = _decode_json_file(child / "plan_summary.json")
        if summary is None:
            continue
        plans.append({"planDir": str(child), **summary})
    plans.sort(key=lambda item: (int(item.get("maxLength") or 0), str(item.get("stage") or "")))
    return plans


def _infer_unit(stage: str | None) -> str:
    if stage is None:
        return "items"
    lowered = stage.lower()
    if "sentinel" in lowered or "evaluate" in lowered or "stacker" in lowered:
        return "examples"
    if "context" in lowered or "expert" in lowered:
        return "records"
    return "items"


def _normalize_progress(
    status: dict[str, Any] | None,
    progress: dict[str, Any] | None,
    *,
    sentinel_summary: dict[str, Any] | None,
    expert_summary: dict[str, Any] | None,
    stacker_summary: dict[str, Any] | None,
    valid_metrics: dict[str, Any] | None,
    test_metrics: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = dict(progress or {})
    stage = payload.get("currentStage") or payload.get("stage") or (status or {}).get("currentStage") or (status or {}).get("currentStep")
    state = payload.get("state") or (status or {}).get("state")
    current_items = payload.get("currentItems")
    if current_items is None:
        current_items = payload.get("recordsSeen")
    if current_items is None and payload.get("optimizerStep") is not None and _infer_unit(stage) == "records":
        current_items = payload.get("recordsSeen")
    total_items = payload.get("totalItems")
    if total_items is None:
        total_items = payload.get("totalTargetRecords")
    percent = payload.get("percent")
    if percent is None:
        progress_fraction = payload.get("progressFraction")
        if progress_fraction is not None:
            percent = round(float(progress_fraction) * 100, 4)
        elif current_items is not None and total_items:
            percent = round((float(current_items) / max(1.0, float(total_items))) * 100, 4)
    metrics = dict(payload.get("metrics") or {})
    for key in [
        "optimizerStep",
        "latestLoss",
        "movingAverageLoss",
        "meanConfidence",
        "gradientNorm",
        "labelEntropy",
        "examplesPerSecond",
        "batchesPerSecond",
        "lastBatchBuildSeconds",
        "movingAverageBatchBuildSeconds",
        "lastOptimizerStepSeconds",
        "movingAverageOptimizerStepSeconds",
        "lastCheckpointWriteSeconds",
        "gpuMemoryAllocatedMb",
        "gpuMemoryReservedMb",
        "consecutiveNonfiniteGradients",
        "hardNegativeReplayCount",
        "validThreatRecall",
        "validMacroF1",
        "stackerBackend",
        "phase",
        "processedBatches",
        "batchSize",
        "threshold",
        "thresholdRecall",
    ]:
        if key in payload and key not in metrics:
            metrics[key] = payload[key]
    if sentinel_summary is not None:
        metrics.setdefault("sentinelThreshold", sentinel_summary.get("threshold"))
        metrics.setdefault("sentinelThresholdRecall", sentinel_summary.get("thresholdRecall"))
        metrics.setdefault("sentinelStructuredBackend", sentinel_summary.get("structuredBackend"))
    if expert_summary is not None:
        metrics.setdefault("expertBackend", expert_summary.get("backend"))
        metrics.setdefault("expertAverageLoss", expert_summary.get("averageLoss"))
        metrics.setdefault("expertRetentionOutcome", expert_summary.get("retentionOutcome"))
    if stacker_summary is not None:
        metrics.setdefault("stackerBackend", stacker_summary.get("backend"))
        calibration = stacker_summary.get("calibration") or {}
        metrics.setdefault("expertTemperature", calibration.get("expertTemperature"))
    if valid_metrics is not None:
        metrics.setdefault("validThreatRecall", valid_metrics.get("threatRecall"))
        metrics.setdefault("validMacroF1", valid_metrics.get("macroF1"))
    if test_metrics is not None:
        metrics.setdefault("testThreatRecall", test_metrics.get("threatRecall"))
        metrics.setdefault("testMacroF1", test_metrics.get("macroF1"))
    return {
        **payload,
        "stage": stage,
        "currentStage": stage,
        "state": state,
        "currentItems": current_items,
        "totalItems": total_items,
        "percent": percent,
        "unit": payload.get("unit") or _infer_unit(stage),
        "metrics": metrics,
        "updatedAt": payload.get("updatedAt") or (status or {}).get("updatedAt"),
    }


def _overall_progress_fraction(
    progress: dict[str, Any],
    *,
    sentinel_summary: dict[str, Any] | None,
    stage_summaries: list[dict[str, Any]],
    stage_plan_summaries: list[dict[str, Any]],
    stacker_summary: dict[str, Any] | None,
    recipe_summary: dict[str, Any] | None,
    bundle_manifest: dict[str, Any] | None,
) -> float | None:
    expert_phase_count = max(len(stage_plan_summaries), len(stage_summaries))
    total_phases = 1 + expert_phase_count + 3
    if total_phases <= 0:
        return None
    if recipe_summary is not None and progress.get("state") == "completed":
        return 1.0

    stage_name = progress.get("currentStage")
    stage_fraction = progress.get("progressFraction")
    if stage_fraction is None and progress.get("percent") is not None:
        stage_fraction = float(progress["percent"]) / 100.0
    if stage_fraction is None:
        stage_fraction = 0.0

    if stage_name == "phase_1_ml_sentinel":
        return max(0.0, min(1.0, stage_fraction / total_phases))

    ordered_stage_names = [str(item.get("stage")) for item in stage_plan_summaries if item.get("stage")]
    if stage_name in ordered_stage_names:
        completed_before = 1 + ordered_stage_names.index(str(stage_name))
        return max(0.0, min(1.0, (completed_before + stage_fraction) / total_phases))

    if stage_name in {"phase_3_stacker", "train_stacker"}:
        completed_before = 1 + expert_phase_count
        return max(0.0, min(1.0, (completed_before + stage_fraction) / total_phases))

    if stage_name in {"phase_4_package_bundle", "package_runtime_bundle"}:
        completed_before = 2 + expert_phase_count
        return max(0.0, min(1.0, (completed_before + stage_fraction) / total_phases))

    if stage_name in {"phase_5_evaluate_valid", "phase_5_evaluate_test", "evaluate"}:
        completed_before = 3 + expert_phase_count
        if stage_name == "phase_5_evaluate_test":
            stage_fraction = max(stage_fraction, 0.5)
        return max(0.0, min(1.0, (completed_before + stage_fraction) / total_phases))

    completed_phases = 0
    if sentinel_summary is not None:
        completed_phases += 1
    completed_phases += len(stage_summaries)
    if stacker_summary is not None:
        completed_phases += 1
    if bundle_manifest is not None:
        completed_phases += 1
    if recipe_summary is not None:
        completed_phases += 1
    return max(0.0, min(1.0, completed_phases / total_phases))


def _dashboard_summary(
    progress: dict[str, Any],
    *,
    status: dict[str, Any] | None,
    sentinel_summary: dict[str, Any] | None,
    expert_summary: dict[str, Any] | None,
    stacker_summary: dict[str, Any] | None,
    valid_metrics: dict[str, Any] | None,
    test_metrics: dict[str, Any] | None,
    stage_summaries: list[dict[str, Any]],
    stage_plan_summaries: list[dict[str, Any]],
    recipe_summary: dict[str, Any] | None,
    bundle_manifest: dict[str, Any] | None,
) -> dict[str, Any]:
    metrics = dict(progress.get("metrics") or {})
    progress_fraction = progress.get("progressFraction")
    if progress_fraction is None and progress.get("percent") is not None:
        progress_fraction = float(progress["percent"]) / 100.0
    return {
        "state": progress.get("state") or (status or {}).get("state") or "unknown",
        "currentStage": progress.get("currentStage") or (status or {}).get("currentStage") or (status or {}).get("currentStep"),
        "progressFraction": progress_fraction,
        "stageProgressFraction": progress_fraction,
        "overallProgressFraction": _overall_progress_fraction(
            progress,
            sentinel_summary=sentinel_summary,
            stage_summaries=stage_summaries,
            stage_plan_summaries=stage_plan_summaries,
            stacker_summary=stacker_summary,
            recipe_summary=recipe_summary,
            bundle_manifest=bundle_manifest,
        ),
        "recordsSeen": progress.get("recordsSeen", progress.get("currentItems")),
        "totalTargetRecords": progress.get("totalTargetRecords", progress.get("totalItems")),
        "optimizerStep": metrics.get("optimizerStep") if metrics else progress.get("optimizerStep"),
        "latestLoss": metrics.get("latestLoss") if metrics else progress.get("latestLoss"),
        "movingAverageLoss": metrics.get("movingAverageLoss") if metrics else progress.get("movingAverageLoss"),
        "meanConfidence": metrics.get("meanConfidence"),
        "gradientNorm": metrics.get("gradientNorm"),
        "labelEntropy": metrics.get("labelEntropy"),
        "examplesPerSecond": metrics.get("examplesPerSecond"),
        "batchesPerSecond": metrics.get("batchesPerSecond"),
        "lastBatchBuildSeconds": metrics.get("lastBatchBuildSeconds"),
        "movingAverageBatchBuildSeconds": metrics.get("movingAverageBatchBuildSeconds"),
        "lastOptimizerStepSeconds": metrics.get("lastOptimizerStepSeconds"),
        "movingAverageOptimizerStepSeconds": metrics.get("movingAverageOptimizerStepSeconds"),
        "lastCheckpointWriteSeconds": metrics.get("lastCheckpointWriteSeconds"),
        "gpuMemoryAllocatedMb": metrics.get("gpuMemoryAllocatedMb"),
        "gpuMemoryReservedMb": metrics.get("gpuMemoryReservedMb"),
        "consecutiveNonfiniteGradients": metrics.get("consecutiveNonfiniteGradients"),
        "currentLabelCounts": progress.get("currentLabelCounts") or metrics.get("currentLabelCounts"),
        "lastCheckpointPath": progress.get("lastCheckpointPath"),
        "lastCheckpointAt": progress.get("lastCheckpointAt"),
        "hardNegativeReplayCount": (recipe_summary or {}).get("hardNegativeReplayCount") or metrics.get("hardNegativeReplayCount"),
        "validThreatRecall": (valid_metrics or {}).get("threatRecall") or metrics.get("validThreatRecall"),
        "testThreatRecall": (test_metrics or {}).get("threatRecall") or metrics.get("testThreatRecall"),
        "validMacroF1": (valid_metrics or {}).get("macroF1") or metrics.get("validMacroF1"),
        "testMacroF1": (test_metrics or {}).get("macroF1") or metrics.get("testMacroF1"),
        "bundleVersion": (bundle_manifest or {}).get("bundleVersion"),
        "sentinelThreshold": (sentinel_summary or {}).get("threshold"),
        "sentinelThresholdRecall": (sentinel_summary or {}).get("thresholdRecall"),
        "sentinelStructuredBackend": (sentinel_summary or {}).get("structuredBackend"),
        "expertBackend": (expert_summary or {}).get("backend"),
        "stackerBackend": (stacker_summary or {}).get("backend"),
        "completedStageCount": len(stage_summaries),
        "stageCount": max(len(stage_plan_summaries), len(stage_summaries)),
    }


def _file_descriptor(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"path": str(path), "missing": True}
    stat = path.stat()
    return {"path": str(path), "size": stat.st_size, "updatedAt": stat.st_mtime}


def load_training_run_state(run_dir: str | Path) -> dict[str, Any]:
    root = Path(run_dir).resolve()
    status = _decode_json_file(root / "status.json")
    progress = _decode_json_file(root / "progress.json")
    sentinel_summary = _decode_json_file(root / "sentinel" / "summary.json")
    recipe_summary = _decode_json_file(root / "recipe_summary.json")
    expert_summary = _decode_json_file(root / "expert" / "summary.json")
    stage_summaries = _expert_stage_summaries(root, recipe_summary)
    if expert_summary is None:
        expert_summary = stage_summaries[-1] if stage_summaries else None
    stacker_summary = _decode_json_file(root / "stacker" / "summary.json")
    if stacker_summary is None and recipe_summary:
        stacker_summary = recipe_summary.get("stacker")
    valid_metrics = _decode_json_file(root / "metrics-valid.json")
    if valid_metrics is None and recipe_summary:
        valid_metrics = ((recipe_summary.get("metrics") or {}).get("valid"))
    test_metrics = _decode_json_file(root / "metrics-test.json")
    if test_metrics is None and recipe_summary:
        test_metrics = ((recipe_summary.get("metrics") or {}).get("test"))
    stage_plan_summaries = _stage_plan_summaries(root)
    bundle_manifest = (
        _decode_json_file(root / "bundle" / "bundle.json")
        or _decode_json_file(root / "bundle" / "bundle_manifest.json")
        or _decode_json_file(root / "runtime_bundle" / "bundle.json")
        or _decode_json_file(root / "runtime_bundle" / "bundle_manifest.json")
    )
    release_manifest = _decode_json_file(root / "bundle" / "manifest.json") or _decode_json_file(root / "runtime_bundle" / "manifest.json")
    progress_view = _normalize_progress(
        status,
        progress,
        sentinel_summary=sentinel_summary,
        expert_summary=expert_summary,
        stacker_summary=stacker_summary,
        valid_metrics=valid_metrics,
        test_metrics=test_metrics,
    )
    dashboard = _dashboard_summary(
        progress_view,
        status=status,
        sentinel_summary=sentinel_summary,
        expert_summary=expert_summary,
        stacker_summary=stacker_summary,
        valid_metrics=valid_metrics,
        test_metrics=test_metrics,
        stage_summaries=stage_summaries,
        stage_plan_summaries=stage_plan_summaries,
        recipe_summary=recipe_summary,
        bundle_manifest=bundle_manifest,
    )
    files = {
        "status": _file_descriptor(root / "status.json"),
        "progress": _file_descriptor(root / "progress.json"),
        "events": _file_descriptor(root / "events.jsonl"),
        "trainLog": _file_descriptor(root / "train.log"),
        "sentinelSummary": _file_descriptor(root / "sentinel" / "summary.json"),
        "recipeSummary": _file_descriptor(root / "recipe_summary.json"),
        "bundleManifest": _file_descriptor(root / "bundle" / "bundle.json") if (root / "bundle" / "bundle.json").is_file() else _file_descriptor(root / "bundle" / "bundle_manifest.json"),
        "releaseManifest": _file_descriptor(root / "bundle" / "manifest.json"),
    }
    return {
        "runDir": str(root),
        "status": status,
        "progress": progress_view,
        "dashboard": dashboard,
        "sentinelSummary": sentinel_summary,
        "expertSummary": expert_summary,
        "stackerSummary": stacker_summary,
        "recipeSummary": recipe_summary,
        "validMetrics": valid_metrics,
        "testMetrics": test_metrics,
        "bundleManifest": bundle_manifest,
        "releaseManifest": release_manifest,
        "stageSummaries": stage_summaries,
        "stagePlanSummaries": stage_plan_summaries,
        "recentEvents": _tail_jsonl(root / "events.jsonl"),
        "files": files,
    }


def _html_page(initial_state: dict[str, Any] | None = None) -> bytes:
    initial_payload = json.dumps(initial_state or {})
    initial_stage = ((initial_state or {}).get("dashboard") or {}).get("currentStage") or "Loading..."
    html = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SafeBrowse Model Guard Monitor</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #081120;
      --panel: #12203c;
      --border: rgba(255,255,255,0.08);
      --text: #eef3ff;
      --muted: #9fb0d6;
      --accent: #5ac8ff;
      --ok: #6ee7a4;
      --warn: #ffd166;
      --danger: #ff6b6b;
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: radial-gradient(circle at top, #173160, var(--bg) 52%); color: var(--text); font-family: "Segoe UI", ui-sans-serif, sans-serif; }
    .wrap { max-width: 1320px; margin: 0 auto; padding: 20px; }
    h1 { margin: 0 0 10px; font-size: 30px; }
    .sub { color: var(--muted); margin-bottom: 18px; word-break: break-all; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 16px; }
    .panel { background: rgba(255,255,255,0.035); border: 1px solid var(--border); border-radius: 18px; padding: 18px; }
    .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 10px; }
    .value { font-size: 24px; font-weight: 600; }
    .badge { display: inline-block; margin-top: 10px; padding: 6px 12px; border-radius: 999px; background: rgba(255,255,255,0.08); font-size: 12px; }
    .badges { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
    .progress { width: 100%; height: 14px; background: rgba(255,255,255,0.08); border-radius: 999px; overflow: hidden; margin-top: 12px; }
    .bar { height: 100%; width: 0%; background: linear-gradient(90deg, var(--accent), #7bffcf); transition: width 0.3s ease; }
    pre { margin: 0; white-space: pre-wrap; word-break: break-word; font-family: Consolas, "Courier New", monospace; font-size: 12px; line-height: 1.45; }
    .log { min-height: 320px; max-height: 520px; overflow: auto; background: rgba(0,0,0,0.25); border-radius: 14px; padding: 16px; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>SafeBrowse Model Guard Monitor</h1>
    <div class="sub" id="runDir">Loading...</div>
    <div class="sub" id="initialStage">Current stage: __INITIAL_STAGE__</div>
    <div class="grid">
      <div class="panel"><div class="label">State</div><div class="value" id="state">unknown</div><div class="badges"><div class="badge" id="stage">idle</div><div class="badge" id="stageCount">0 / 0 complete</div></div></div>
      <div class="panel"><div class="label">Progress</div><div class="value" id="progressText">0 processed</div><div class="progress"><div class="bar" id="bar"></div></div><div class="badges"><div class="badge" id="percent">0%</div><div class="badge" id="overallPercent">0% total</div></div></div>
      <div class="panel"><div class="label">Loss / Confidence</div><div class="value" id="lossCard">-</div><div class="badges"><div class="badge" id="throughput">-</div><div class="badge" id="stabilityCard">-</div></div></div>
      <div class="panel"><div class="label">Threat Recall</div><div class="value" id="recallCard">-</div><div class="badges"><div class="badge" id="checkpointCard">-</div><div class="badge" id="bundleCard">-</div></div></div>
    </div>
    <div class="grid">
      <div class="panel"><div class="label">Progress Details</div><pre id="progressJson">{}</pre></div>
      <div class="panel"><div class="label">Sentinel</div><pre id="sentinel">{}</pre></div>
      <div class="panel"><div class="label">Expert</div><pre id="expert">{}</pre></div>
      <div class="panel"><div class="label">Stacker / Eval</div><pre id="metrics">{}</pre></div>
    </div>
    <div class="grid">
      <div class="panel"><div class="label">Recent Events</div><pre id="events">[]</pre></div>
      <div class="panel"><div class="label">Files</div><pre id="files">{}</pre></div>
    </div>
    <div class="panel">
      <div class="label">Live Log</div>
      <div class="log"><pre id="log"></pre></div>
    </div>
  </div>
  <script>
    let offset = 0;
    let initialized = false;
    window.__INITIAL_STATE__ = __INITIAL_STATE__;
    const pretty = (value) => JSON.stringify(value ?? {}, null, 2);
    async function refreshState() {
      const response = await fetch('/api/state', { cache: 'no-store' });
      const payload = await response.json();
      const status = payload.status ?? {};
      const progress = payload.progress ?? {};
      const dashboard = payload.dashboard ?? {};
      const metrics = progress.metrics ?? {};
      document.getElementById('runDir').textContent = payload.runDir;
      document.getElementById('initialStage').textContent = `Current stage: ${dashboard.currentStage ?? progress.currentStage ?? status.currentStage ?? status.currentStep ?? 'idle'}`;
      document.getElementById('state').textContent = dashboard.state ?? status.state ?? progress.state ?? 'unknown';
      document.getElementById('stage').textContent = dashboard.currentStage ?? progress.currentStage ?? status.currentStage ?? status.currentStep ?? 'idle';
      const current = dashboard.recordsSeen ?? progress.currentItems ?? 0;
      const total = dashboard.totalTargetRecords ?? progress.totalItems ?? 0;
      const unit = progress.unit ?? 'items';
      document.getElementById('progressText').textContent = total ? `${current.toLocaleString()} / ${total.toLocaleString()} ${unit}` : `${current.toLocaleString()} ${unit}`;
      const stagePercent = dashboard.progressFraction != null ? (Number(dashboard.progressFraction) * 100) : (progress.percent ?? 0);
      const overallPercent = dashboard.overallProgressFraction != null ? (Number(dashboard.overallProgressFraction) * 100) : stagePercent;
      document.getElementById('percent').textContent = `${stagePercent.toFixed(2)}% stage`;
      document.getElementById('overallPercent').textContent = `${overallPercent.toFixed(2)}% total`;
      document.getElementById('bar').style.width = `${Math.max(0, Math.min(100, stagePercent))}%`;
      const completedStageCount = dashboard.completedStageCount ?? 0;
      const stageCount = dashboard.stageCount ?? 0;
      document.getElementById('stageCount').textContent = `${completedStageCount} / ${stageCount} complete`;
      const loss = dashboard.movingAverageLoss ?? dashboard.latestLoss ?? metrics.movingAverageLoss ?? metrics.latestLoss ?? payload.expertSummary?.averageLoss;
      const confidence = dashboard.meanConfidence ?? metrics.meanConfidence;
      document.getElementById('lossCard').textContent = loss != null ? `${Number(loss).toFixed(4)}${confidence != null ? ` / ${Number(confidence).toFixed(4)}` : ''}` : '-';
      const throughputParts = [];
      const throughput = dashboard.examplesPerSecond ?? dashboard.batchesPerSecond ?? metrics.examplesPerSecond ?? metrics.batchesPerSecond;
      if (throughput != null) throughputParts.push(`${Number(throughput).toFixed(2)} /s`);
      const buildSeconds = dashboard.movingAverageBatchBuildSeconds ?? metrics.movingAverageBatchBuildSeconds;
      if (buildSeconds != null) throughputParts.push(`build ${Number(buildSeconds).toFixed(3)}s`);
      const optimizerSeconds = dashboard.movingAverageOptimizerStepSeconds ?? metrics.movingAverageOptimizerStepSeconds;
      if (optimizerSeconds != null) throughputParts.push(`step ${Number(optimizerSeconds).toFixed(3)}s`);
      const checkpointSeconds = dashboard.lastCheckpointWriteSeconds ?? metrics.lastCheckpointWriteSeconds;
      if (checkpointSeconds != null) throughputParts.push(`ckpt ${Number(checkpointSeconds).toFixed(3)}s`);
      document.getElementById('throughput').textContent = throughputParts.length ? throughputParts.join(' | ') : '-';
      const gradientNorm = dashboard.gradientNorm ?? metrics.gradientNorm;
      const labelEntropy = dashboard.labelEntropy ?? metrics.labelEntropy;
      const nonfinite = dashboard.consecutiveNonfiniteGradients ?? metrics.consecutiveNonfiniteGradients;
      const gpuAllocated = dashboard.gpuMemoryAllocatedMb ?? metrics.gpuMemoryAllocatedMb;
      const gpuReserved = dashboard.gpuMemoryReservedMb ?? metrics.gpuMemoryReservedMb;
      const stabilityParts = [];
      if (gradientNorm != null) stabilityParts.push(`grad ${Number(gradientNorm).toFixed(3)}`);
      if (labelEntropy != null) stabilityParts.push(`entropy ${Number(labelEntropy).toFixed(3)}`);
      if (nonfinite != null) stabilityParts.push(`nonfinite ${Number(nonfinite)}`);
      if (gpuAllocated != null) stabilityParts.push(`gpu ${Number(gpuAllocated).toFixed(0)}MB`);
      if (gpuReserved != null) stabilityParts.push(`reserved ${Number(gpuReserved).toFixed(0)}MB`);
      document.getElementById('stabilityCard').textContent = stabilityParts.length ? stabilityParts.join(' | ') : '-';
      const validRecall = dashboard.validThreatRecall ?? payload.validMetrics?.threatRecall ?? metrics.validThreatRecall;
      const testRecall = dashboard.testThreatRecall ?? payload.testMetrics?.threatRecall ?? metrics.testThreatRecall;
      document.getElementById('recallCard').textContent = validRecall != null || testRecall != null ? `valid ${validRecall ?? '-'} / test ${testRecall ?? '-'}` : '-';
      document.getElementById('checkpointCard').textContent = dashboard.lastCheckpointPath ?? progress.lastCheckpointPath ?? 'no checkpoint';
      document.getElementById('bundleCard').textContent = dashboard.bundleVersion ?? payload.bundleManifest?.bundleVersion ?? 'bundle pending';
      document.getElementById('progressJson').textContent = pretty(progress);
      document.getElementById('sentinel').textContent = pretty(payload.sentinelSummary);
      document.getElementById('expert').textContent = pretty(payload.expertSummary);
      document.getElementById('metrics').textContent = pretty({ stacker: payload.stackerSummary, valid: payload.validMetrics, test: payload.testMetrics });
      document.getElementById('events').textContent = pretty(payload.recentEvents);
      document.getElementById('files').textContent = pretty(payload.files);
      const trainLog = payload.files?.trainLog;
      if (!initialized && trainLog && !trainLog.missing) {
        offset = Math.max(0, (trainLog.size ?? 0) - 65536);
        initialized = true;
      }
    }
    async function refreshLog() {
      const response = await fetch(`/api/log?offset=${offset}`, { cache: 'no-store' });
      const payload = await response.json();
      if (payload.reset) {
        document.getElementById('log').textContent = '';
      }
      if (payload.text) {
        const view = document.getElementById('log');
        view.textContent += payload.text;
        view.parentElement.scrollTop = view.parentElement.scrollHeight;
      }
      offset = payload.nextOffset ?? offset;
    }
    async function tick() {
      try {
        await refreshState();
        await refreshLog();
      } catch (error) {
        document.getElementById('state').textContent = 'error';
        document.getElementById('stage').textContent = String(error);
      }
    }
    tick();
    setInterval(tick, 2000);
  </script>
</body>
</html>
"""
    return html.replace("__INITIAL_STATE__", initial_payload).replace("__INITIAL_STAGE__", initial_stage).encode("utf-8")


class _TrainingMonitorHandler(BaseHTTPRequestHandler):
    run_dir: Path

    def _json_response(self, payload: dict[str, Any], status: int = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._json_response({"ready": True, "runDir": str(self.run_dir), "exists": self.run_dir.is_dir()})
            return
        if parsed.path == "/":
            body = _html_page(load_training_run_state(self.run_dir))
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/state":
            self._json_response(load_training_run_state(self.run_dir))
            return
        if parsed.path == "/api/log":
            query = parse_qs(parsed.query)
            offset = max(0, int(query.get("offset", ["0"])[0]))
            self._json_response(_read_log_chunk(self.run_dir / "train.log", offset=offset))
            return
        self._json_response({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


def create_training_monitor_server(
    run_dir: str | Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8790,
) -> ThreadingHTTPServer:
    resolved = Path(run_dir).resolve()
    handler = type("BoundTrainingMonitorHandler", (_TrainingMonitorHandler,), {"run_dir": resolved})
    return ThreadingHTTPServer((host, port), handler)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8790)
    args = parser.parse_args()
    server = create_training_monitor_server(args.run_dir, host=args.host, port=args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
