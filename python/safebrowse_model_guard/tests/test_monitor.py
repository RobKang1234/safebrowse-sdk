from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.request import urlopen

from safebrowse_model_guard.monitor import create_training_monitor_server, load_training_run_state


class TrainingMonitorTest(unittest.TestCase):
    def _write_json(self, path: Path, payload: dict, *, encoding: str = "utf-8") -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding=encoding)

    def test_load_training_run_state_decodes_bom_and_normalizes_progress(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            run_dir = Path(temporary_directory)
            self._write_json(
                run_dir / "status.json",
                {"currentStep": "train_recipe", "currentStage": "short_context_warmup", "state": "running"},
                encoding="utf-8-sig",
            )
            self._write_json(
                run_dir / "progress.json",
                {
                    "currentStage": "short_context_warmup",
                    "recordsSeen": 25,
                    "totalTargetRecords": 100,
                    "progressFraction": 0.25,
                    "latestLoss": 1.2345,
                    "movingAverageLoss": 1.5432,
                    "meanConfidence": 0.8123,
                    "gradientNorm": 3.25,
                    "state": "running",
                    "lastCheckpointPath": str(run_dir / "expert" / "active" / "latest"),
                    "updatedAt": "2026-04-05T12:00:00Z",
                },
                encoding="utf-8-sig",
            )
            self._write_json(run_dir / "sentinel" / "summary.json", {"threshold": 0.991, "thresholdRecall": 1.0, "structuredBackend": "xgboost_binary"})
            self._write_json(run_dir / "expert" / "summary.json", {"backend": "peft_hierarchical_modernbert_recipe", "averageLoss": 1.5432, "retentionOutcome": "latest_plus_sparse_milestones"})
            self._write_json(run_dir / "stacker" / "summary.json", {"backend": "catboost_multiclass_cpu", "calibration": {"expertTemperature": 1.25}})
            self._write_json(run_dir / "bundle" / "bundle.json", {"bundleVersion": "recipe-test"})
            self._write_json(run_dir / "bundle" / "manifest.json", {"retentionOutcome": "latest_plus_sparse_milestones"})
            self._write_json(run_dir / "metrics-valid.json", {"threatRecall": 0.99, "macroF1": 0.87})
            self._write_json(run_dir / "metrics-test.json", {"threatRecall": 0.98, "macroF1": 0.85})
            (run_dir / "events.jsonl").write_text('{"type":"checkpoint","step":25}\n', encoding="utf-8")

            state = load_training_run_state(run_dir)

            self.assertEqual(state["progress"]["currentStage"], "short_context_warmup")
            self.assertEqual(state["progress"]["currentItems"], 25)
            self.assertEqual(state["progress"]["totalItems"], 100)
            self.assertEqual(state["progress"]["percent"], 25.0)
            self.assertEqual(state["progress"]["unit"], "records")
            self.assertEqual(state["progress"]["metrics"]["movingAverageLoss"], 1.5432)
            self.assertEqual(state["progress"]["metrics"]["sentinelStructuredBackend"], "xgboost_binary")
            self.assertEqual(state["progress"]["metrics"]["validThreatRecall"], 0.99)
            self.assertEqual(state["bundleManifest"]["bundleVersion"], "recipe-test")
            self.assertEqual(state["releaseManifest"]["retentionOutcome"], "latest_plus_sparse_milestones")
            self.assertEqual(state["recentEvents"][0]["type"], "checkpoint")

    def test_monitor_server_serves_state_and_log(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            run_dir = Path(temporary_directory)
            self._write_json(run_dir / "status.json", {"currentStep": "train_recipe", "currentStage": "phase_1_ml_sentinel", "state": "running"})
            self._write_json(run_dir / "progress.json", {"currentStage": "phase_1_ml_sentinel", "recordsSeen": 10, "totalTargetRecords": 40, "progressFraction": 0.25, "state": "running"})
            (run_dir / "run.log.1").write_text("older retained line\n", encoding="utf-8")
            (run_dir / "run.log").write_text("hello monitor\n", encoding="utf-8")
            (run_dir / "events.jsonl.1").write_text('{"type":"older"}\n', encoding="utf-8")
            (run_dir / "events.jsonl").write_text('{"type":"newer"}\n', encoding="utf-8")

            server = create_training_monitor_server(run_dir, host="127.0.0.1", port=0)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                time.sleep(0.1)
                with urlopen(f"http://127.0.0.1:{port}/api/state") as response:
                    state = json.loads(response.read().decode("utf-8"))
                with urlopen(f"http://127.0.0.1:{port}/api/log?offset=0") as response:
                    log_payload = json.loads(response.read().decode("utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            self.assertEqual(state["progress"]["currentItems"], 10)
            self.assertEqual(state["progress"]["percent"], 25.0)
            self.assertEqual([item["type"] for item in state["recentEvents"]], ["older", "newer"])
            self.assertIn("hello monitor", log_payload["text"])

    def test_load_training_run_state_infers_hard_negative_replay_from_log(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            run_dir = Path(temporary_directory)
            self._write_json(run_dir / "status.json", {"currentStep": "train_recipe", "currentStage": "mid_context", "state": "running"})
            self._write_json(
                run_dir / "progress.json",
                {
                    "currentStage": "mid_context",
                    "recordsSeen": 600000,
                    "totalTargetRecords": 600000,
                    "progressFraction": 1.0,
                    "state": "completed",
                    "optimizerStep": 18750,
                },
            )
            self._write_json(run_dir / "expert" / "plans" / "short_context_warmup" / "plan_summary.json", {"stage": "short_context_warmup", "maxLength": 1024})
            self._write_json(run_dir / "expert" / "plans" / "mid_context" / "plan_summary.json", {"stage": "mid_context", "maxLength": 2048})
            self._write_json(run_dir / "expert" / "short_context_warmup" / "summary.json", {"stage": "short_context_warmup"})
            self._write_json(run_dir / "expert" / "mid_context" / "summary.json", {"stage": "mid_context"})
            (run_dir / "run.log").write_text(
                "\n".join(
                    [
                        "mid_context completed",
                        "scored 158000/1000000 stage examples for hard-negative replay; found 0",
                        "scored 160000/1000000 stage examples for hard-negative replay; found 3",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            state = load_training_run_state(run_dir)

            self.assertEqual(state["progress"]["currentStage"], "long_context")
            self.assertEqual(state["progress"]["phase"], "hard_negative_replay")
            self.assertEqual(state["progress"]["currentItems"], 160000)
            self.assertEqual(state["progress"]["totalItems"], 1000000)
            self.assertEqual(state["progress"]["unit"], "examples")
            self.assertEqual(state["progress"]["metrics"]["hardNegativeReplayCount"], 3)
            self.assertEqual(state["dashboard"]["completedStageCount"], 2)
            self.assertEqual(state["dashboard"]["stageCount"], 3)
            self.assertIn("hard-negative replay", state["dashboard"]["displayProgressText"])
            self.assertGreater(state["dashboard"]["overallProgressFraction"], 0.45)


if __name__ == "__main__":
    unittest.main()
