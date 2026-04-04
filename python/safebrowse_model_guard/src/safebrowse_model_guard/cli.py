from __future__ import annotations

import argparse
import json
from pathlib import Path

from .bundle import create_demo_bundle
from .server import create_model_guard_server
from .training import (
    evaluate,
    package_runtime_bundle,
    prepare_data,
    train_expert,
    train_sentinel,
    train_stacker,
)


def _print_json(payload: dict) -> None:
    print(json.dumps(payload, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="safebrowse-model-guard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare_data")
    prepare_parser.add_argument("--manifest", required=True)
    prepare_parser.add_argument("--output-dir", default=".local/model_guard/prepared")
    prepare_parser.add_argument("--data-root")

    sentinel_parser = subparsers.add_parser("train_sentinel")
    sentinel_parser.add_argument("--manifest", required=True)
    sentinel_parser.add_argument("--output-dir", required=True)
    sentinel_parser.add_argument("--data-root")
    sentinel_parser.add_argument("--limit", type=int)
    sentinel_parser.add_argument("--threat-threshold", type=float, default=0.55)

    expert_parser = subparsers.add_parser("train_expert")
    expert_parser.add_argument("--manifest", required=True)
    expert_parser.add_argument("--output-dir", required=True)
    expert_parser.add_argument("--data-root")
    expert_parser.add_argument("--limit", type=int)
    expert_parser.add_argument("--backbone", default="answerdotai/ModernBERT-base")
    expert_parser.add_argument("--backend", default="transformers", choices=["transformers", "smoke"])
    expert_parser.add_argument("--max-length", type=int, default=1024)
    expert_parser.add_argument("--top-k-chunks", type=int, default=3)
    expert_parser.add_argument("--epochs", type=float, default=1.0)
    expert_parser.add_argument("--batch-size", type=int, default=1)
    expert_parser.add_argument("--learning-rate", type=float, default=2e-5)

    stacker_parser = subparsers.add_parser("train_stacker")
    stacker_parser.add_argument("--manifest", required=True)
    stacker_parser.add_argument("--sentinel-dir", required=True)
    stacker_parser.add_argument("--expert-dir", required=True)
    stacker_parser.add_argument("--output-dir", required=True)
    stacker_parser.add_argument("--data-root")
    stacker_parser.add_argument("--limit", type=int)

    evaluate_parser = subparsers.add_parser("evaluate")
    evaluate_parser.add_argument("--manifest", required=True)
    evaluate_parser.add_argument("--bundle-dir", required=True)
    evaluate_parser.add_argument("--split", default="valid")
    evaluate_parser.add_argument("--data-root")
    evaluate_parser.add_argument("--limit", type=int)
    evaluate_parser.add_argument("--output-path")

    package_parser = subparsers.add_parser("package_runtime_bundle")
    package_parser.add_argument("--sentinel-dir", required=True)
    package_parser.add_argument("--expert-dir", required=True)
    package_parser.add_argument("--stacker-dir", required=True)
    package_parser.add_argument("--output-dir", required=True)
    package_parser.add_argument("--bundle-version", required=True)

    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--bundle-dir", required=True)
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8788)

    demo_parser = subparsers.add_parser("create_demo_bundle")
    demo_parser.add_argument("--output-dir", required=True)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "prepare_data":
        _print_json(
            prepare_data(args.manifest, output_dir=args.output_dir, data_root=args.data_root)
        )
        return
    if args.command == "train_sentinel":
        _print_json(
            train_sentinel(
                args.manifest,
                output_dir=args.output_dir,
                data_root=args.data_root,
                limit=args.limit,
                threat_threshold=args.threat_threshold,
            )
        )
        return
    if args.command == "train_expert":
        _print_json(
            train_expert(
                args.manifest,
                output_dir=args.output_dir,
                data_root=args.data_root,
                limit=args.limit,
                backbone=args.backbone,
                backend=args.backend,
                max_length=args.max_length,
                top_k_chunks=args.top_k_chunks,
                epochs=args.epochs,
                batch_size=args.batch_size,
                learning_rate=args.learning_rate,
            )
        )
        return
    if args.command == "train_stacker":
        _print_json(
            train_stacker(
                args.manifest,
                sentinel_dir=args.sentinel_dir,
                expert_dir=args.expert_dir,
                output_dir=args.output_dir,
                data_root=args.data_root,
                limit=args.limit,
            )
        )
        return
    if args.command == "evaluate":
        _print_json(
            evaluate(
                args.manifest,
                bundle_dir=args.bundle_dir,
                split=args.split,
                data_root=args.data_root,
                limit=args.limit,
                output_path=args.output_path,
            )
        )
        return
    if args.command == "package_runtime_bundle":
        _print_json(
            package_runtime_bundle(
                args.sentinel_dir,
                args.expert_dir,
                args.stacker_dir,
                output_dir=args.output_dir,
                bundle_version=args.bundle_version,
            )
        )
        return
    if args.command == "serve":
        server = create_model_guard_server(args.bundle_dir, host=args.host, port=args.port)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return
    if args.command == "create_demo_bundle":
        path = create_demo_bundle(Path(args.output_dir))
        _print_json({"bundleDir": str(path)})
        return
    parser.error(f"Unsupported command {args.command}")
