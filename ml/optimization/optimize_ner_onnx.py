from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.common.dnrti import DEFAULT_REPORTS_DIR, write_json  # noqa: E402


DEFAULT_MODEL_DIR = Path("ml/models/dnrti_bert_ner")
DEFAULT_FP32_DIR = Path("ml/models/dnrti_bert_ner_onnx_fp32")
DEFAULT_INT8_DIR = Path("ml/models/dnrti_bert_ner_onnx_int8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export the trained DNRTI token classifier to ONNX and INT8."
    )
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--fp32-dir", type=Path, default=DEFAULT_FP32_DIR)
    parser.add_argument("--int8-dir", type=Path, default=DEFAULT_INT8_DIR)
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS_DIR)
    parser.add_argument(
        "--reuse-fp32",
        action="store_true",
        help="Reuse an existing FP32 model.onnx instead of exporting again.",
    )
    return parser.parse_args()


def _copy_model_metadata(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for name in (
        "config.json",
        "tokenizer.json",
        "tokenizer_config.json",
        "special_tokens_map.json",
        "vocab.txt",
    ):
        source_file = source / name
        if source_file.exists():
            shutil.copy2(source_file, destination / name)


def optimize(args: argparse.Namespace) -> dict[str, object]:
    from onnx import TensorProto
    from onnxruntime.quantization import QuantType, quantize_dynamic
    from onnxruntime.transformers.optimizer import optimize_model
    from optimum.onnxruntime import ORTModelForTokenClassification
    from transformers import AutoConfig, AutoTokenizer

    source = args.model_dir.resolve()
    fp32_dir = args.fp32_dir.resolve()
    int8_dir = args.int8_dir.resolve()
    if not (source / "config.json").exists():
        raise FileNotFoundError(f"Missing transformer model: {source}")
    config = AutoConfig.from_pretrained(source)

    timings: dict[str, float] = {}
    fp32_model = fp32_dir / "model.onnx"
    if not args.reuse_fp32 or not fp32_model.exists():
        started = time.perf_counter()
        exported = ORTModelForTokenClassification.from_pretrained(source, export=True)
        exported.save_pretrained(fp32_dir)
        AutoTokenizer.from_pretrained(source).save_pretrained(fp32_dir)
        timings["export_seconds"] = time.perf_counter() - started
    else:
        timings["export_seconds"] = 0.0

    int8_dir.mkdir(parents=True, exist_ok=True)
    optimized_model = int8_dir / "model_optimized.onnx"
    started = time.perf_counter()
    optimized = optimize_model(
        str(fp32_model),
        model_type="bert",
        num_heads=int(config.num_attention_heads),
        hidden_size=int(config.hidden_size),
        use_gpu=False,
    )
    optimized.save_model_to_file(str(optimized_model))
    timings["graph_optimization_seconds"] = time.perf_counter() - started

    quantized_model = int8_dir / "model.onnx"
    started = time.perf_counter()
    # Quantize the original exported graph. Quantizing the ORT-fused graph can
    # silently corrupt token-classification logits on some CPU builds even
    # when model loading succeeds, so the fused artifact is kept for inspection
    # but is not used as the INT8 source.
    quantize_dynamic(
        str(fp32_model),
        str(quantized_model),
        weight_type=QuantType.QInt8,
        per_channel=False,
        extra_options={"DefaultTensorType": TensorProto.FLOAT},
    )
    timings["quantization_seconds"] = time.perf_counter() - started
    _copy_model_metadata(fp32_dir, int8_dir)

    report = {
        "source_model": args.model_dir.as_posix(),
        "fp32_model": (args.fp32_dir / "model.onnx").as_posix(),
        "int8_model": (args.int8_dir / "model.onnx").as_posix(),
        "fp32_bytes": fp32_model.stat().st_size,
        "optimized_fp32_bytes": optimized_model.stat().st_size,
        "int8_bytes": quantized_model.stat().st_size,
        "int8_quantized_from": "exported_fp32_graph",
        "size_reduction_ratio": 1.0 - quantized_model.stat().st_size / fp32_model.stat().st_size,
        "timings": timings,
        "activation_status": "experimental_not_enabled",
        "quality_gate": {
            "maximum_absolute_unseen_f1_drop": 0.01,
            "minimum_speedup": 1.5,
        },
    }
    output = args.reports_dir / "ner_onnx_optimization.json"
    write_json(output, report)
    report["report_path"] = str(output)
    return report


def main() -> None:
    report = optimize(parse_args())
    print(f"FP32 bytes: {report['fp32_bytes']}")
    print(f"INT8 bytes: {report['int8_bytes']}")
    print(f"Size reduction: {report['size_reduction_ratio']:.2%}")
    print(f"Report: {report['report_path']}")


if __name__ == "__main__":
    main()
