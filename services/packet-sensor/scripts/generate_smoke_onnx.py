#!/usr/bin/env python3
"""Generate the non-trained sequence risk model used only for runtime smoke tests."""

from __future__ import annotations

import argparse
from pathlib import Path

import onnx
from onnx import TensorProto, checker, helper


def build_model() -> onnx.ModelProto:
    input_info = helper.make_tensor_value_info(
        "sequence_features",
        TensorProto.FLOAT,
        [1, 8, 4],
    )
    output_info = helper.make_tensor_value_info(
        "risk_score",
        TensorProto.FLOAT,
        [1, 1, 1],
    )
    reduce_mean = helper.make_node(
        "ReduceMean",
        inputs=["sequence_features"],
        outputs=["risk_score"],
        axes=[1, 2],
        keepdims=1,
    )
    graph = helper.make_graph(
        [reduce_mean],
        "sensel_sequence_risk_smoke",
        [input_info],
        [output_info],
    )
    model = helper.make_model(
        graph,
        producer_name="sensel-p0-runtime-smoke",
        opset_imports=[helper.make_opsetid("", 13)],
        ir_version=9,
    )
    helper.set_model_props(
        model,
        {
            "purpose": "runtime-smoke-only-not-a-trained-model",
            "feature_contract_id": "sequence-risk-smoke-v1",
        },
    )
    checker.check_model(model)
    return model


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    onnx.save_model(build_model(), args.output)
    print(f"wrote smoke model: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
