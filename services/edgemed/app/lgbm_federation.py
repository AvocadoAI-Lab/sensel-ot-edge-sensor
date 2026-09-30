"""LightGBM helpers for lab FL experiments."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import lightgbm as lgb
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier

from .classifier import DEFAULT_LGBM_BINARY, ClassifierBundle, binary_labels


def lgbm_booster(model: Any) -> lgb.Booster:
    if isinstance(model, LGBMClassifier):
        return model.booster_
    if isinstance(model, lgb.Booster):
        return model
    raise TypeError(f"unsupported LightGBM model type: {type(model)!r}")


def lgbm_num_trees(model: Any) -> int:
    return int(lgbm_booster(model).num_trees())


def _align_frame(frame: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    out = frame.copy()
    for name in features:
        if name not in out.columns:
            out[name] = np.nan
    return out


def continue_binary_lgbm(
    bundle: ClassifierBundle,
    frame: pd.DataFrame,
    *,
    extra_trees: int,
    seed: int,
    lgbm_params: dict[str, Any] | None = None,
) -> ClassifierBundle:
    aligned = _align_frame(frame, bundle.features)
    matrix = (
        bundle.preprocess.transform(aligned)
        if bundle.preprocess is not None
        else aligned[bundle.features].to_numpy(dtype=float)
    )
    labels = binary_labels(aligned["label"])
    if len(np.unique(labels)) < 2:
        return bundle
    existing = lgbm_num_trees(bundle.pipeline)
    params = dict(DEFAULT_LGBM_BINARY)
    if lgbm_params:
        params.update({key: value for key, value in lgbm_params.items() if value is not None})
    fit_params = dict(params)
    fit_params["n_estimators"] = int(extra_trees)
    fit_params["random_state"] = seed
    fit_params["verbose"] = -1
    classifier = LGBMClassifier(**fit_params)
    classifier.fit(
        matrix,
        labels,
        init_model=lgbm_booster(bundle.pipeline),
    )
    metadata = dict(bundle.metadata)
    metadata["continued_from_rounds"] = existing
    metadata["extra_trees"] = extra_trees
    metadata["training_rows"] = int(len(aligned))
    return ClassifierBundle(
        model_name=bundle.model_name,
        task="binary",
        pipeline=classifier,
        features=bundle.features,
        classes=bundle.classes,
        preprocess=bundle.preprocess,
        metadata=metadata,
    )


def aggregate_lgbm_sequential_continuation(
    global_bundle: ClassifierBundle,
    local_bundles: dict[str, ClassifierBundle],
    *,
    site_order: tuple[str, ...],
) -> tuple[ClassifierBundle, dict[str, int]]:
    """Lab proxy: apply each Edge's locally-trained model as the next init snapshot.

    Each entry in ``local_bundles`` must have been trained from the same round-start
    global model. We keep the last site's continued booster as the round global model.
    This differs from XGB parallel tree-append and is documented in experiment output.
    """
    added: dict[str, int] = {}
    current = deepcopy(global_bundle)
    base_trees = lgbm_num_trees(global_bundle.pipeline)
    for site_id in site_order:
        local = local_bundles[site_id]
        added[site_id] = lgbm_num_trees(local.pipeline) - base_trees
        current = local
    metadata = {
        **global_bundle.metadata,
        "aggregation": "sequential_local_snapshot",
        "global_rounds_before": base_trees,
        "trees_added_by_site": added,
        "global_rounds_after": lgbm_num_trees(current.pipeline),
        "note": "LightGBM lab proxy; not byte-identical to XGB parallel tree-append.",
    }
    return (
        ClassifierBundle(
            model_name=global_bundle.model_name,
            task="binary",
            pipeline=current.pipeline,
            features=global_bundle.features,
            classes=global_bundle.classes,
            preprocess=global_bundle.preprocess,
            metadata=metadata,
        ),
        added,
    )


def lgbm_tree_update_bytes(global_bundle: ClassifierBundle, local_bundle: ClassifierBundle) -> int:
    global_trees = lgbm_num_trees(global_bundle.pipeline)
    local_trees = lgbm_num_trees(local_bundle.pipeline)
    if local_trees <= global_trees:
        return 0
    return len(lgbm_booster(local_bundle.pipeline).model_to_string().encode("utf-8"))
