from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from xgboost import XGBClassifier


DEFAULT_EDGE_CSV = "experment/ML-EdgeIIoT-dataset.csv"
DEFAULT_MODEL_PATH = "experment/edge_iiot_xgb_model.joblib"
DEFAULT_PCAP_FOLDER = "attack"
DEFAULT_EXTRACTED_FOLDER = "experment/extracted-attack-edge-csvs"
DEFAULT_PREDICTIONS_CSV = "experment/edge_iiot_attack_predictions.csv"
DEFAULT_REPORT_CSV = "experment/edge_iiot_schema_value_report.csv"

LABEL_COLUMNS = {"Attack_label", "Attack_type"}

# Edge-IIoTset uses Wireshark/tshark packet fields, not CICFlowMeter flow
# fields. These defaults match the published ML/DL CSV feature names.
EDGE_IIOT_COLUMNS = [
    "frame.time",
    "ip.src_host",
    "ip.dst_host",
    "arp.dst.proto_ipv4",
    "arp.opcode",
    "arp.hw.size",
    "arp.src.proto_ipv4",
    "icmp.checksum",
    "icmp.seq_le",
    "icmp.transmit_timestamp",
    "icmp.unused",
    "http.file_data",
    "http.content_length",
    "http.request.uri.query",
    "http.request.method",
    "http.referer",
    "http.request.full_uri",
    "http.request.version",
    "http.response",
    "http.tls_port",
    "tcp.ack",
    "tcp.ack_raw",
    "tcp.checksum",
    "tcp.connection.fin",
    "tcp.connection.rst",
    "tcp.connection.syn",
    "tcp.connection.synack",
    "tcp.dstport",
    "tcp.flags",
    "tcp.flags.ack",
    "tcp.len",
    "tcp.options",
    "tcp.payload",
    "tcp.seq",
    "tcp.srcport",
    "udp.port",
    "udp.stream",
    "udp.time_delta",
    "dns.qry.name",
    "dns.qry.name.len",
    "dns.qry.qu",
    "dns.qry.type",
    "dns.retransmission",
    "dns.retransmit_request",
    "dns.retransmit_request_in",
    "mqtt.conack.flags",
    "mqtt.conflag.cleansess",
    "mqtt.conflags",
    "mqtt.hdrflags",
    "mqtt.len",
    "mqtt.msg_decoded_as",
    "mqtt.msg",
    "mqtt.msgtype",
    "mqtt.proto_len",
    "mqtt.protoname",
    "mqtt.topic",
    "mqtt.topic_len",
    "mqtt.ver",
    "mbtcp.len",
    "mbtcp.trans_id",
    "mbtcp.unit_id",
    "Attack_label",
    "Attack_type",
]

# These are commonly removed by Edge-IIoTset preprocessing papers because they
# are identifiers, timestamps, ports, URIs, or payload content. Keeping them can
# make the model memorize the dataset environment instead of attack behavior.
EDGE_DROP_IDENTITY_PAYLOAD_COLUMNS = {
    "frame.time",
    "ip.dst_host",
    "ip.src_host",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    "http.file_data",
    "http.request.full_uri",
    "icmp.transmit_timestamp",
    "http.request.uri.query",
    "tcp.options",
    "tcp.payload",
    "tcp.srcport",
    "tcp.dstport",
    "udp.port",
    "mqtt.msg",
}

MISSING_STRINGS = {"", "nan", "none", "null", "na", "n/a", "<nan>"}


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(col).replace("\ufeff", "").strip() for col in df.columns]
    return df.loc[:, ~df.columns.duplicated()]


def read_csv(path: str | Path, *, sample_rows: int | None = None) -> pd.DataFrame:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"CSV not found: {path}")
    df = pd.read_csv(path, low_memory=False, nrows=sample_rows)
    return normalize_columns(df)


def read_many_csvs(paths: Iterable[Path]) -> pd.DataFrame:
    frames = []
    for path in paths:
        df = pd.read_csv(path, low_memory=False)
        df = normalize_columns(df)
        df["__source_file__"] = path.name
        frames.append(df)
        print(f"Loaded {path.name}: rows={len(df):,}, cols={df.shape[1]:,}")
    if not frames:
        raise RuntimeError("No CSV files were loaded.")
    return pd.concat(frames, ignore_index=True)


def pcap_files(folder: str | Path) -> list[Path]:
    folder = Path(folder)
    files = sorted([*folder.glob("*.pcap"), *folder.glob("*.pcapng"), *folder.glob("*.cap")])
    if not files:
        raise FileNotFoundError(f"No PCAP files found in: {folder}")
    return files


def extracted_csv_files(folder: str | Path) -> list[Path]:
    folder = Path(folder)
    files = sorted(folder.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No extracted CSV files found in: {folder}")
    return files


def edge_columns_from_csv(edge_csv: str | Path | None) -> list[str]:
    if edge_csv is None:
        return list(EDGE_IIOT_COLUMNS)
    path = Path(edge_csv)
    if not path.exists():
        return list(EDGE_IIOT_COLUMNS)
    return list(read_csv(path, sample_rows=0).columns)


def feature_columns_from_raw_columns(raw_columns: list[str]) -> list[str]:
    return [col for col in raw_columns if col not in LABEL_COLUMNS and col != "__source_file__"]


def first_repeated_value(text: str) -> str:
    # tshark can emit repeated fields. The extractor uses occurrence=f, but this
    # also protects against already-aggregated values in downloaded CSVs.
    for sep in ("|", ";"):
        if sep in text:
            return text.split(sep, 1)[0].strip()
    return text


def parse_numeric_value(value: object) -> float:
    if pd.isna(value):
        return np.nan

    text = str(value).strip()
    if text.lower() in MISSING_STRINGS:
        return np.nan
    text = first_repeated_value(text)

    lower = text.lower()
    if lower in {"true", "yes"}:
        return 1.0
    if lower in {"false", "no"}:
        return 0.0

    if re.fullmatch(r"0x[0-9a-fA-F]+", text):
        return float(int(text, 16))

    # Some exported protocol fields contain comma-separated repeated values.
    # Treat those as not safely numeric instead of silently changing meaning.
    if "," in text:
        return np.nan

    return float(pd.to_numeric(text, errors="coerce"))


def numeric_parse_ratio(series: pd.Series) -> tuple[pd.Series, float, int]:
    raw = series.astype("string")
    non_empty = raw.notna() & ~raw.str.strip().str.lower().isin(MISSING_STRINGS)
    parsed = series.map(parse_numeric_value)
    denominator = int(non_empty.sum())
    if denominator == 0:
        return parsed, 1.0, 0
    return parsed, float(parsed.notna().sum() / denominator), denominator


def clean_string_series(series: pd.Series) -> pd.Series:
    values = series.astype("string").fillna("__MISSING__").str.strip()
    return values.mask(values.str.lower().isin(MISSING_STRINGS), "__MISSING__").astype(str)


def coerce_feature_types(
    df: pd.DataFrame,
    *,
    numeric_columns: list[str] | None = None,
    categorical_columns: list[str] | None = None,
    numeric_threshold: float = 0.95,
) -> tuple[pd.DataFrame, list[str], list[str], dict[str, object]]:
    df = normalize_columns(df)
    out = pd.DataFrame(index=df.index)

    if numeric_columns is not None or categorical_columns is not None:
        numeric_columns = numeric_columns or []
        categorical_columns = categorical_columns or []
        for col in numeric_columns:
            out[col] = df[col].map(parse_numeric_value) if col in df.columns else np.nan
        for col in categorical_columns:
            out[col] = clean_string_series(df[col]) if col in df.columns else "__MISSING__"
        return out, numeric_columns, categorical_columns, {
            "numeric_parse_ratios": {},
            "numeric_non_empty_counts": {},
        }

    numeric_cols: list[str] = []
    categorical_cols: list[str] = []
    ratios: dict[str, float] = {}
    non_empty_counts: dict[str, int] = {}

    for col in df.columns:
        parsed, ratio, non_empty_count = numeric_parse_ratio(df[col])
        ratios[col] = ratio
        non_empty_counts[col] = non_empty_count
        if ratio >= numeric_threshold:
            out[col] = parsed
            numeric_cols.append(col)
        else:
            out[col] = clean_string_series(df[col])
            categorical_cols.append(col)

    return out, numeric_cols, categorical_cols, {
        "numeric_parse_ratios": ratios,
        "numeric_non_empty_counts": non_empty_counts,
    }


def build_binary_labels(df: pd.DataFrame) -> tuple[pd.Series, str]:
    if "Attack_label" in df.columns:
        parsed = df["Attack_label"].map(parse_numeric_value)
        if parsed.notna().any():
            return (parsed.fillna(0) > 0).astype(int), "Attack_label"

        text = df["Attack_label"].astype(str).str.strip().str.lower()
        return (~text.isin({"0", "normal", "benign", "false"})).astype(int), "Attack_label"

    if "Attack_type" in df.columns:
        text = df["Attack_type"].astype(str).str.strip().str.lower()
        return (~text.isin({"normal", "benign", "0", "false"})).astype(int), "Attack_type"

    raise ValueError("No label column found. Expected Attack_label or Attack_type.")


def make_one_hot_encoder(min_frequency: int) -> OneHotEncoder:
    attempts = []
    base_kwargs = {"handle_unknown": "ignore"}
    if min_frequency > 1:
        base_kwargs["min_frequency"] = min_frequency

    for sparse_key in ("sparse_output", "sparse"):
        kwargs = dict(base_kwargs)
        kwargs[sparse_key] = True
        attempts.append(kwargs)

    for kwargs in attempts:
        try:
            return OneHotEncoder(**kwargs)
        except TypeError:
            continue

    return OneHotEncoder(handle_unknown="ignore")


def make_preprocessor(
    numeric_columns: list[str],
    categorical_columns: list[str],
    *,
    min_category_count: int,
) -> ColumnTransformer:
    transformers = []
    if numeric_columns:
        transformers.append(("num", SimpleImputer(strategy="median"), numeric_columns))
    if categorical_columns:
        categorical_pipeline = Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="constant", fill_value="__MISSING__")),
                ("onehot", make_one_hot_encoder(min_category_count)),
            ]
        )
        transformers.append(("cat", categorical_pipeline, categorical_columns))

    if not transformers:
        raise ValueError("No usable feature columns remain after preprocessing.")

    return ColumnTransformer(transformers=transformers, remainder="drop", sparse_threshold=1.0)


def train_xgb(X_train, y_train: pd.Series) -> XGBClassifier:
    pos = int((y_train == 1).sum())
    neg = int((y_train == 0).sum())
    model = XGBClassifier(
        objective="binary:logistic",
        n_estimators=350,
        max_depth=6,
        learning_rate=0.04,
        subsample=0.85,
        colsample_bytree=0.85,
        reg_lambda=1.0,
        min_child_weight=3,
        random_state=42,
        n_jobs=-1,
        tree_method="hist",
        eval_metric="aucpr",
        scale_pos_weight=(neg / pos) if pos else 1.0,
    )
    model.fit(X_train, y_train)
    return model


def choose_threshold(
    y_true: pd.Series,
    pred_proba: np.ndarray,
    *,
    strategy: str,
    fixed_threshold: float,
    min_precision: float,
) -> tuple[float, dict[str, float]]:
    if strategy == "fixed":
        return fixed_threshold, {}

    precision, recall, thresholds = precision_recall_curve(y_true, pred_proba)
    if len(thresholds) == 0:
        return fixed_threshold, {}

    precision = precision[:-1]
    recall = recall[:-1]
    if strategy == "f1":
        scores = (2 * precision * recall) / (precision + recall + 1e-12)
    elif strategy == "f2":
        scores = (5 * precision * recall) / (4 * precision + recall + 1e-12)
    else:
        raise ValueError(f"Unsupported threshold strategy: {strategy}")

    if min_precision > 0 and (precision >= min_precision).any():
        scores = np.where(precision >= min_precision, scores, -np.inf)

    idx = int(np.argmax(scores))
    return float(thresholds[idx]), {
        "validation_precision": float(precision[idx]),
        "validation_recall": float(recall[idx]),
        "validation_score": float(scores[idx]),
    }


def evaluate_predictions(
    y_true: pd.Series,
    pred_proba: np.ndarray,
    *,
    threshold: float,
    title: str,
) -> dict[str, float]:
    pred_label = (pred_proba >= threshold).astype(int)
    cm = confusion_matrix(y_true, pred_label, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    metrics = {
        "accuracy": float(accuracy_score(y_true, pred_label)),
        "roc_auc": float(roc_auc_score(y_true, pred_proba)),
        "pr_auc": float(average_precision_score(y_true, pred_proba)),
        "precision": float(tp / (tp + fp)) if tp + fp else 0.0,
        "recall": float(tp / (tp + fn)) if tp + fn else 0.0,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }

    print(f"\n=== {title} ===")
    print(f"Threshold : {threshold:.9f}")
    print(f"Accuracy  : {metrics['accuracy']:.4f}")
    print(f"ROC-AUC   : {metrics['roc_auc']:.4f}")
    print(f"PR-AUC    : {metrics['pr_auc']:.4f}")
    print(classification_report(y_true, pred_label, target_names=["Normal", "Attack"]))
    print("Confusion matrix [ [TN, FP], [FN, TP] ]")
    print(cm)
    return metrics


def prepare_training_frame(
    edge_csv: str | Path,
    *,
    keep_identity_payload: bool,
    numeric_threshold: float,
    sample_rows: int | None,
    drop_duplicates: bool,
) -> tuple[pd.DataFrame, pd.Series, dict[str, object]]:
    df = read_csv(edge_csv, sample_rows=sample_rows)
    original_rows = len(df)
    if drop_duplicates:
        df = df.drop_duplicates()

    y, label_source = build_binary_labels(df)
    raw_feature_columns = feature_columns_from_raw_columns(list(df.columns))
    dropped_columns = []
    if not keep_identity_payload:
        dropped_columns = [col for col in raw_feature_columns if col in EDGE_DROP_IDENTITY_PAYLOAD_COLUMNS]
        raw_feature_columns = [col for col in raw_feature_columns if col not in EDGE_DROP_IDENTITY_PAYLOAD_COLUMNS]

    X_raw = df[raw_feature_columns].copy()
    X_typed, numeric_columns, categorical_columns, diagnostics = coerce_feature_types(
        X_raw,
        numeric_threshold=numeric_threshold,
    )

    empty_columns = [col for col in X_typed.columns if X_typed[col].isna().all() or (X_typed[col] == "__MISSING__").all()]
    if empty_columns:
        X_typed = X_typed.drop(columns=empty_columns)
        numeric_columns = [col for col in numeric_columns if col not in empty_columns]
        categorical_columns = [col for col in categorical_columns if col not in empty_columns]

    constant_columns = []
    for col in X_typed.columns:
        if X_typed[col].nunique(dropna=True) <= 1:
            constant_columns.append(col)
    if constant_columns:
        X_typed = X_typed.drop(columns=constant_columns)
        numeric_columns = [col for col in numeric_columns if col not in constant_columns]
        categorical_columns = [col for col in categorical_columns if col not in constant_columns]

    used_feature_columns = list(X_typed.columns)
    training_meta = {
        "edge_csv": str(edge_csv),
        "original_rows": int(original_rows),
        "rows_after_drop_duplicates": int(len(df)),
        "label_source": label_source,
        "raw_edge_columns": list(df.columns),
        "raw_feature_columns_before_drops": feature_columns_from_raw_columns(list(df.columns)),
        "dropped_identity_payload_columns": dropped_columns,
        "dropped_empty_columns": empty_columns,
        "dropped_constant_columns": constant_columns,
        "feature_columns": used_feature_columns,
        "numeric_columns": numeric_columns,
        "categorical_columns": categorical_columns,
        "numeric_parse_ratios": diagnostics["numeric_parse_ratios"],
        "numeric_non_empty_counts": diagnostics["numeric_non_empty_counts"],
    }
    return X_typed, y.reset_index(drop=True), training_meta


def fit_bundle(
    X: pd.DataFrame,
    y: pd.Series,
    *,
    min_category_count: int,
    threshold_strategy: str,
    fixed_threshold: float,
    min_precision: float,
    file_max_threshold: float,
    file_ratio_threshold: float,
    training_meta: dict[str, object],
) -> dict[str, object]:
    fit_started = time.perf_counter()
    train_idx, test_idx = train_test_split(
        np.arange(len(X)),
        test_size=0.20,
        random_state=42,
        stratify=y,
    )
    train_idx, val_idx = train_test_split(
        train_idx,
        test_size=0.20,
        random_state=43,
        stratify=y.iloc[train_idx],
    )

    X_train = X.iloc[train_idx]
    y_train = y.iloc[train_idx]
    X_val = X.iloc[val_idx]
    y_val = y.iloc[val_idx]
    X_test = X.iloc[test_idx]
    y_test = y.iloc[test_idx]

    preprocessor = make_preprocessor(
        training_meta["numeric_columns"],
        training_meta["categorical_columns"],
        min_category_count=min_category_count,
    )
    threshold_fit_started = time.perf_counter()
    X_train_tx = preprocessor.fit_transform(X_train)
    threshold_model = train_xgb(X_train_tx, y_train)
    threshold_fit_seconds = time.perf_counter() - threshold_fit_started

    validation_predict_started = time.perf_counter()
    val_proba = threshold_model.predict_proba(preprocessor.transform(X_val))[:, 1]
    validation_predict_seconds = time.perf_counter() - validation_predict_started
    threshold, threshold_meta = choose_threshold(
        y_val,
        val_proba,
        strategy=threshold_strategy,
        fixed_threshold=fixed_threshold,
        min_precision=min_precision,
    )

    print("\nThreshold selection:")
    print(f"Strategy           : {threshold_strategy}")
    print(f"Selected threshold : {threshold:.9f}")
    for key, value in threshold_meta.items():
        print(f"{key:18s}: {value:.6f}")

    dev_idx = np.concatenate([train_idx, val_idx])
    eval_preprocessor = make_preprocessor(
        training_meta["numeric_columns"],
        training_meta["categorical_columns"],
        min_category_count=min_category_count,
    )
    eval_fit_started = time.perf_counter()
    X_dev_tx = eval_preprocessor.fit_transform(X.iloc[dev_idx])
    eval_model = train_xgb(X_dev_tx, y.iloc[dev_idx])
    eval_fit_seconds = time.perf_counter() - eval_fit_started

    test_predict_started = time.perf_counter()
    test_proba = eval_model.predict_proba(eval_preprocessor.transform(X_test))[:, 1]
    test_predict_seconds = time.perf_counter() - test_predict_started
    metrics = evaluate_predictions(y_test, test_proba, threshold=threshold, title="EDGE-IIOT HOLDOUT TEST")

    final_preprocessor = make_preprocessor(
        training_meta["numeric_columns"],
        training_meta["categorical_columns"],
        min_category_count=min_category_count,
    )
    final_fit_started = time.perf_counter()
    X_full_tx = final_preprocessor.fit_transform(X)
    final_model = train_xgb(X_full_tx, y)
    final_fit_seconds = time.perf_counter() - final_fit_started

    transformed_feature_names = get_transformed_feature_names(final_preprocessor)
    importance = pd.DataFrame(
        {
            "feature": transformed_feature_names[: len(final_model.feature_importances_)],
            "importance": final_model.feature_importances_,
        }
    ).sort_values("importance", ascending=False)

    print("\nTop feature importances:")
    print(importance.head(25).to_string(index=False))

    runtime = {
        "rows_total": int(len(X)),
        "features_total": int(X.shape[1]),
        "train_rows_threshold_model": int(len(X_train)),
        "validation_rows": int(len(X_val)),
        "test_rows": int(len(X_test)),
        "threshold_model_fit_seconds": float(threshold_fit_seconds),
        "validation_predict_seconds": float(validation_predict_seconds),
        "eval_model_fit_seconds": float(eval_fit_seconds),
        "test_predict_seconds": float(test_predict_seconds),
        "test_predict_rows_per_second": float(len(X_test) / test_predict_seconds)
        if test_predict_seconds > 0
        else float("inf"),
        "final_model_fit_seconds": float(final_fit_seconds),
        "fit_bundle_seconds": float(time.perf_counter() - fit_started),
    }

    print("\nRuntime:")
    print(f"Threshold model fit : {runtime['threshold_model_fit_seconds']:.3f}s")
    print(f"Eval model fit      : {runtime['eval_model_fit_seconds']:.3f}s")
    print(f"Final model fit     : {runtime['final_model_fit_seconds']:.3f}s")
    print(
        "Holdout prediction : "
        f"{runtime['test_predict_seconds']:.3f}s "
        f"({runtime['test_predict_rows_per_second']:.0f} rows/s)"
    )

    return {
        "model": final_model,
        "preprocessor": final_preprocessor,
        "threshold": threshold,
        "threshold_strategy": threshold_strategy,
        "fixed_threshold": fixed_threshold,
        "threshold_meta": threshold_meta,
        "file_max_threshold": file_max_threshold,
        "file_ratio_threshold": file_ratio_threshold,
        "training_meta": training_meta,
        "evaluation_metrics": metrics,
        "runtime": runtime,
        "feature_importance": importance,
    }


def get_transformed_feature_names(preprocessor: ColumnTransformer) -> list[str]:
    try:
        return list(preprocessor.get_feature_names_out())
    except Exception:
        names: list[str] = []
        for name, _, columns in preprocessor.transformers_:
            if name == "remainder":
                continue
            names.extend([str(col) for col in columns])
        return names


def train_command(args: argparse.Namespace) -> None:
    command_started = time.perf_counter()
    prep_started = time.perf_counter()
    X, y, training_meta = prepare_training_frame(
        args.edge_csv,
        keep_identity_payload=args.keep_identity_payload,
        numeric_threshold=args.numeric_threshold,
        sample_rows=args.sample_rows,
        drop_duplicates=not args.keep_duplicates,
    )
    preprocessing_seconds = time.perf_counter() - prep_started

    print("\nTraining data:")
    print(f"Rows                  : {len(X):,}")
    print(f"Features used          : {X.shape[1]:,}")
    print(f"Numeric features       : {len(training_meta['numeric_columns']):,}")
    print(f"Categorical features   : {len(training_meta['categorical_columns']):,}")
    print(f"Dropped ID/payload cols : {len(training_meta['dropped_identity_payload_columns']):,}")
    print(f"Dropped empty cols      : {len(training_meta['dropped_empty_columns']):,}")
    print(f"Dropped constant cols   : {len(training_meta['dropped_constant_columns']):,}")
    print("Class distribution:")
    print(y.value_counts().sort_index().rename(index={0: "normal", 1: "attack"}).to_string())

    bundle = fit_bundle(
        X,
        y,
        min_category_count=args.min_category_count,
        threshold_strategy=args.threshold_strategy,
        fixed_threshold=args.fixed_threshold,
        min_precision=args.min_precision,
        file_max_threshold=args.file_max_threshold,
        file_ratio_threshold=args.file_ratio_threshold,
        training_meta=training_meta,
    )
    total_seconds = time.perf_counter() - command_started
    bundle["runtime"]["preprocessing_seconds"] = float(preprocessing_seconds)
    bundle["runtime"]["train_command_total_seconds"] = float(total_seconds)

    model_path = Path(args.model_out)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model_path)
    print(f"\nSaved model bundle: {model_path}")

    importance_path = model_path.with_suffix(".feature_importance.csv")
    bundle["feature_importance"].to_csv(importance_path, index=False)
    print(f"Saved feature importance: {importance_path}")

    meta_path = model_path.with_suffix(".metadata.json")
    with meta_path.open("w", encoding="utf-8") as fh:
        json.dump(
            {
                "threshold": bundle["threshold"],
                "threshold_strategy": bundle["threshold_strategy"],
                "threshold_meta": bundle["threshold_meta"],
                "file_max_threshold": bundle["file_max_threshold"],
                "file_ratio_threshold": bundle["file_ratio_threshold"],
                "training_meta": bundle["training_meta"],
                "evaluation_metrics": bundle["evaluation_metrics"],
                "runtime": bundle["runtime"],
            },
            fh,
            indent=2,
        )
    print(f"Saved metadata: {meta_path}")
    print(f"Total train command: {total_seconds:.3f}s")


def tshark_path_or_fail(path: str | None) -> str:
    tshark = path or shutil.which("tshark")
    if not tshark:
        raise RuntimeError(
            "tshark was not found on PATH. Install Wireshark CLI tools first. "
            "On macOS with Homebrew, try: brew install wireshark"
        )
    return tshark


def available_tshark_fields(tshark: str) -> set[str] | None:
    try:
        result = subprocess.run(
            [tshark, "-G", "fields"],
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception:
        return None

    fields = set()
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "F":
            fields.add(parts[2])
    return fields


def run_tshark_extract(
    pcap_path: Path,
    output_csv: Path,
    *,
    tshark: str,
    requested_columns: list[str],
    valid_fields: set[str] | None,
) -> None:
    label_columns = [col for col in requested_columns if col in LABEL_COLUMNS]
    requested_fields = [col for col in requested_columns if col not in LABEL_COLUMNS]
    if valid_fields is not None:
        extract_fields = [field for field in requested_fields if field in valid_fields]
        invalid_fields = sorted(set(requested_fields) - set(extract_fields))
    else:
        extract_fields = requested_fields
        invalid_fields = []

    if not extract_fields:
        raise RuntimeError("No requested Edge-IIoT fields are valid for this tshark installation.")

    command = [
        tshark,
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for field in extract_fields:
        command.extend(["-e", field])

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as fh:
        result = subprocess.run(command, stdout=fh, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    df = pd.read_csv(output_csv, low_memory=False)
    df = normalize_columns(df)
    for col in requested_columns:
        if col not in df.columns:
            df[col] = ""
    for col in label_columns:
        df[col] = ""
    df = df[requested_columns]
    df.to_csv(output_csv, index=False)

    if invalid_fields:
        print(f"  skipped unsupported tshark fields: {len(invalid_fields)}")
        print(f"  sample unsupported fields: {invalid_fields[:10]}")


def extract_command(args: argparse.Namespace) -> None:
    tshark = tshark_path_or_fail(args.tshark)
    requested_columns = edge_columns_from_csv(args.edge_csv)
    valid_fields = available_tshark_fields(tshark)
    files = pcap_files(args.pcap_folder)
    output_folder = Path(args.output_folder)
    output_folder.mkdir(parents=True, exist_ok=True)

    print(f"Using tshark: {tshark}")
    print(f"PCAP files: {len(files)}")
    print(f"Requested Edge-IIoT columns: {len(requested_columns)}")
    print(f"Output folder: {output_folder}\n")

    success = 0
    failed = 0
    for pcap_path in files:
        output_csv = output_folder / f"{pcap_path.stem}.csv"
        print(f"[RUN ] {pcap_path.name} -> {output_csv.name}")
        try:
            run_tshark_extract(
                pcap_path,
                output_csv,
                tshark=tshark,
                requested_columns=requested_columns,
                valid_fields=valid_fields,
            )
            rows = len(pd.read_csv(output_csv, usecols=[requested_columns[0]], low_memory=False))
            print(f"[ OK ] rows={rows:,}")
            success += 1
        except Exception as exc:
            print(f"[FAIL] {pcap_path.name}: {exc}")
            failed += 1

    print("\nExtraction complete.")
    print(f"Successful: {success}")
    print(f"Failed    : {failed}")


def prepare_inference_frame(df: pd.DataFrame, bundle: dict[str, object]) -> tuple[pd.DataFrame, pd.Series]:
    meta = bundle["training_meta"]
    raw_feature_columns = meta["feature_columns"]
    numeric_columns = meta["numeric_columns"]
    categorical_columns = meta["categorical_columns"]

    source_files = (
        df["__source_file__"].copy()
        if "__source_file__" in df.columns
        else pd.Series(["unknown"] * len(df))
    )

    for col in raw_feature_columns:
        if col not in df.columns:
            df[col] = np.nan

    X_raw = df[raw_feature_columns].copy()
    X_typed, _, _, _ = coerce_feature_types(
        X_raw,
        numeric_columns=numeric_columns,
        categorical_columns=categorical_columns,
    )
    return X_typed[raw_feature_columns], source_files


def build_file_summary(
    predictions: pd.DataFrame,
    *,
    file_max_threshold: float,
    file_ratio_threshold: float,
) -> pd.DataFrame:
    summary = (
        predictions.groupby("source_file")
        .agg(
            records=("pred_label", "size"),
            malicious_records=("pred_label", "sum"),
            malicious_record_ratio=("pred_label", "mean"),
            mean_attack_probability=("pred_proba_attack", "mean"),
            median_attack_probability=("pred_proba_attack", "median"),
            p95_attack_probability=("pred_proba_attack", lambda s: float(s.quantile(0.95))),
            max_attack_probability=("pred_proba_attack", "max"),
        )
        .reset_index()
    )
    summary["file_pass_max_probability_rule"] = summary["max_attack_probability"] >= file_max_threshold
    summary["file_pass_ratio_rule"] = summary["malicious_record_ratio"] >= file_ratio_threshold
    summary["file_pred_label"] = (
        summary["file_pass_max_probability_rule"] & summary["file_pass_ratio_rule"]
    ).astype(int)
    return summary


def score_command(args: argparse.Namespace) -> None:
    bundle = joblib.load(args.model_path)
    threshold = bundle["threshold"] if args.threshold is None else args.threshold
    file_max_threshold = (
        bundle.get("file_max_threshold", threshold)
        if args.file_max_threshold is None
        else args.file_max_threshold
    )
    file_ratio_threshold = (
        bundle.get("file_ratio_threshold", 0.05)
        if args.file_ratio_threshold is None
        else args.file_ratio_threshold
    )

    files = extracted_csv_files(args.score_folder)
    df = read_many_csvs(files)
    X, source_files = prepare_inference_frame(df, bundle)

    missing_used_features = [col for col in bundle["training_meta"]["feature_columns"] if col not in df.columns]
    all_empty_features = [
        col
        for col in bundle["training_meta"]["feature_columns"]
        if col in df.columns and df[col].isna().all()
    ]

    print("\nInference schema:")
    print(f"Model features        : {len(bundle['training_meta']['feature_columns']):,}")
    print(f"Missing used features : {len(missing_used_features):,}")
    print(f"All-empty used feats  : {len(all_empty_features):,}")
    if missing_used_features:
        print(f"Missing sample        : {missing_used_features[:15]}")
    if all_empty_features:
        print(f"All-empty sample      : {all_empty_features[:15]}")

    proba = bundle["model"].predict_proba(bundle["preprocessor"].transform(X))[:, 1]
    pred = (proba >= threshold).astype(int)

    print("\nAttack probability summary:")
    print(pd.Series(proba).describe(percentiles=[0.5, 0.9, 0.95, 0.99]).to_string())
    print(
        "File rule: "
        f"max_probability >= {file_max_threshold:.6f} and "
        f"malicious_record_ratio >= {file_ratio_threshold:.6f}"
    )

    metadata_columns = [
        col
        for col in [
            "frame.time",
            "ip.src_host",
            "ip.dst_host",
            "tcp.srcport",
            "tcp.dstport",
            "udp.port",
            "tcp.flags",
            "tcp.connection.syn",
            "tcp.connection.synack",
            "tcp.connection.rst",
            "tcp.connection.fin",
            "http.request.method",
        ]
        if col in df.columns
    ]

    results = pd.DataFrame(
        {
            "source_file": source_files.values,
            "pred_proba_attack": proba,
            "pred_label": pred,
        }
    )
    for col in metadata_columns:
        results[col] = df[col].values

    output_csv = Path(args.output_csv)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(output_csv, index=False)

    summary = build_file_summary(
        results,
        file_max_threshold=file_max_threshold,
        file_ratio_threshold=file_ratio_threshold,
    )
    summary_path = output_csv.with_name(output_csv.stem + "_summary.csv")
    summary.to_csv(summary_path, index=False)

    print(f"\nSaved predictions: {output_csv}")
    print(f"Saved summary    : {summary_path}")
    print("\nPer-file summary:")
    print(summary.to_string(index=False))


def column_stats(df: pd.DataFrame, columns: list[str], prefix: str) -> pd.DataFrame:
    rows = []
    for col in columns:
        if col not in df.columns:
            rows.append(
                {
                    "column": col,
                    f"{prefix}_present": False,
                    f"{prefix}_null_ratio": np.nan,
                    f"{prefix}_constant": np.nan,
                    f"{prefix}_numeric_ratio": np.nan,
                    f"{prefix}_min": np.nan,
                    f"{prefix}_median": np.nan,
                    f"{prefix}_max": np.nan,
                    f"{prefix}_sample_values": "",
                }
            )
            continue

        series = df[col]
        parsed, numeric_ratio, _ = numeric_parse_ratio(series)
        sample_values = (
            series.dropna().astype(str).str.strip().replace("", np.nan).dropna().head(5).tolist()
        )
        numeric_values = parsed.dropna()
        rows.append(
            {
                "column": col,
                f"{prefix}_present": True,
                f"{prefix}_null_ratio": float(series.isna().mean()),
                f"{prefix}_constant": bool(series.nunique(dropna=True) <= 1),
                f"{prefix}_numeric_ratio": numeric_ratio,
                f"{prefix}_min": float(numeric_values.min()) if len(numeric_values) else np.nan,
                f"{prefix}_median": float(numeric_values.median()) if len(numeric_values) else np.nan,
                f"{prefix}_max": float(numeric_values.max()) if len(numeric_values) else np.nan,
                f"{prefix}_sample_values": " | ".join(sample_values),
            }
        )
    return pd.DataFrame(rows)


def compare_command(args: argparse.Namespace) -> None:
    edge_df = read_csv(args.edge_csv, sample_rows=args.edge_sample_rows)
    local_files = extracted_csv_files(args.extracted_folder)
    local_df = read_many_csvs(local_files)

    columns = list(dict.fromkeys([*edge_df.columns, *local_df.columns]))
    edge_stats = column_stats(edge_df, columns, "edge")
    local_stats = column_stats(local_df, columns, "local")
    report = edge_stats.merge(local_stats, on="column", how="outer")

    report["present_in_both"] = report["edge_present"].fillna(False) & report["local_present"].fillna(False)
    report["range_shift_ratio"] = np.where(
        (report["edge_max"].notna()) & (report["edge_max"].abs() > 0) & (report["local_max"].notna()),
        report["local_max"] / report["edge_max"].replace(0, np.nan),
        np.nan,
    )

    output_csv = Path(args.output_csv)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    report.to_csv(output_csv, index=False)

    edge_only = report.loc[report["edge_present"].fillna(False) & ~report["local_present"].fillna(False), "column"].tolist()
    local_only = report.loc[~report["edge_present"].fillna(False) & report["local_present"].fillna(False), "column"].tolist()
    local_empty = report.loc[
        report["present_in_both"] & (report["local_null_ratio"].fillna(1.0) >= 1.0),
        "column",
    ].tolist()
    local_constant = report.loc[
        report["present_in_both"] & report["local_constant"].fillna(False),
        "column",
    ].tolist()

    print("\nSchema/value comparison:")
    print(f"Edge rows sampled        : {len(edge_df):,}")
    print(f"Local extracted rows     : {len(local_df):,}")
    print(f"Columns only in Edge CSV : {len(edge_only):,}")
    print(f"Columns only in local    : {len(local_only):,}")
    print(f"Local all-null columns   : {len(local_empty):,}")
    print(f"Local constant columns   : {len(local_constant):,}")
    if edge_only:
        print(f"Edge-only sample         : {edge_only[:15]}")
    if local_empty:
        print(f"Local all-null sample    : {local_empty[:15]}")
    print(f"\nSaved comparison report: {output_csv}")


def run_command(args: argparse.Namespace) -> None:
    train_args = argparse.Namespace(
        edge_csv=args.edge_csv,
        model_out=args.model_out,
        keep_identity_payload=args.keep_identity_payload,
        numeric_threshold=args.numeric_threshold,
        sample_rows=args.sample_rows,
        keep_duplicates=args.keep_duplicates,
        min_category_count=args.min_category_count,
        threshold_strategy=args.threshold_strategy,
        fixed_threshold=args.fixed_threshold,
        min_precision=args.min_precision,
        file_max_threshold=args.file_max_threshold,
        file_ratio_threshold=args.file_ratio_threshold,
    )
    train_command(train_args)

    extract_args = argparse.Namespace(
        edge_csv=args.edge_csv,
        pcap_folder=args.pcap_folder,
        output_folder=args.output_folder,
        tshark=args.tshark,
    )
    extract_command(extract_args)

    score_args = argparse.Namespace(
        model_path=args.model_out,
        score_folder=args.output_folder,
        output_csv=args.output_csv,
        threshold=None,
        file_max_threshold=None,
        file_ratio_threshold=None,
    )
    score_command(score_args)

    compare_args = argparse.Namespace(
        edge_csv=args.edge_csv,
        extracted_folder=args.output_folder,
        output_csv=args.report_csv,
        edge_sample_rows=args.edge_sample_rows,
    )
    compare_command(compare_args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Edge-IIoTset experiment: train on ML-EdgeIIoT-dataset.csv, "
            "extract local PCAPs with tshark using the same field schema, and score them."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    train_parser = subparsers.add_parser("train", help="Train an XGBoost binary IDS on Edge-IIoT CSV.")
    train_parser.add_argument("--edge_csv", default=DEFAULT_EDGE_CSV)
    train_parser.add_argument("--model_out", default=DEFAULT_MODEL_PATH)
    train_parser.add_argument("--sample_rows", type=int, default=None, help="Optional row limit for quick tests.")
    train_parser.add_argument("--keep_duplicates", action="store_true", help="Do not drop duplicate rows.")
    train_parser.add_argument(
        "--keep_identity_payload",
        action="store_true",
        help="Keep timestamp/IP/port/payload columns. Default drops them to reduce memorization.",
    )
    train_parser.add_argument("--numeric_threshold", type=float, default=0.95)
    train_parser.add_argument("--min_category_count", type=int, default=20)
    train_parser.add_argument(
        "--threshold_strategy",
        choices=["fixed", "f1", "f2"],
        default="fixed",
        help=(
            "Default uses a fixed 0.5 flow threshold because the Edge-IIoT "
            "validation-tuned f2 threshold was too sensitive on local PCAPs."
        ),
    )
    train_parser.add_argument("--fixed_threshold", type=float, default=0.5)
    train_parser.add_argument("--min_precision", type=float, default=0.0)
    train_parser.add_argument("--file_max_threshold", type=float, default=0.5)
    train_parser.add_argument(
        "--file_ratio_threshold",
        type=float,
        default=0.4,
        help=(
            "Per-file rule: classify a PCAP as attack only if this fraction "
            "of extracted records is malicious."
        ),
    )
    train_parser.set_defaults(func=train_command)

    extract_parser = subparsers.add_parser("extract", help="Extract local PCAPs to Edge-IIoT-like CSVs.")
    extract_parser.add_argument("--edge_csv", default=DEFAULT_EDGE_CSV)
    extract_parser.add_argument("--pcap_folder", default=DEFAULT_PCAP_FOLDER)
    extract_parser.add_argument("--output_folder", default=DEFAULT_EXTRACTED_FOLDER)
    extract_parser.add_argument("--tshark", default=None, help="Optional explicit path to tshark.")
    extract_parser.set_defaults(func=extract_command)

    score_parser = subparsers.add_parser("score", help="Score extracted Edge-IIoT-like CSV files.")
    score_parser.add_argument("--model_path", default=DEFAULT_MODEL_PATH)
    score_parser.add_argument("--score_folder", default=DEFAULT_EXTRACTED_FOLDER)
    score_parser.add_argument("--output_csv", default=DEFAULT_PREDICTIONS_CSV)
    score_parser.add_argument("--threshold", type=float, default=None)
    score_parser.add_argument("--file_max_threshold", type=float, default=None)
    score_parser.add_argument("--file_ratio_threshold", type=float, default=None)
    score_parser.set_defaults(func=score_command)

    compare_parser = subparsers.add_parser(
        "compare",
        help="Compare Edge training CSV columns/ranges with extracted local PCAP CSVs.",
    )
    compare_parser.add_argument("--edge_csv", default=DEFAULT_EDGE_CSV)
    compare_parser.add_argument("--extracted_folder", default=DEFAULT_EXTRACTED_FOLDER)
    compare_parser.add_argument("--output_csv", default=DEFAULT_REPORT_CSV)
    compare_parser.add_argument("--edge_sample_rows", type=int, default=200_000)
    compare_parser.set_defaults(func=compare_command)

    run_parser = subparsers.add_parser("run", help="Train, extract, score, and compare in one command.")
    run_parser.add_argument("--edge_csv", default=DEFAULT_EDGE_CSV)
    run_parser.add_argument("--model_out", default=DEFAULT_MODEL_PATH)
    run_parser.add_argument("--pcap_folder", default=DEFAULT_PCAP_FOLDER)
    run_parser.add_argument("--output_folder", default=DEFAULT_EXTRACTED_FOLDER)
    run_parser.add_argument("--output_csv", default=DEFAULT_PREDICTIONS_CSV)
    run_parser.add_argument("--report_csv", default=DEFAULT_REPORT_CSV)
    run_parser.add_argument("--tshark", default=None)
    run_parser.add_argument("--sample_rows", type=int, default=None)
    run_parser.add_argument("--edge_sample_rows", type=int, default=200_000)
    run_parser.add_argument("--keep_duplicates", action="store_true")
    run_parser.add_argument("--keep_identity_payload", action="store_true")
    run_parser.add_argument("--numeric_threshold", type=float, default=0.95)
    run_parser.add_argument("--min_category_count", type=int, default=20)
    run_parser.add_argument(
        "--threshold_strategy",
        choices=["fixed", "f1", "f2"],
        default="fixed",
        help=(
            "Default uses a fixed 0.5 flow threshold because the Edge-IIoT "
            "validation-tuned f2 threshold was too sensitive on local PCAPs."
        ),
    )
    run_parser.add_argument("--fixed_threshold", type=float, default=0.5)
    run_parser.add_argument("--min_precision", type=float, default=0.0)
    run_parser.add_argument("--file_max_threshold", type=float, default=0.5)
    run_parser.add_argument(
        "--file_ratio_threshold",
        type=float,
        default=0.4,
        help=(
            "Per-file rule: classify a PCAP as attack only if this fraction "
            "of extracted records is malicious."
        ),
    )
    run_parser.set_defaults(func=run_command)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
