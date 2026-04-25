from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pymongo
from pyspark.sql import SparkSession
from pyspark.sql.types import ArrayType, IntegerType, StringType, StructField, StructType

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from testoutside.live_wifi_edge_ids_pcap import prepare_model_input

WINDOW_RECORD_PREVIEW_LIMIT = 25


def default_model_path() -> Path:
    local_model = REPO_ROOT / "experment" / "edge_iiot_xgb_model.joblib"
    if local_model.exists():
        return local_model
    return REPO_ROOT / "testoutside" / "edge_iiot_xgb_model.joblib"


def build_schema(feature_columns: list[str]) -> StructType:
    record_fields = [StructField(col, StringType(), True) for col in feature_columns]
    return StructType(
        [
            StructField("window_id", IntegerType(), True),
            StructField("window_start", StringType(), True),
            StructField("window_end", StringType(), True),
            StructField("interface", StringType(), True),
            StructField("source_path", StringType(), True),
            StructField("stream_file", StringType(), True),
            StructField("window_seconds", IntegerType(), True),
            StructField("record_count", IntegerType(), True),
            StructField("capture_filter", StringType(), True),
            StructField("display_filter", StringType(), True),
            StructField("unsupported_tshark_fields", ArrayType(StringType(), True), True),
            StructField("records", ArrayType(StructType(record_fields), True), True),
        ]
    )


def probability_summary(probabilities: np.ndarray) -> dict[str, float]:
    if len(probabilities) == 0:
        return {
            "mean_attack_probability": 0.0,
            "median_attack_probability": 0.0,
            "p95_attack_probability": 0.0,
            "max_attack_probability": 0.0,
        }

    return {
        "mean_attack_probability": float(np.mean(probabilities)),
        "median_attack_probability": float(np.median(probabilities)),
        "p95_attack_probability": float(np.quantile(probabilities, 0.95)),
        "max_attack_probability": float(np.max(probabilities)),
    }


def normalize_records(records: object) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    if records is None:
        return normalized

    for item in records:
        if hasattr(item, "asDict"):
            item = item.asDict(recursive=True)
        if not isinstance(item, dict):
            continue
        normalized.append({key: "" if pd.isna(value) else str(value) for key, value in item.items()})
    return normalized


def preview_records(records: list[dict[str, str]], limit: int = WINDOW_RECORD_PREVIEW_LIMIT) -> list[dict[str, str]]:
    return records[:limit]


def decide_window_label(
    *,
    records: int,
    attack_ratio: float,
    max_attack_probability: float,
    file_max_threshold: float,
    file_ratio_threshold: float,
    min_records: int,
) -> int:
    if records < min_records:
        return 0
    return int(
        max_attack_probability >= file_max_threshold
        and attack_ratio >= file_ratio_threshold
    )


def native_value(value: object) -> object:
    if isinstance(value, (np.integer, np.floating)):
        return value.item()
    if isinstance(value, (pd.Timestamp, datetime)):
        return value.isoformat()
    return value


def as_mongo_doc(data: dict[str, object]) -> dict[str, object]:
    return {key: native_value(value) for key, value in data.items()}


def write_upsert(collection: pymongo.collection.Collection, document: dict[str, object]) -> None:
    doc = as_mongo_doc(document)
    doc_id = doc.get("_id")
    if doc_id is None:
        raise ValueError("MongoDB document is missing _id")
    collection.replace_one({"_id": doc_id}, doc, upsert=True)


def process_batch_factory(
    *,
    bundle: dict[str, object],
    mongo_uri: str,
    mongo_db: str,
    windows_collection: str,
    predictions_collection: str,
    alerts_collection: str,
    threshold: float,
    file_max_threshold: float,
    file_ratio_threshold: float,
    min_records: int,
):
    mongo_client = pymongo.MongoClient(mongo_uri)
    db = mongo_client[mongo_db]
    windows = db[windows_collection]
    predictions = db[predictions_collection]
    alerts = db[alerts_collection]

    def process_batch(batch_df, batch_id: int) -> None:
        rows = [row.asDict(recursive=True) for row in batch_df.collect()]
        if not rows:
            return

        for row in rows:
            window_file = str(row.get("stream_file") or f"window_{batch_id:06d}")
            records = normalize_records(row.get("records"))
            record_df = pd.DataFrame(records)
            record_preview = preview_records(records)
            window_doc = as_mongo_doc(
                {
                    "_id": window_file,
                    "window_id": row.get("window_id"),
                    "window_start": row.get("window_start"),
                    "window_end": row.get("window_end"),
                    "interface": row.get("interface"),
                    "source_path": row.get("source_path"),
                    "stream_file": window_file,
                    "window_seconds": row.get("window_seconds"),
                    "record_count": row.get("record_count"),
                    "capture_filter": row.get("capture_filter"),
                    "display_filter": row.get("display_filter"),
                    "unsupported_tshark_fields": row.get("unsupported_tshark_fields"),
                    "record_preview": record_preview,
                    "record_preview_count": int(len(record_preview)),
                    "records_truncated": bool(len(records) > len(record_preview)),
                    "stream_json_path": row.get("stream_json_path")
                    or str(REPO_ROOT / "stream_input" / "live" / window_file),
                    "ingested_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
            )
            write_upsert(windows, window_doc)

            if record_df.empty:
                summary = probability_summary(np.array([]))
                prediction_doc = {
                    "_id": window_file,
                    "window_id": row.get("window_id"),
                    "stream_file": window_file,
                    "window_start": row.get("window_start"),
                    "window_end": row.get("window_end"),
                    "interface": row.get("interface"),
                    "source_path": row.get("source_path"),
                    "record_count": 0,
                    "attack_records": 0,
                    "attack_record_ratio": 0.0,
                    **summary,
                    "record_threshold": threshold,
                    "file_max_threshold": file_max_threshold,
                    "file_ratio_threshold": file_ratio_threshold,
                    "min_records": min_records,
                    "window_pred_label": 0,
                    "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
                write_upsert(predictions, prediction_doc)
                continue

            X = prepare_model_input(record_df, bundle)
            probabilities = bundle["model"].predict_proba(bundle["preprocessor"].transform(X))[:, 1]
            labels = (probabilities >= threshold).astype(int)
            records_count = int(len(record_df))
            attack_records = int(labels.sum())
            attack_ratio = float(attack_records / records_count) if records_count else 0.0
            summary = probability_summary(probabilities)
            window_pred_label = decide_window_label(
                records=records_count,
                attack_ratio=attack_ratio,
                max_attack_probability=summary["max_attack_probability"],
                file_max_threshold=file_max_threshold,
                file_ratio_threshold=file_ratio_threshold,
                min_records=min_records,
            )

            prediction_doc = {
                "_id": window_file,
                "window_id": row.get("window_id"),
                "stream_file": window_file,
                "window_start": row.get("window_start"),
                "window_end": row.get("window_end"),
                "interface": row.get("interface"),
                "source_path": row.get("source_path"),
                "record_count": records_count,
                "attack_records": attack_records,
                "attack_record_ratio": attack_ratio,
                **summary,
                "record_threshold": threshold,
                "file_max_threshold": file_max_threshold,
                "file_ratio_threshold": file_ratio_threshold,
                "min_records": min_records,
                "window_pred_label": window_pred_label,
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
            write_upsert(predictions, prediction_doc)

            if window_pred_label:
                alert_doc = {
                    "_id": window_file,
                    "window_id": row.get("window_id"),
                    "stream_file": window_file,
                    "window_start": row.get("window_start"),
                    "window_end": row.get("window_end"),
                    "interface": row.get("interface"),
                    "source_path": row.get("source_path"),
                    "record_count": records_count,
                    "attack_records": attack_records,
                    "attack_record_ratio": attack_ratio,
                    "max_attack_probability": summary["max_attack_probability"],
                    "mean_attack_probability": summary["mean_attack_probability"],
                    "reason": "window_pred_label=1",
                    "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
                write_upsert(alerts, alert_doc)

    return process_batch


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Spark Structured Streaming IDS for Edge-IIoT live windows.")
    parser.add_argument("--model_path", default=str(default_model_path()), help="Path to edge_iiot_xgb_model.joblib.")
    parser.add_argument("--input_dir", default=str(REPO_ROOT / "stream_input" / "live"), help="Folder of JSON window files.")
    parser.add_argument("--checkpoint_dir", default=str(REPO_ROOT / "stream_input" / "checkpoints"), help="Spark checkpoint folder.")
    parser.add_argument("--mongo_uri", default="mongodb://localhost:27017", help="MongoDB connection URI.")
    parser.add_argument("--mongo_db", default="edgeids", help="MongoDB database name.")
    parser.add_argument("--windows_collection", default="windows", help="MongoDB collection for raw window docs.")
    parser.add_argument("--predictions_collection", default="predictions", help="MongoDB collection for prediction summaries.")
    parser.add_argument("--alerts_collection", default="alerts", help="MongoDB collection for alerts.")
    parser.add_argument("--trigger_interval", default="5 seconds", help="Structured Streaming trigger interval.")
    parser.add_argument("--app_name", default="EdgeIIoTStreamIDS", help="Spark application name.")
    parser.add_argument("--log_level", default="WARN", help="Spark log level.")
    parser.add_argument("--threshold", type=float, default=None, help="Override record-level attack threshold.")
    parser.add_argument("--file_max_threshold", type=float, default=None, help="Override window max-probability threshold.")
    parser.add_argument("--file_ratio_threshold", type=float, default=None, help="Override window attack-ratio threshold.")
    parser.add_argument("--min_records", type=int, default=None, help="Minimum records before a window can alert.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    model_path = Path(args.model_path).expanduser().resolve()
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")

    bundle = joblib.load(model_path)
    feature_columns = list(bundle["training_meta"]["feature_columns"])
    threshold = float(args.threshold if args.threshold is not None else bundle.get("threshold", 0.5))
    file_max_threshold = float(
        args.file_max_threshold if args.file_max_threshold is not None else bundle.get("file_max_threshold", threshold)
    )
    file_ratio_threshold = float(
        args.file_ratio_threshold if args.file_ratio_threshold is not None else bundle.get("file_ratio_threshold", 0.4)
    )
    min_records = int(args.min_records if args.min_records is not None else bundle.get("min_records", 50))

    spark = SparkSession.builder.appName(args.app_name).getOrCreate()
    spark.sparkContext.setLogLevel(args.log_level)

    schema = build_schema(feature_columns)
    input_dir = Path(args.input_dir).expanduser().resolve()
    checkpoint_dir = Path(args.checkpoint_dir).expanduser().resolve()
    input_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_dir.mkdir(parents=True, exist_ok=True)

    print(f"Model path      : {model_path}")
    print(f"Input dir       : {input_dir}")
    print(f"Checkpoint dir  : {checkpoint_dir}")
    print(f"Mongo URI       : {args.mongo_uri}")
    print(f"Mongo DB        : {args.mongo_db}")
    print(f"Windows coll    : {args.windows_collection}")
    print(f"Predictions coll: {args.predictions_collection}")
    print(f"Alerts coll     : {args.alerts_collection}")
    print(f"Feature columns : {len(feature_columns):,}")

    stream_df = (
        spark.readStream
        .schema(schema)
        .option("multiLine", "true")
        .json(str(input_dir))
    )

    process_batch = process_batch_factory(
        bundle=bundle,
        mongo_uri=args.mongo_uri,
        mongo_db=args.mongo_db,
        windows_collection=args.windows_collection,
        predictions_collection=args.predictions_collection,
        alerts_collection=args.alerts_collection,
        threshold=threshold,
        file_max_threshold=file_max_threshold,
        file_ratio_threshold=file_ratio_threshold,
        min_records=min_records,
    )

    query = (
        stream_df.writeStream
        .foreachBatch(process_batch)
        .option("checkpointLocation", str(checkpoint_dir))
        .trigger(processingTime=args.trigger_interval)
        .outputMode("append")
        .start()
    )

    print("Spark stream started. Waiting for window JSON files...")
    query.awaitTermination()


if __name__ == "__main__":
    main()
