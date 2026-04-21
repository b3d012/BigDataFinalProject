from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


MISSING_STRINGS = {"", "nan", "none", "null", "na", "n/a", "<nan>"}

DEFAULT_METADATA_FIELDS = [
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
    "dns.qry.name",
]


def script_dir() -> Path:
    return Path(__file__).resolve().parent


def default_model_path() -> Path:
    local_model = script_dir() / "edge_iiot_xgb_model.joblib"
    if local_model.exists():
        return local_model
    return script_dir().parent / "experment" / "edge_iiot_xgb_model.joblib"


def default_output_dir() -> Path:
    return script_dir() / "live-output"


def default_baseline_path(output_dir: Path) -> Path:
    return output_dir / "live_wifi_baseline.json"


def find_tshark(explicit_path: str | None = None) -> str:
    candidates: list[str] = []
    if explicit_path:
        candidates.append(explicit_path)

    found = shutil.which("tshark")
    if found:
        candidates.append(found)

    system = platform.system().lower()
    if system == "darwin":
        candidates.append("/Applications/Wireshark.app/Contents/MacOS/tshark")
    elif system == "windows":
        candidates.extend(
            [
                r"C:\Program Files\Wireshark\tshark.exe",
                r"C:\Program Files (x86)\Wireshark\tshark.exe",
            ]
        )

    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return str(Path(candidate))

    raise RuntimeError(
        "Could not find tshark. Install Wireshark CLI tools, then pass "
        "--tshark if it is not on PATH."
    )


def run_text(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout


def list_interfaces(tshark: str) -> str:
    return run_text([tshark, "-D"])


def choose_interface(tshark: str, requested: str | None) -> str:
    if requested:
        return requested

    listing = list_interfaces(tshark)
    lines = [line.strip() for line in listing.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("tshark did not report any capture interfaces.")

    preferred_tokens = ("wi-fi", "wifi", "wireless", "wlan", "en0")
    for line in lines:
        if any(token in line.lower() for token in preferred_tokens):
            return line.split(".", 1)[0].strip()

    for line in lines:
        lowered = line.lower()
        if "loopback" not in lowered and "lo0" not in lowered:
            return line.split(".", 1)[0].strip()

    return lines[0].split(".", 1)[0].strip()


def available_tshark_fields(tshark: str) -> set[str] | None:
    try:
        output = run_text([tshark, "-G", "fields"])
    except Exception:
        return None

    fields = set()
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "F":
            fields.add(parts[2])
    return fields


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(col).replace("\ufeff", "").strip() for col in df.columns]
    return df.loc[:, ~df.columns.duplicated()]


def first_repeated_value(text: str) -> str:
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

    lowered = text.lower()
    if lowered in {"true", "yes"}:
        return 1.0
    if lowered in {"false", "no"}:
        return 0.0

    if re.fullmatch(r"0x[0-9a-fA-F]+", text):
        return float(int(text, 16))

    if "," in text:
        return np.nan

    return float(pd.to_numeric(text, errors="coerce"))


def clean_string_series(series: pd.Series) -> pd.Series:
    values = series.astype("string").fillna("__MISSING__").str.strip()
    return values.mask(values.str.lower().isin(MISSING_STRINGS), "__MISSING__").astype(str)


def prepare_model_input(df: pd.DataFrame, bundle: dict[str, object]) -> pd.DataFrame:
    df = normalize_columns(df)
    meta = bundle["training_meta"]
    feature_columns = list(meta["feature_columns"])
    numeric_columns = list(meta.get("numeric_columns", []))
    categorical_columns = list(meta.get("categorical_columns", []))

    for column in feature_columns:
        if column not in df.columns:
            df[column] = np.nan

    out = pd.DataFrame(index=df.index)
    for column in numeric_columns:
        out[column] = df[column].map(parse_numeric_value) if column in df.columns else np.nan
    for column in categorical_columns:
        out[column] = clean_string_series(df[column]) if column in df.columns else "__MISSING__"

    return out[feature_columns]


def requested_tshark_fields(bundle: dict[str, object], include_metadata: bool) -> list[str]:
    meta = bundle["training_meta"]
    fields = list(meta["feature_columns"])
    if include_metadata:
        fields.extend(DEFAULT_METADATA_FIELDS)
    return list(dict.fromkeys(fields))


def resolve_supported_fields(
    fields: list[str],
    valid_fields: set[str] | None,
) -> tuple[list[str], list[str]]:
    supported_fields = fields
    unsupported_fields: list[str] = []
    if valid_fields is not None:
        supported_fields = [field for field in fields if field in valid_fields]
        unsupported_fields = sorted(set(fields) - set(supported_fields))

    if not supported_fields:
        raise RuntimeError("None of the model fields are supported by this tshark installation.")

    return supported_fields, unsupported_fields



def finalize_output_csv(
    output_csv: Path,
    fields: list[str],
    supported_fields: list[str],
) -> None:
    if output_csv.exists() and output_csv.stat().st_size > 0:
        df = pd.read_csv(output_csv, low_memory=False)
        df = normalize_columns(df)
    else:
        df = pd.DataFrame(columns=supported_fields)

    for field in fields:
        if field not in df.columns:
            df[field] = ""
    df = df[fields]
    df.to_csv(output_csv, index=False)



def capture_window_to_csv(
    *,
    tshark: str,
    interface: str,
    duration_seconds: int,
    output_csv: Path,
    fields: list[str],
    valid_fields: set[str] | None,
    capture_filter: str | None,
    display_filter: str | None,
    packet_count: int | None,
) -> tuple[list[str], list[str]]:
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    supported_fields, unsupported_fields = resolve_supported_fields(fields, valid_fields)

    command = [
        tshark,
        "-i",
        str(interface),
        "-a",
        f"duration:{duration_seconds}",
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
    if packet_count is not None and packet_count > 0:
        command.extend(["-c", str(packet_count)])
    if capture_filter:
        command.extend(["-f", capture_filter])
    if display_filter:
        command.extend(["-Y", display_filter])

    for field in supported_fields:
        command.extend(["-e", field])

    with output_csv.open("w", encoding="utf-8", newline="") as fh:
        result = subprocess.run(command, stdout=fh, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    finalize_output_csv(output_csv, fields, supported_fields)
    return supported_fields, unsupported_fields



def pcap_to_csv(
    *,
    tshark: str,
    input_pcap: Path,
    output_csv: Path,
    fields: list[str],
    valid_fields: set[str] | None,
    display_filter: str | None,
    packet_count: int | None,
) -> tuple[list[str], list[str]]:
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    supported_fields, unsupported_fields = resolve_supported_fields(fields, valid_fields)

    command = [
        tshark,
        "-r",
        str(input_pcap),
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
    if packet_count is not None and packet_count > 0:
        command.extend(["-c", str(packet_count)])
    if display_filter:
        command.extend(["-Y", display_filter])

    for field in supported_fields:
        command.extend(["-e", field])

    with output_csv.open("w", encoding="utf-8", newline="") as fh:
        result = subprocess.run(command, stdout=fh, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    finalize_output_csv(output_csv, fields, supported_fields)
    return supported_fields, unsupported_fields


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


def summary_fieldnames() -> list[str]:
    return [
        "window_id",
        "window_start",
        "window_end",
        "interface",
        "source_path",
        "records",
        "attack_records",
        "attack_record_ratio",
        "mean_attack_probability",
        "median_attack_probability",
        "p95_attack_probability",
        "max_attack_probability",
        "threshold",
        "file_max_threshold",
        "file_ratio_threshold",
        "window_pred_label",
        "raw_csv_path",
        "unsupported_tshark_fields",
    ]


def append_row(path: Path, row: dict[str, object], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists() and path.stat().st_size > 0
    with path.open("a", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        writer.writerow({key: row.get(key, "") for key in fieldnames})


def append_packet_predictions(
    path: Path,
    df: pd.DataFrame,
    *,
    window_id: int,
    probabilities: np.ndarray,
    labels: np.ndarray,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    metadata = [field for field in DEFAULT_METADATA_FIELDS if field in df.columns]
    output = pd.DataFrame(
        {
            "window_id": window_id,
            "record_index": np.arange(len(df)),
            "pred_proba_attack": probabilities,
            "pred_label": labels,
        }
    )
    for field in metadata:
        output[field] = df[field].values

    header = not path.exists() or path.stat().st_size == 0
    output.to_csv(path, mode="a", index=False, header=header)


def score_window(
    raw_csv: Path,
    bundle: dict[str, object],
    *,
    threshold: float,
) -> tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    if not raw_csv.exists() or raw_csv.stat().st_size == 0:
        return pd.DataFrame(), np.array([]), np.array([], dtype=int)

    df = pd.read_csv(raw_csv, low_memory=False)
    df = normalize_columns(df)
    if df.empty:
        return df, np.array([]), np.array([], dtype=int)

    X = prepare_model_input(df, bundle)
    probabilities = bundle["model"].predict_proba(bundle["preprocessor"].transform(X))[:, 1]
    labels = (probabilities >= threshold).astype(int)
    return df, probabilities, labels


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


def capture_score_once(
    *,
    window_id: int,
    raw_csv: Path,
    tshark: str,
    interface: str,
    duration_seconds: int,
    fields: list[str],
    valid_fields: set[str] | None,
    capture_filter: str | None,
    display_filter: str | None,
    packet_count: int | None,
    bundle: dict[str, object],
    threshold: float,
    file_max_threshold: float,
    file_ratio_threshold: float,
    min_records: int,
) -> tuple[dict[str, object], pd.DataFrame, np.ndarray, np.ndarray]:
    start = datetime.now().astimezone()
    _, unsupported_fields = capture_window_to_csv(
        tshark=tshark,
        interface=interface,
        duration_seconds=duration_seconds,
        output_csv=raw_csv,
        fields=fields,
        valid_fields=valid_fields,
        capture_filter=capture_filter,
        display_filter=display_filter,
        packet_count=packet_count,
    )
    end = datetime.now().astimezone()

    df, probabilities, labels = score_window(raw_csv, bundle, threshold=threshold)
    records = int(len(df))
    attack_records = int(labels.sum()) if len(labels) else 0
    attack_ratio = float(attack_records / records) if records else 0.0
    stats = probability_summary(probabilities)
    window_pred_label = decide_window_label(
        records=records,
        attack_ratio=attack_ratio,
        max_attack_probability=stats["max_attack_probability"],
        file_max_threshold=file_max_threshold,
        file_ratio_threshold=file_ratio_threshold,
        min_records=min_records,
    )

    row = {
        "window_id": window_id,
        "window_start": start.isoformat(timespec="seconds"),
        "window_end": end.isoformat(timespec="seconds"),
        "interface": interface,
        "source_path": "",
        "records": records,
        "attack_records": attack_records,
        "attack_record_ratio": attack_ratio,
        **stats,
        "threshold": threshold,
        "file_max_threshold": file_max_threshold,
        "file_ratio_threshold": file_ratio_threshold,
        "window_pred_label": window_pred_label,
        "raw_csv_path": str(raw_csv),
        "unsupported_tshark_fields": "|".join(unsupported_fields),
    }
    return row, df, probabilities, labels



def score_pcap_once(
    *,
    window_id: int,
    pcap_path: Path,
    raw_csv: Path,
    tshark: str,
    fields: list[str],
    valid_fields: set[str] | None,
    display_filter: str | None,
    packet_count: int | None,
    bundle: dict[str, object],
    threshold: float,
    file_max_threshold: float,
    file_ratio_threshold: float,
    min_records: int,
) -> tuple[dict[str, object], pd.DataFrame, np.ndarray, np.ndarray]:
    start = datetime.now().astimezone()
    _, unsupported_fields = pcap_to_csv(
        tshark=tshark,
        input_pcap=pcap_path,
        output_csv=raw_csv,
        fields=fields,
        valid_fields=valid_fields,
        display_filter=display_filter,
        packet_count=packet_count,
    )
    end = datetime.now().astimezone()

    df, probabilities, labels = score_window(raw_csv, bundle, threshold=threshold)
    records = int(len(df))
    attack_records = int(labels.sum()) if len(labels) else 0
    attack_ratio = float(attack_records / records) if records else 0.0
    stats = probability_summary(probabilities)
    window_pred_label = decide_window_label(
        records=records,
        attack_ratio=attack_ratio,
        max_attack_probability=stats["max_attack_probability"],
        file_max_threshold=file_max_threshold,
        file_ratio_threshold=file_ratio_threshold,
        min_records=min_records,
    )

    row = {
        "window_id": window_id,
        "window_start": start.isoformat(timespec="seconds"),
        "window_end": end.isoformat(timespec="seconds"),
        "interface": pcap_path.name,
        "source_path": str(pcap_path),
        "records": records,
        "attack_records": attack_records,
        "attack_record_ratio": attack_ratio,
        **stats,
        "threshold": threshold,
        "file_max_threshold": file_max_threshold,
        "file_ratio_threshold": file_ratio_threshold,
        "window_pred_label": window_pred_label,
        "raw_csv_path": str(raw_csv),
        "unsupported_tshark_fields": "|".join(unsupported_fields),
    }
    return row, df, probabilities, labels


def build_baseline_from_rows(
    rows: list[dict[str, object]],
    *,
    output_path: Path,
    model_path: Path,
    threshold: float,
    file_max_threshold: float,
    current_file_ratio_threshold: float,
    min_records: int,
    baseline_quantile: float,
    baseline_margin: float,
    max_ratio_threshold: float,
) -> dict[str, object]:
    if not rows:
        raise RuntimeError("No baseline rows were available.")

    df = pd.DataFrame(rows)
    return build_baseline_from_summary_frame(
        df,
        output_path=output_path,
        model_path=model_path,
        threshold=threshold,
        file_max_threshold=file_max_threshold,
        current_file_ratio_threshold=current_file_ratio_threshold,
        min_records=min_records,
        baseline_quantile=baseline_quantile,
        baseline_margin=baseline_margin,
        max_ratio_threshold=max_ratio_threshold,
    )


def build_baseline_from_summary_frame(
    df: pd.DataFrame,
    *,
    output_path: Path,
    model_path: Path,
    threshold: float,
    file_max_threshold: float,
    current_file_ratio_threshold: float,
    min_records: int,
    baseline_quantile: float,
    baseline_margin: float,
    max_ratio_threshold: float,
) -> dict[str, object]:
    required = {"records", "attack_record_ratio", "max_attack_probability"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Baseline summary is missing required columns: {sorted(missing)}")

    clean = df.copy()
    clean["records"] = pd.to_numeric(clean["records"], errors="coerce")
    clean["attack_record_ratio"] = pd.to_numeric(clean["attack_record_ratio"], errors="coerce")
    clean["max_attack_probability"] = pd.to_numeric(clean["max_attack_probability"], errors="coerce")
    clean = clean.dropna(subset=["attack_record_ratio", "max_attack_probability"])
    if clean.empty:
        raise RuntimeError("Baseline summary did not contain usable numeric rows.")

    used = clean[clean["records"] >= min_records]
    if used.empty:
        used = clean

    q = min(1.0, max(0.0, baseline_quantile))
    ratio_quantile = float(used["attack_record_ratio"].quantile(q))
    recommended_ratio = max(
        current_file_ratio_threshold,
        min(max_ratio_threshold, ratio_quantile + baseline_margin),
    )

    baseline = {
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "model_path": str(model_path),
        "record_threshold": float(threshold),
        "file_max_threshold": float(file_max_threshold),
        "file_ratio_threshold": float(recommended_ratio),
        "min_records": int(min_records),
        "baseline_quantile": float(q),
        "baseline_margin": float(baseline_margin),
        "windows_total": int(len(clean)),
        "windows_used": int(len(used)),
        "attack_record_ratio_min": float(used["attack_record_ratio"].min()),
        "attack_record_ratio_median": float(used["attack_record_ratio"].median()),
        "attack_record_ratio_p95": float(used["attack_record_ratio"].quantile(0.95)),
        "attack_record_ratio_max": float(used["attack_record_ratio"].max()),
        "max_attack_probability_median": float(used["max_attack_probability"].median()),
        "max_attack_probability_p95": float(used["max_attack_probability"].quantile(0.95)),
        "max_attack_probability_max": float(used["max_attack_probability"].max()),
        "note": (
            "Generated from traffic assumed to be benign. Recalibrate if your "
            "normal network behavior changes."
        ),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=2)
    return baseline


def load_baseline(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def print_baseline(baseline: dict[str, object], path: Path) -> None:
    print(f"Baseline JSON  : {path}")
    print(f"Baseline ratio : {float(baseline['file_ratio_threshold']):.6f}")
    print(f"Baseline windows used: {baseline.get('windows_used', 'unknown')}")
    if "attack_record_ratio_max" in baseline:
        print(f"Normal max attack ratio seen: {float(baseline['attack_record_ratio_max']):.6f}")



def list_pcap_files(pcap_dir: Path, pattern: str, recursive: bool) -> list[Path]:
    if not pcap_dir.exists() or not pcap_dir.is_dir():
        raise FileNotFoundError(f"PCAP folder not found: {pcap_dir}")

    iterator = pcap_dir.rglob(pattern) if recursive else pcap_dir.glob(pattern)
    files = sorted(path for path in iterator if path.is_file())
    if not files:
        raise RuntimeError(f"No PCAP files matched {pattern!r} inside {pcap_dir}")
    return files


def monitor(args: argparse.Namespace) -> None:
    tshark = find_tshark(args.tshark)
    if args.list_interfaces:
        print(list_interfaces(tshark))
        return

    model_path = Path(args.model).expanduser().resolve()
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")

    bundle = joblib.load(model_path)
    threshold = args.threshold if args.threshold is not None else float(bundle.get("threshold", 0.5))
    file_max_threshold = (
        args.file_max_threshold
        if args.file_max_threshold is not None
        else float(bundle.get("file_max_threshold", threshold))
    )
    file_ratio_threshold = (
        args.file_ratio_threshold
        if args.file_ratio_threshold is not None
        else float(bundle.get("file_ratio_threshold", 0.4))
    )

    output_dir = Path(args.output_dir).expanduser().resolve()
    raw_dir = output_dir / "raw-window-csvs"
    summary_csv = Path(args.summary_csv).expanduser()
    if not summary_csv.is_absolute():
        summary_csv = output_dir / summary_csv
    packet_csv = Path(args.packet_csv).expanduser()
    if not packet_csv.is_absolute():
        packet_csv = output_dir / packet_csv

    baseline_out = Path(args.baseline_out).expanduser()
    if not baseline_out.is_absolute():
        baseline_out = output_dir / baseline_out

    if args.calibrate_from_summary:
        summary_path = Path(args.calibrate_from_summary).expanduser()
        if not summary_path.is_absolute():
            summary_path = summary_path.resolve() if summary_path.exists() else output_dir / summary_path
        baseline = build_baseline_from_summary_frame(
            pd.read_csv(summary_path, low_memory=False),
            output_path=baseline_out,
            model_path=model_path,
            threshold=threshold,
            file_max_threshold=file_max_threshold,
            current_file_ratio_threshold=file_ratio_threshold,
            min_records=args.min_records,
            baseline_quantile=args.baseline_quantile,
            baseline_margin=args.baseline_margin,
            max_ratio_threshold=args.max_ratio_threshold,
        )
        print_baseline(baseline, baseline_out)
        print("Use this baseline with normal monitoring, or let the script auto-load it from the output folder.")
        return

    baseline_path: Path | None = None
    if args.baseline_json:
        baseline_path = Path(args.baseline_json).expanduser()
        if not baseline_path.is_absolute():
            baseline_path = output_dir / baseline_path
    elif not args.no_baseline:
        for candidate in (default_baseline_path(output_dir), script_dir() / "live_wifi_baseline.json"):
            if candidate.exists():
                baseline_path = candidate
                break

    min_records = args.min_records
    if baseline_path is not None and baseline_path.exists():
        baseline = load_baseline(baseline_path)
        if args.threshold is None:
            threshold = float(baseline.get("record_threshold", threshold))
        if args.file_max_threshold is None:
            file_max_threshold = float(baseline.get("file_max_threshold", file_max_threshold))
        if args.file_ratio_threshold is None:
            file_ratio_threshold = float(baseline.get("file_ratio_threshold", file_ratio_threshold))
        if args.min_records == 50:
            min_records = int(baseline.get("min_records", min_records))
        print_baseline(baseline, baseline_path)

    fields = requested_tshark_fields(bundle, include_metadata=not args.no_metadata)
    valid_fields = available_tshark_fields(tshark)
    summary_fields = summary_fieldnames()

    pcap_dir: Path | None = None
    if args.pcap_dir:
        pcap_dir = Path(args.pcap_dir).expanduser()
        if not pcap_dir.is_absolute():
            pcap_dir = (Path.cwd() / pcap_dir).resolve()

    if pcap_dir is not None:
        if args.capture_filter:
            raise RuntimeError("--capture_filter works only for live capture. Use --display_filter in PCAP mode.")

        pcap_files = list_pcap_files(pcap_dir, args.pcap_glob, args.pcap_recursive)
        if args.iterations > 0:
            pcap_files = pcap_files[: args.iterations]

        print(f"Model          : {model_path}")
        print(f"tshark         : {tshark}")
        print(f"PCAP folder    : {pcap_dir}")
        print(f"PCAP files     : {len(pcap_files)}")
        print(f"Flow threshold : {threshold:.6f}")
        print(
            "Window rule    : "
            f"max_probability >= {file_max_threshold:.6f} and "
            f"attack_record_ratio >= {file_ratio_threshold:.6f} and "
            f"records >= {min_records}"
        )
        print(f"Summary CSV    : {summary_csv}")
        if not args.no_packet_csv:
            print(f"Packet CSV     : {packet_csv}")
        print()

        for window_id, pcap_path in enumerate(pcap_files, start=1):
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", pcap_path.stem)
            raw_csv = raw_dir / f"pcap_{window_id:06d}_{safe_name}.csv"

            print(f"[{window_id}] reading {pcap_path.name}...")
            row, df, probabilities, labels = score_pcap_once(
                window_id=window_id,
                pcap_path=pcap_path,
                raw_csv=raw_csv,
                tshark=tshark,
                fields=fields,
                valid_fields=valid_fields,
                display_filter=args.display_filter,
                packet_count=args.packet_count,
                bundle=bundle,
                threshold=threshold,
                file_max_threshold=file_max_threshold,
                file_ratio_threshold=file_ratio_threshold,
                min_records=min_records,
            )
            append_row(summary_csv, row, summary_fields)

            records = int(row["records"])
            attack_ratio = float(row["attack_record_ratio"])
            max_attack_probability = float(row["max_attack_probability"])
            window_pred_label = int(row["window_pred_label"])

            if not args.no_packet_csv and records:
                append_packet_predictions(
                    packet_csv,
                    df,
                    window_id=window_id,
                    probabilities=probabilities,
                    labels=labels,
                )

            label_text = "ATTACK" if window_pred_label else "BENIGN"
            print(
                f"[{window_id}] {label_text} file={pcap_path.name} "
                f"records={records:,} attack_ratio={attack_ratio:.3f} "
                f"max_prob={max_attack_probability:.6f}"
            )
        return

    interface = choose_interface(tshark, args.interface)

    print(f"Model          : {model_path}")
    print(f"tshark         : {tshark}")
    print(f"Interface      : {interface}")
    print(f"Window seconds : {args.window_seconds}")
    print(f"Pause seconds  : {args.pause_seconds}")
    print(f"Flow threshold : {threshold:.6f}")
    print(
        "Window rule    : "
        f"max_probability >= {file_max_threshold:.6f} and "
        f"attack_record_ratio >= {file_ratio_threshold:.6f} and "
        f"records >= {min_records}"
    )
    print(f"Summary CSV    : {summary_csv}")
    if not args.no_packet_csv:
        print(f"Packet CSV     : {packet_csv}")
    print("Press Ctrl+C to stop.\n")

    if args.calibrate_windows > 0:
        calibration_rows: list[dict[str, object]] = []
        calibration_summary = output_dir / "baseline_capture_windows.csv"
        print(
            f"Baseline mode: capturing {args.calibrate_windows} benign window(s). "
            "Do not run attacks during calibration."
        )
        for window_id in range(1, args.calibrate_windows + 1):
            start = datetime.now().astimezone()
            timestamp = start.strftime("%Y%m%d_%H%M%S")
            raw_csv = raw_dir / f"baseline_{window_id:06d}_{timestamp}.csv"
            print(f"[baseline {window_id}] capturing {args.window_seconds}s...")
            row, df, probabilities, labels = capture_score_once(
                window_id=window_id,
                raw_csv=raw_csv,
                tshark=tshark,
                interface=interface,
                duration_seconds=args.window_seconds,
                fields=fields,
                valid_fields=valid_fields,
                capture_filter=args.capture_filter,
                display_filter=args.display_filter,
                packet_count=args.packet_count,
                bundle=bundle,
                threshold=threshold,
                file_max_threshold=file_max_threshold,
                file_ratio_threshold=file_ratio_threshold,
                min_records=min_records,
            )
            row["window_pred_label"] = 0
            append_row(calibration_summary, row, summary_fields)
            calibration_rows.append(row)
            print(
                f"[baseline {window_id}] records={int(row['records']):,} "
                f"attack_ratio={float(row['attack_record_ratio']):.3f} "
                f"max_prob={float(row['max_attack_probability']):.6f}"
            )
            if window_id < args.calibrate_windows:
                time.sleep(max(0.0, args.pause_seconds))

        baseline = build_baseline_from_rows(
            calibration_rows,
            output_path=baseline_out,
            model_path=model_path,
            threshold=threshold,
            file_max_threshold=file_max_threshold,
            current_file_ratio_threshold=file_ratio_threshold,
            min_records=min_records,
            baseline_quantile=args.baseline_quantile,
            baseline_margin=args.baseline_margin,
            max_ratio_threshold=args.max_ratio_threshold,
        )
        print("\nBaseline calibration complete.")
        print_baseline(baseline, baseline_out)
        print(f"Calibration windows saved to: {calibration_summary}")
        return

    window_id = 0
    try:
        while args.iterations == 0 or window_id < args.iterations:
            window_id += 1
            start = datetime.now().astimezone()
            timestamp = start.strftime("%Y%m%d_%H%M%S")
            raw_csv = raw_dir / f"window_{window_id:06d}_{timestamp}.csv"

            print(f"[{window_id}] capturing {args.window_seconds}s...")
            row, df, probabilities, labels = capture_score_once(
                window_id=window_id,
                raw_csv=raw_csv,
                tshark=tshark,
                interface=interface,
                duration_seconds=args.window_seconds,
                fields=fields,
                valid_fields=valid_fields,
                capture_filter=args.capture_filter,
                display_filter=args.display_filter,
                packet_count=args.packet_count,
                bundle=bundle,
                threshold=threshold,
                file_max_threshold=file_max_threshold,
                file_ratio_threshold=file_ratio_threshold,
                min_records=min_records,
            )
            append_row(summary_csv, row, summary_fields)

            records = int(row["records"])
            attack_ratio = float(row["attack_record_ratio"])
            max_attack_probability = float(row["max_attack_probability"])
            window_pred_label = int(row["window_pred_label"])

            if not args.no_packet_csv and records:
                append_packet_predictions(
                    packet_csv,
                    df,
                    window_id=window_id,
                    probabilities=probabilities,
                    labels=labels,
                )

            label_text = "ATTACK" if window_pred_label else "BENIGN"
            print(
                f"[{window_id}] {label_text} records={records:,} "
                f"attack_ratio={attack_ratio:.3f} "
                f"max_prob={max_attack_probability:.6f}"
            )

            if args.iterations == 0 or window_id < args.iterations:
                time.sleep(max(0.0, args.pause_seconds))
    except KeyboardInterrupt:
        print("\nStopped by user.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Wi-Fi IDS monitor using a trained Edge-IIoT XGBoost model. "
            "It can score live traffic or already-recorded PCAP files with tshark and append CSV results."
        )
    )
    parser.add_argument("--model", default=str(default_model_path()), help="Path to edge_iiot_xgb_model.joblib.")
    parser.add_argument("--tshark", default=None, help="Optional path to tshark/tshark.exe.")
    parser.add_argument("--list-interfaces", action="store_true", help="Print tshark interfaces and exit.")
    parser.add_argument(
        "--interface",
        default=None,
        help="Capture interface name or number for live mode. Use --list-interfaces first.",
    )
    parser.add_argument(
        "--pcap_dir",
        default=None,
        help="Folder of recorded PCAP files to score instead of doing live capture.",
    )
    parser.add_argument(
        "--pcap_glob",
        default="*.pcap*",
        help="Glob pattern used inside --pcap_dir. Default matches .pcap and .pcapng files.",
    )
    parser.add_argument(
        "--pcap_recursive",
        action="store_true",
        help="Search for PCAP files recursively inside --pcap_dir.",
    )
    parser.add_argument("--window_seconds", type=int, default=30, help="Capture duration for each live prediction window.")
    parser.add_argument("--pause_seconds", type=float, default=5.0, help="Pause between live capture windows.")
    parser.add_argument(
        "--iterations",
        type=int,
        default=0,
        help="Live mode: number of windows to run. PCAP mode: number of files to process. Use 0 for all.",
    )
    parser.add_argument("--output_dir", default=str(default_output_dir()), help="Folder for outputs.")
    parser.add_argument("--summary_csv", default="live_wifi_window_predictions.csv")
    parser.add_argument("--packet_csv", default="live_wifi_packet_predictions.csv")
    parser.add_argument("--no_packet_csv", action="store_true", help="Do not write per-packet prediction CSV.")
    parser.add_argument("--no_metadata", action="store_true", help="Capture only model fields, not IP/port metadata.")
    parser.add_argument("--threshold", type=float, default=None, help="Override per-record attack threshold.")
    parser.add_argument("--file_max_threshold", type=float, default=None, help="Override max-probability window rule.")
    parser.add_argument("--file_ratio_threshold", type=float, default=None, help="Override attack-ratio window rule.")
    parser.add_argument(
        "--min_records",
        type=int,
        default=50,
        help="Do not alert on windows/files with fewer than this many captured records.",
    )
    parser.add_argument(
        "--baseline_json",
        default=None,
        help="Load calibrated thresholds from this JSON file. Relative paths are under --output_dir.",
    )
    parser.add_argument(
        "--baseline_out",
        default="live_wifi_baseline.json",
        help="Where to write calibrated baseline JSON. Relative paths are under --output_dir.",
    )
    parser.add_argument(
        "--no_baseline",
        action="store_true",
        help="Do not auto-load live_wifi_baseline.json from the output folder.",
    )
    parser.add_argument(
        "--calibrate_windows",
        type=int,
        default=0,
        help="Capture this many benign live windows, write baseline JSON, then exit.",
    )
    parser.add_argument(
        "--calibrate_from_summary",
        default=None,
        help="Build baseline JSON from an existing live_wifi_window_predictions.csv, then exit.",
    )
    parser.add_argument(
        "--baseline_quantile",
        type=float,
        default=1.0,
        help="Normal attack-ratio quantile used for calibration. 1.0 means use the observed max.",
    )
    parser.add_argument(
        "--baseline_margin",
        type=float,
        default=0.05,
        help="Extra margin added above the normal baseline attack-ratio quantile.",
    )
    parser.add_argument(
        "--max_ratio_threshold",
        type=float,
        default=0.99,
        help="Upper cap for calibrated file/window attack-ratio threshold.",
    )
    parser.add_argument("--capture_filter", default=None, help="Optional BPF capture filter for live mode.")
    parser.add_argument("--display_filter", default=None, help="Optional Wireshark display filter.")
    parser.add_argument("--packet_count", type=int, default=None, help="Optional max packets per live window or PCAP file.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        monitor(args)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if platform.system().lower() == "windows":
            print("Hint: run PowerShell as Administrator and make sure Npcap is installed.", file=sys.stderr)
        elif platform.system().lower() == "darwin":
            print("Hint: live capture may require sudo or Wireshark capture permissions.", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
