from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import joblib
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from testoutside.live_wifi_edge_ids_pcap import (
    available_tshark_fields,
    capture_window_to_csv,
    choose_interface,
    find_tshark,
    list_interfaces,
    requested_tshark_fields,
)


def default_model_path() -> Path:
    local_model = Path(__file__).resolve().parent / "edge_iiot_xgb_model.joblib"
    if local_model.exists():
        return local_model
    return Path(__file__).resolve().parent.parent / "experment" / "edge_iiot_xgb_model.joblib"


def default_stream_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "stream_input" / "live"


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(col).replace("\ufeff", "").strip() for col in df.columns]
    return df.loc[:, ~df.columns.duplicated()]


def stringify_value(value: object) -> str:
    if pd.isna(value):
        return ""
    return str(value)


def dataframe_to_records(df: pd.DataFrame) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for row in df.to_dict(orient="records"):
        records.append({key: stringify_value(value) for key, value in row.items()})
    return records


def capture_window_frame(
    *,
    tshark: str,
    interface: str,
    duration_seconds: int,
    fields: list[str],
    valid_fields: set[str] | None,
    capture_filter: str | None,
    display_filter: str | None,
    packet_count: int | None,
    temp_csv: Path,
) -> tuple[pd.DataFrame, list[str]]:
    temp_csv.parent.mkdir(parents=True, exist_ok=True)
    supported_fields, unsupported_fields = capture_window_to_csv(
        tshark=tshark,
        interface=interface,
        duration_seconds=duration_seconds,
        output_csv=temp_csv,
        fields=fields,
        valid_fields=valid_fields,
        capture_filter=capture_filter,
        display_filter=display_filter,
        packet_count=packet_count,
    )

    if temp_csv.exists() and temp_csv.stat().st_size > 0:
        df = pd.read_csv(temp_csv, low_memory=False)
    else:
        df = pd.DataFrame(columns=supported_fields)

    df = normalize_columns(df)
    for field in fields:
        if field not in df.columns:
            df[field] = ""
    df = df[fields]
    return df, unsupported_fields


def write_atomic_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    tmp_path.replace(path)


def build_window_document(
    *,
    window_id: int,
    interface: str,
    start_time: datetime,
    end_time: datetime,
    capture_seconds: int,
    source_path: str,
    stream_json_path: str,
    df: pd.DataFrame,
    unsupported_fields: list[str],
    capture_filter: str | None,
    display_filter: str | None,
) -> dict[str, object]:
    window_file = f"window_{window_id:06d}_{start_time.strftime('%Y%m%d_%H%M%S')}.json"
    records = dataframe_to_records(df)
    return {
        "window_id": window_id,
        "window_start": start_time.isoformat(timespec="seconds"),
        "window_end": end_time.isoformat(timespec="seconds"),
        "interface": interface,
        "source_path": source_path,
        "stream_file": window_file,
        "stream_json_path": stream_json_path,
        "window_seconds": int(capture_seconds),
        "record_count": int(len(records)),
        "capture_filter": capture_filter or "",
        "display_filter": display_filter or "",
        "unsupported_tshark_fields": unsupported_fields,
        "records": records,
    }


def write_window(
    *,
    stream_dir: Path,
    payload: dict[str, object],
) -> Path:
    stream_dir.mkdir(parents=True, exist_ok=True)
    output_path = stream_dir / str(payload["stream_file"])
    write_atomic_json(output_path, payload)
    return output_path


def run_live_capture(args: argparse.Namespace) -> None:
    tshark = find_tshark(args.tshark)
    if args.list_interfaces:
        print(list_interfaces(tshark))
        return

    model_path = Path(args.model).expanduser().resolve()
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")

    bundle = joblib.load(model_path)
    feature_fields = requested_tshark_fields(bundle, include_metadata=False)
    valid_fields = available_tshark_fields(tshark)
    interface = choose_interface(tshark, args.interface)

    stream_dir = Path(args.stream_dir).expanduser().resolve()
    temp_dir = Path(args.temp_dir).expanduser().resolve()
    temp_dir.mkdir(parents=True, exist_ok=True)

    print(f"Model          : {model_path}")
    print(f"tshark         : {tshark}")
    print(f"Interface      : {interface}")
    print(f"Window seconds : {args.window_seconds}")
    print(f"Pause seconds  : {args.pause_seconds}")
    print(f"Stream dir     : {stream_dir}")
    print(f"Temp dir       : {temp_dir}")
    print(f"Feature fields : {len(feature_fields):,}")
    print("Press Ctrl+C to stop.\n")

    window_id = 0
    try:
        while args.iterations == 0 or window_id < args.iterations:
            window_id += 1
            start_time = datetime.now().astimezone()
            temp_csv = temp_dir / f"window_{window_id:06d}_{start_time.strftime('%Y%m%d_%H%M%S')}.csv"

            print(f"[{window_id}] capturing {args.window_seconds}s...")
            df, unsupported_fields = capture_window_frame(
                tshark=tshark,
                interface=interface,
                duration_seconds=args.window_seconds,
                fields=feature_fields,
                valid_fields=valid_fields,
                capture_filter=args.capture_filter,
                display_filter=args.display_filter,
                packet_count=args.packet_count,
                temp_csv=temp_csv,
            )
            end_time = datetime.now().astimezone()

            payload = build_window_document(
                window_id=window_id,
                interface=interface,
                start_time=start_time,
                end_time=end_time,
                capture_seconds=args.window_seconds,
                source_path="live_capture",
                stream_json_path=str(stream_dir / f"window_{window_id:06d}_{start_time.strftime('%Y%m%d_%H%M%S')}.json"),
                df=df,
                unsupported_fields=unsupported_fields,
                capture_filter=args.capture_filter,
                display_filter=args.display_filter,
            )
            output_path = write_window(stream_dir=stream_dir, payload=payload)
            temp_csv.unlink(missing_ok=True)

            print(
                f"[{window_id}] wrote {output_path.name} "
                f"records={payload['record_count']:,} "
                f"unsupported_fields={len(unsupported_fields)}"
            )

            if args.iterations == 0 or window_id < args.iterations:
                time.sleep(max(0.0, args.pause_seconds))
    except KeyboardInterrupt:
        print("\nStopped by user.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Capture live traffic with tshark and emit one JSON window document per capture window for Spark."
        )
    )
    parser.add_argument("--model", default=str(default_model_path()), help="Path to edge_iiot_xgb_model.joblib.")
    parser.add_argument("--tshark", default=None, help="Optional path to tshark/tshark.exe.")
    parser.add_argument("--list-interfaces", action="store_true", help="Print tshark interfaces and exit.")
    parser.add_argument(
        "--interface",
        default=None,
        help="Capture interface name or number. Use --list-interfaces first.",
    )
    parser.add_argument(
        "--stream_dir",
        default=str(default_stream_dir()),
        help="Directory where JSON window documents will be written for Spark to consume.",
    )
    parser.add_argument(
        "--temp_dir",
        default=str(default_stream_dir().parent / "live-tmp"),
        help="Temporary folder used while capturing tshark CSV output.",
    )
    parser.add_argument("--window_seconds", type=int, default=30, help="Capture duration for each window.")
    parser.add_argument("--pause_seconds", type=float, default=5.0, help="Pause between capture windows.")
    parser.add_argument(
        "--iterations",
        type=int,
        default=0,
        help="Number of windows to capture. Use 0 for continuous capture.",
    )
    parser.add_argument("--capture_filter", default=None, help="Optional BPF capture filter.")
    parser.add_argument("--display_filter", default=None, help="Optional tshark display filter.")
    parser.add_argument("--packet_count", type=int, default=None, help="Optional packet cap for each window.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    run_live_capture(args)


if __name__ == "__main__":
    main()
