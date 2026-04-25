from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

from pymongo import MongoClient


ROOT = Path(__file__).resolve().parent
STREAM_DIR_DEFAULT = ROOT / "stream_input" / "live"
CHECKPOINT_DIR_DEFAULT = ROOT / "stream_input" / "checkpoints"
TEMP_DIR_DEFAULT = ROOT / "stream_input" / "live-tmp"


def safe_rmtree(path: Path) -> None:
    resolved = path.resolve()
    if not resolved.exists():
        return
    if ROOT not in resolved.parents and resolved != ROOT:
        raise RuntimeError(f"Refusing to delete path outside repo root: {resolved}")
    shutil.rmtree(resolved)


def reset_directory(path: Path) -> None:
    safe_rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def reset_mongo(uri: str, db_name: str, collections: list[str]) -> None:
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")
    db = client[db_name]
    for collection in collections:
        db[collection].drop()


def launch_process(name: str, cmd: list[str], *, cwd: Path) -> subprocess.Popen:
    print(f"Starting {name}:")
    print("  " + " ".join(cmd))
    return subprocess.Popen(cmd, cwd=str(cwd))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Launch the live Edge-IIoT Spark + MongoDB demo.")
    parser.add_argument("--interface", required=True, help="Capture interface number/name for tshark.")
    parser.add_argument("--tshark", default=None, help="Optional explicit path to tshark/tshark.exe.")
    parser.add_argument("--window_seconds", type=int, default=30, help="Capture duration for each window.")
    parser.add_argument("--pause_seconds", type=float, default=5.0, help="Pause between capture windows.")
    parser.add_argument("--stream_dir", default=str(STREAM_DIR_DEFAULT), help="Folder where live JSON windows are written.")
    parser.add_argument("--checkpoint_dir", default=str(CHECKPOINT_DIR_DEFAULT), help="Spark checkpoint folder.")
    parser.add_argument("--temp_dir", default=str(TEMP_DIR_DEFAULT), help="Temporary folder used by the live producer.")
    parser.add_argument("--mongo_uri", default="mongodb://localhost:27017", help="MongoDB connection URI.")
    parser.add_argument("--mongo_db", default="edgeids", help="MongoDB database name.")
    parser.add_argument("--no_reset", action="store_true", help="Do not delete old stream files, checkpoints, or MongoDB collections.")
    parser.add_argument("--spark_poll_seconds", type=float, default=2.0, help="Delay before the producer starts after Spark launches.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    stream_dir = Path(args.stream_dir).expanduser().resolve()
    checkpoint_dir = Path(args.checkpoint_dir).expanduser().resolve()
    temp_dir = Path(args.temp_dir).expanduser().resolve()

    if not args.no_reset:
        print("Resetting previous stream state...")
        reset_directory(stream_dir)
        reset_directory(checkpoint_dir)
        reset_directory(temp_dir)
        reset_mongo(args.mongo_uri, args.mongo_db, ["windows", "predictions", "alerts"])

    spark_cmd = [
        sys.executable,
        "-u",
        str(ROOT / "spark_streaming" / "edge_ids_stream.py"),
        "--input_dir",
        str(stream_dir),
        "--checkpoint_dir",
        str(checkpoint_dir),
        "--mongo_uri",
        args.mongo_uri,
        "--mongo_db",
        args.mongo_db,
    ]

    dashboard_cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(ROOT / "spark_streaming" / "ids_dashboard.py"),
    ]

    producer_cmd = [
        sys.executable,
        "-u",
        str(ROOT / "testoutside" / "live_wifi_edge_ids.py"),
        "--interface",
        str(args.interface),
        "--window_seconds",
        str(args.window_seconds),
        "--pause_seconds",
        str(args.pause_seconds),
        "--stream_dir",
        str(stream_dir),
        "--temp_dir",
        str(temp_dir),
    ]
    if args.tshark:
        producer_cmd.extend(["--tshark", args.tshark])

    procs: list[tuple[str, subprocess.Popen]] = []
    try:
        procs.append(("spark", launch_process("Spark stream", spark_cmd, cwd=ROOT)))
        time.sleep(max(0.5, float(args.spark_poll_seconds)))
        procs.append(("dashboard", launch_process("Streamlit dashboard", dashboard_cmd, cwd=ROOT)))
        time.sleep(1.0)
        procs.append(("producer", launch_process("Live producer", producer_cmd, cwd=ROOT)))

        print("\nAll services launched.")
        print(f"Interface: {args.interface}")
        print("Use Ctrl+C in this terminal to stop everything.\n")

        while True:
            for name, proc in procs:
                code = proc.poll()
                if code is not None:
                    raise RuntimeError(f"{name} exited with code {code}")
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nStopping services...")
    finally:
        for _, proc in reversed(procs):
            if proc.poll() is None:
                proc.terminate()
        deadline = time.time() + 15
        for _, proc in reversed(procs):
            if proc.poll() is None:
                remaining = max(0.1, deadline - time.time())
                try:
                    proc.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    proc.kill()


if __name__ == "__main__":
    main()
