# IDS Experiment Summary

## Final Status

The current working implementation satisfies the main project pipeline for the class demo:

```text
Edge-IIoT dataset -> XGBoost model -> tshark live windows -> Spark Structured Streaming -> MongoDB -> Streamlit dashboard
```

The offline PCAP replay path still exists, but the primary live demo now runs through Spark and MongoDB.

## What Is Complete

- Edge-IIoT dataset training is complete.
- The model is trained and saved as a reusable `joblib` bundle.
- Live traffic is captured in 30-second `tshark` windows.
- Spark Structured Streaming consumes those window JSON files.
- MongoDB stores live windows, predictions, and alerts.
- Streamlit shows the live state for the demo.
- A one-command launcher resets old state and starts all three services together.

## What The Dashboard Shows

The dashboard is intentionally small and sufficient for the demo:

- total windows ingested
- total predictions written
- total alerts written
- latest attack ratio
- latest max attack probability
- recent alert and prediction tables
- prediction trend chart

Optional metrics, such as processing latency or throughput per minute, can be added later, but they are not required for the class demo.

## Current Model Metrics

Last Edge-IIoT holdout test:

| Metric | Value |
|---|---:|
| Rows after duplicate removal | `156,986` |
| Features used | `32` |
| Holdout test rows | `31,398` |
| Accuracy | `0.9472` |
| ROC-AUC | `0.9926` |
| PR-AUC | `0.9985` |
| Normal precision | `0.77` |
| Normal recall | `0.95` |
| Attack precision | `0.99` |
| Attack recall | `0.95` |
| True negatives | `4,600` |
| False positives | `260` |
| False negatives | `1,398` |
| True positives | `25,140` |

## Current Live Demo Stack

| Component | File |
|---|---|
| Live tshark window producer | `testoutside/live_wifi_edge_ids.py` |
| Spark Structured Streaming job | `spark_streaming/edge_ids_stream.py` |
| MongoDB dashboard | `spark_streaming/ids_dashboard.py` |
| One-command launcher | `run_live_demo.py` |
| Existing model bundle | `experment/edge_iiot_xgb_model.joblib` |

## Current Collections

MongoDB collections used by the live demo:

- `windows`
- `predictions`
- `alerts`

The `windows` collection stores metadata and a bounded record preview. The full JSON window remains on disk in `stream_input/live/`.

## Demo Launch

Use this command for a fresh run:

```powershell
python run_live_demo.py `
  --interface 5 `
  --tshark "C:\Program Files\Wireshark\tshark.exe"
```

The launcher clears old stream files, checkpoints, and MongoDB collections before it starts.

## Report-Ready Summary

This project demonstrates a complete intrusion-detection pipeline for the class: a public dataset is used to train an XGBoost model offline, live traffic is captured in fixed windows with `tshark`, Spark processes the windows as a streaming workload, MongoDB stores the live outputs, and Streamlit provides a simple operational view of the live system. The same feature contract is used end to end, which is why the model works across both training and live inference.
