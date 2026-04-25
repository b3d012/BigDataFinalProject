# Edge-IIoT Project Guide and Runbook

## 1. Big Picture

This project has one trained IDS model and two ways to use it:

1. Offline replay mode
   - train the model from the Edge-IIoT dataset
   - extract tshark features from saved PCAP files
   - score the extracted files with the saved model bundle

2. Live monitoring mode
   - capture live traffic in fixed windows with `tshark`
   - write one JSON document per window
   - stream those windows through Spark
   - store windows, predictions, and alerts in MongoDB
   - show the live state in Streamlit

The live demo stack is:

```text
Edge-IIoT dataset -> XGBoost bundle -> tshark windows -> Spark Structured Streaming -> MongoDB -> Streamlit
```

---

## 2. Why This Pipeline Works

The project works because the training data and inference data use the same style of tshark/Wireshark feature fields.

That gives you a consistent feature contract:

- training on Edge-IIoT CSV data
- inference from tshark feature windows

This is why the same saved model bundle can be reused for both offline scoring and live monitoring.

---

## 3. Main Scripts

### A. `experment/edge_iiot_experiment.py`

This is the training and offline replay script.

It supports:

- `train`
- `extract`
- `score`
- `compare`
- `run`

What it does:

- loads the Edge-IIoT dataset CSV
- builds binary labels from `Attack_label` or `Attack_type`
- drops duplicate rows by default
- removes identity and payload-heavy columns by default
- infers numeric and categorical features
- builds preprocessing
- trains an XGBoost classifier
- evaluates the model
- saves the final model bundle and metadata

### B. `testoutside/live_wifi_edge_ids.py`

This is the live capture producer for the classroom demo.

It:

- captures live traffic with `tshark`
- groups traffic into 30-second windows
- writes one JSON document per window into `stream_input/live/`

If you want to use a different network interface next week, change the `--interface` value when you run this script or the launcher.

### C. `spark_streaming/edge_ids_stream.py`

This is the Spark Structured Streaming job.

It:

- reads the JSON window files from `stream_input/live/`
- loads the saved model bundle
- scores each window
- writes to MongoDB collections:
  - `windows`
  - `predictions`
  - `alerts`

The `windows` collection stores metadata and a bounded record preview. The full JSON window stays on disk in `stream_input/live/` so MongoDB documents stay small.

### D. `spark_streaming/ids_dashboard.py`

This is the dashboard.

It reads MongoDB and shows:

- total windows
- total predictions
- total alerts
- latest attack ratio
- latest max attack probability
- recent alerts
- recent predictions
- a simple trend chart

For the class demo, these metrics are sufficient.

### E. `run_live_demo.py`

This is the recommended launcher.

It:

- clears old stream files
- clears old Spark checkpoints
- clears temporary capture files
- drops the MongoDB collections
- starts Spark
- starts Streamlit
- starts the live producer

---

## 4. Dashboard Scope

The dashboard is intentionally minimal.

It is enough to show:

- the stream is active
- the model is producing predictions
- alerts are being recorded
- recent traffic can be inspected quickly

Optional metrics like processing latency or throughput per minute are nice to have, but they are not required for the project requirements or the class demo.

---

## 5. How The Model Is Trained

The training dataset is:

```text
experment/ML-EdgeIIoT-dataset.csv
```

Training flow:

1. load the CSV
2. normalize column names
3. build binary labels
4. remove duplicate rows
5. drop identity and payload-heavy columns
6. infer numeric and categorical columns
7. build preprocessing
8. split into train, validation, and holdout test sets
9. train XGBoost
10. evaluate on holdout data
11. retrain the final model on the full dataset
12. save the model bundle, metadata JSON, and feature importance CSV

The saved `joblib` bundle contains the trained model, preprocessing pipeline, thresholds, and feature metadata.

---

## 6. Live Demo Commands

### Create the environment

```powershell
conda env create -f environment-edgeids.yml
conda activate edgeids
```

### Run the full live demo

```powershell
python run_live_demo.py `
  --interface 5 `
  --tshark "C:\Program Files\Wireshark\tshark.exe"
```

### Run the producer manually

```powershell
python testoutside/live_wifi_edge_ids.py `
  --tshark "C:\Program Files\Wireshark\tshark.exe" `
  --interface 5 `
  --window_seconds 30 `
  --pause_seconds 5 `
  --stream_dir stream_input/live
```

### Run Spark manually

```powershell
spark-submit spark_streaming/edge_ids_stream.py `
  --input_dir stream_input/live `
  --checkpoint_dir stream_input/checkpoints `
  --mongo_uri mongodb://localhost:27017 `
  --mongo_db edgeids
```

### Run the dashboard manually

```powershell
streamlit run spark_streaming/ids_dashboard.py
```

---

## 7. What To Mention In The Report

Use this short explanation in your report:

> The project trains an XGBoost intrusion detection model on the Edge-IIoT dataset. For the live system, tshark captures traffic in fixed windows, Spark Structured Streaming processes each window, MongoDB stores the live outputs, and Streamlit provides a dashboard for the class demo. The same tshark-style feature contract is used during both training and inference, which keeps the model consistent across offline and live use.

---

## 8. Notes

- `run_live_demo.py` is the recommended starting point for the final demo.
- `--interface` is where you change the capture NIC.
- The launcher resets the live stream folders and MongoDB collections by default.
- The legacy PCAP replay path is still available for offline evaluation.
- The dashboard does not need extra metrics unless you want to extend the project beyond the assignment requirements.
