# Edge-IIoT IDS Project

An intrusion detection project built around an **XGBoost model trained on the Edge-IIoT dataset** and deployed in two practical modes:

1. **Offline replay mode** using saved PCAP files
2. **Live monitoring mode** using `tshark` capture windows

The core pipeline is:

**Edge-IIoT dataset -> trained XGBoost bundle -> tshark feature extraction -> offline or live scoring**

---

## Project description

This project trains an intrusion detection model on the Edge-IIoT dataset and then reuses the same trained bundle to analyze either:

- saved PCAP attack files from the `attack/` folder
- live traffic captured directly from a network interface

The reason this setup works is that the **training data** and the **inference data** use the same style of features: Wireshark/tshark-style packet fields.

---

## Why this pipeline works

The earlier CICFlowMeter approach struggled because there was a mismatch between:

- the features used in training
- the features extracted from local/live traffic

This Edge-IIoT project works better because:

- the model is trained on **Wireshark/tshark-style fields**
- the offline and live scripts also extract **Wireshark/tshark-style fields**
- the same saved model bundle is reused for both offline replay and live monitoring

That makes training and inference much more consistent.

---

## Main scripts

## 1. `experment/edge_iiot_experiment.py`

This is the main **training + offline replay** script.

It supports these subcommands:

- `train`
- `extract`
- `score`
- `compare`
- `run`

### What each subcommand does

### `train`
- loads `ML-EdgeIIoT-dataset.csv`
- builds binary labels from `Attack_label` or `Attack_type`
- drops duplicate rows by default
- removes identity and payload-heavy fields by default
- infers numeric and categorical columns
- builds preprocessing
- trains an XGBoost classifier
- evaluates on a holdout split
- saves the final model bundle, metadata, and feature importance

### `extract`
- reads PCAP files from the `attack/` folder
- uses `tshark` to extract Edge-IIoT-style fields
- writes extracted CSV files

### `score`
- reads the extracted CSVs
- aligns them to the training feature contract
- scores them with the saved model bundle
- writes prediction and summary CSV files

### `compare`
- compares extracted local CSV values with the training dataset schema and ranges

### `run`
- performs `train + extract + score + compare` in one command

---

## 2. `testoutside/live_wifi_edge_ids_pcap.py`

This is the **live monitoring** script.

It supports two modes:

### Live mode
- captures traffic from a network interface with `tshark`
- groups traffic into time windows
- extracts the model fields
- scores each window
- writes live prediction summaries
- supports benign baseline calibration

### PCAP mode
- reads already-saved PCAP files from a folder
- extracts the model fields
- scores each file
- writes summary and per-record outputs

So this script can be used for:

- live traffic monitoring
- scoring saved PCAP folders by passing `--pcap_dir`

---

## Recommended project structure

```text
BIGDATAFINALPROJECT/
├── attack/
│   └── *.pcap / *.pcapng
├── data/
│   └── dataedge-iot/
│       ├── ML-EdgeIIoT-dataset.csv
│       ├── DNN-EdgeIIoT-dataset.csv
│       └── live_data_training.csv
├── experment/
│   ├── edge_iiot_experiment.py
│   ├── ML-EdgeIIoT-dataset.csv
│   ├── extracted-attack-edge-csvs/
│   ├── edge_iiot_xgb_model.joblib
│   ├── edge_iiot_xgb_model.metadata.json
│   ├── edge_iiot_xgb_model.feature_importance.csv
│   ├── edge_iiot_attack_predictions.csv
│   └── edge_iiot_attack_predictions_summary.csv
├── testoutside/
│   └── live_wifi_edge_ids_pcap.py
├── environment-edgeids.yml
└── README.md
```

---

## How the model is trained

The training dataset used is:

```text
experment/ML-EdgeIIoT-dataset.csv
```

### Training process

1. load the Edge-IIoT CSV
2. normalize column names
3. build binary labels from `Attack_label` or `Attack_type`
4. drop duplicate rows by default
5. drop identity and payload-heavy fields by default
6. infer numeric and categorical columns
7. build preprocessing:
   - numeric -> median imputation
   - categorical -> missing fill + one-hot encoding
8. split into train / validation / holdout test
9. train XGBoost
10. choose the classification threshold
11. evaluate on the holdout data
12. retrain the final model on the full dataset
13. save:
   - model bundle
   - metadata JSON
   - feature importance CSV

### Saved model bundle

The saved `.joblib` bundle contains:
- the XGBoost model
- the preprocessing pipeline
- the chosen thresholds
- file/window decision thresholds
- training feature metadata

This same bundle is reused for both offline replay and live scoring.

---

## Offline replay workflow

The `attack/` folder contains saved PCAP files used for controlled replay and evaluation.

### Step 1. Extract features from saved PCAPs

```powershell
python experment/edge_iiot_experiment.py extract --tshark "C:\Program Files\Wireshark\tshark.exe"
```

### Step 2. Score the extracted CSVs

```powershell
python experment/edge_iiot_experiment.py score
```

### Final outputs

This produces:

- `experment/edge_iiot_attack_predictions.csv`
- `experment/edge_iiot_attack_predictions_summary.csv`

---

## Live monitoring workflow

The live script uses `tshark` to capture traffic directly from an interface and score it in time windows.

### List interfaces

```powershell
python testoutside/live_wifi_edge_ids_pcap.py --list-interfaces --tshark "C:\Program Files\Wireshark\tshark.exe"
```

### Run benign baseline calibration

Do this only when **no attack** is active.

```powershell
python testoutside/live_wifi_edge_ids_pcap.py `
  --tshark "C:\Program Files\Wireshark\tshark.exe" `
  --interface 5 `
  --window_seconds 30 `
  --pause_seconds 5 `
  --calibrate_windows 20 `
  --output_dir testoutside/live-output `
  --no_packet_csv
```

### Run live monitoring

```powershell
python testoutside/live_wifi_edge_ids_pcap.py `
  --tshark "C:\Program Files\Wireshark\tshark.exe" `
  --interface 5 `
  --window_seconds 30 `
  --pause_seconds 5 `
  --output_dir testoutside/live-output
```

Replace `5` with the correct interface number.

---

## Setup

### Create the environment

```powershell
conda env create -f environment-edgeids.yml
conda activate edgeids
```

Install Wireshark and make sure `tshark.exe` is available.

---

## Training commands

### Train the model

```powershell
python experment/edge_iiot_experiment.py train
```

### Run the full offline pipeline in one command

```powershell
python experment/edge_iiot_experiment.py run --tshark "C:\Program Files\Wireshark\tshark.exe"
```

---

## How to explain this project

A simple explanation for supervisors or reviewers:

> This project trains an XGBoost intrusion detection model on the Edge-IIoT dataset, which contains Wireshark/tshark-style packet fields. During training, duplicate rows are removed, identity and payload-heavy columns are dropped, and the remaining fields are preprocessed and used to train the model. The resulting model bundle is then reused in two ways: first, to score saved PCAP attack files through an offline replay pipeline, and second, to score live traffic windows captured with tshark. The reason this works is that both training and inference use the same style of packet-level tshark features.

---

## Notes

- The `attack/` folder is used for saved replay PCAPs.
- `live_wifi_edge_ids_pcap.py` does **not** need to be hardcoded to `attack/`; use `--pcap_dir attack` if you want that script to score the same saved PCAPs.
- The folder name itself does not affect model accuracy.
- Accuracy depends on the extracted tshark fields matching the training feature contract.

---

## Minimal usage summary

### Train
```powershell
python experment/edge_iiot_experiment.py train
```

### Extract from saved PCAPs
```powershell
python experment/edge_iiot_experiment.py extract --tshark "C:\Program Files\Wireshark\tshark.exe"
```

### Score extracted PCAP CSVs
```powershell
python experment/edge_iiot_experiment.py score
```

### Live monitor
```powershell
python testoutside/live_wifi_edge_ids_pcap.py `
  --tshark "C:\Program Files\Wireshark\tshark.exe" `
  --interface 5 `
  --window_seconds 30 `
  --pause_seconds 5 `
  --output_dir testoutside/live-output
```
