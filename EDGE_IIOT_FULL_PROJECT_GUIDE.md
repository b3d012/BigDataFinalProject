# Edge-IIoT Project Explanation and Run Guide

## 1. Big picture

This project has one trained IDS model and two ways to use it:

1. offline replay mode  
   - train the model from the Edge-IIoT CSV dataset
   - take saved PCAP files from the `attack/` folder
   - extract the same tshark feature fields from those PCAPs
   - score them with the trained model

2. live monitoring mode  
   - capture live traffic in time windows with `tshark`
   - extract the same tshark feature fields
   - score each live window with the same trained model
   - optionally calibrate a benign baseline first

So the real pipeline is:

Edge-IIoT dataset -> trained XGBoost bundle -> tshark feature extraction -> offline PCAP scoring or live window scoring

---

## 2. Why this model works better than the old CICFlowMeter one

The old CICFlowMeter approach had a mismatch between:
- what the model was trained on
- what the live system extracted from local traffic

This Edge-IIoT project works better because:
- the model is trained on Wireshark/tshark-style packet fields
- the offline and live scripts also extract Wireshark/tshark-style packet fields
- the same saved model bundle is reused for both offline and live scoring

So training and inference are much more consistent.

That is the main reason this pipeline works better.

---

## 3. Main scripts

## A. `edge_iiot_experiment.py`

This is the main training and offline replay script.

It supports:
- `train`
- `extract`
- `score`
- `compare`
- `run`

### What each subcommand does

### `train`
- loads the Edge-IIoT dataset CSV
- builds binary labels from `Attack_label` or `Attack_type`
- drops duplicate rows by default
- removes identity and payload-heavy fields by default
- infers numeric vs categorical features
- builds a preprocessing pipeline
- trains an XGBoost classifier
- chooses a threshold strategy
- evaluates on a holdout split
- retrains a final model on the full dataset
- saves a model bundle and metadata

### `extract`
- reads PCAP files from the `attack/` folder by default
- uses `tshark` to extract Edge-IIoT-style fields
- saves those extracted CSVs to `experment/extracted-attack-edge-csvs`

### `score`
- reads the extracted CSVs
- aligns them to the training feature contract
- runs the saved model bundle
- creates prediction CSV files and summary files

### `compare`
- compares extracted local CSVs with the Edge-IIoT training CSV schema and value ranges

### `run`
- performs train + extract + score + compare in one command

---

## B. `live_wifi_edge_ids_pcap.py`

This is the live and PCAP scoring script.

It can run in two modes:

### live mode
- captures live traffic from a selected interface with `tshark`
- writes temporary/raw CSV windows
- applies the same model bundle
- writes live prediction summaries
- can calibrate a benign baseline

### PCAP mode
- reads already-saved PCAP files from a folder
- extracts the model fields from each PCAP
- scores each file
- writes summary and per-record results

---

## 4. Important difference between the two scripts

### `edge_iiot_experiment.py`
Use this for:
- training the model
- extracting from saved PCAPs in `attack/`
- scoring extracted CSVs
- offline experiments

### `live_wifi_edge_ids_pcap.py`
Use this for:
- live capture and live scoring
- baseline calibration
- optionally scoring saved PCAP folders too

So the clean split is:

- `edge_iiot_experiment.py` = training + offline replay pipeline
- `live_wifi_edge_ids_pcap.py` = live monitor and optional PCAP scorer

---

## 5. Should you change the live script to use `attack/` instead of `pcaps/`?

Do **not** change the script just to rename the folder.

The folder name itself does **not** affect accuracy.

What matters is:
- which PCAP files you give the script
- whether the extracted tshark fields match the training feature contract

If you want `live_wifi_edge_ids_pcap.py` to score the same saved attack PCAPs that `edge_iiot_experiment.py` uses, just pass:

```powershell
--pcap_dir attack
```

That is enough.

### Recommended answer for your dr
- `attack/` is the offline replay folder used by `edge_iiot_experiment.py`
- `live_wifi_edge_ids_pcap.py` is more general and can read any PCAP folder through `--pcap_dir`
- the folder name is only for organization, not model accuracy

### Important warning
Do **not** hardcode `attack` as the default PCAP folder inside `live_wifi_edge_ids_pcap.py` unless you are sure you want it to default into PCAP mode.

If `--pcap_dir` is always set by default, the script may stop behaving like a live monitor by default.

Best practice:
- keep the script generic
- use `--pcap_dir attack` when you want offline PCAP scoring
- use `--interface ...` when you want live capture

---

## 6. How the model is trained

The training data is the Edge-IIoT dataset CSV:
- `experment/ML-EdgeIIoT-dataset.csv`

### Training process

1. load the CSV
2. normalize column names
3. build binary labels from:
   - `Attack_label`
   - or `Attack_type`
4. remove duplicate rows by default
5. drop identity/payload-heavy columns by default, such as:
   - timestamps
   - source/destination IPs
   - some full payload or URI-like fields
   - source/destination ports in the default training path
6. infer numeric and categorical columns
7. build preprocessing:
   - numeric -> median imputation
   - categorical -> missing fill + one-hot encoding
8. split into:
   - training
   - validation
   - holdout test
9. train XGBoost
10. choose the record threshold
    - default script behavior uses a fixed threshold of `0.5`
11. evaluate on holdout data
12. retrain the final model on the full dataset
13. save:
    - model bundle
    - metadata JSON
    - feature importance CSV

### What the model bundle contains
The saved `.joblib` bundle includes:
- the XGBoost model
- the preprocessor
- the chosen thresholds
- file/window decision thresholds
- training feature metadata

This matters because the same bundle is reused for offline scoring and live scoring.

---

## 7. Why the model works on local/live data

It works because the project uses the same style of features in both places:

### training
- Edge-IIoT CSV uses Wireshark/tshark-style fields

### inference
- saved PCAPs are converted with `tshark` into those same field types
- live capture also uses `tshark` to extract those same field types

So the model sees a representation that is much closer to what it learned during training.

That is the main reason it generalizes better than the old CICFlowMeter path.

---

## 8. Outputs you should expect

## From training
After:

```powershell
python experment/edge_iiot_experiment.py train
```

You should get:
- `experment/edge_iiot_xgb_model.joblib`
- `experment/edge_iiot_xgb_model.metadata.json`
- `experment/edge_iiot_xgb_model.feature_importance.csv`

## From extract
After:

```powershell
python experment/edge_iiot_experiment.py extract --tshark "C:\Program Files\Wireshark\tshark.exe"
```

You should get:
- `experment/extracted-attack-edge-csvs/*.csv`

## From score
After:

```powershell
python experment/edge_iiot_experiment.py score
```

You should get:
- `experment/edge_iiot_attack_predictions.csv`
- `experment/edge_iiot_attack_predictions_summary.csv`

## From live monitor
After running the live script, you should get files under:
- `testoutside/live-output/`
or another `--output_dir` you choose

Usually:
- `live_wifi_window_predictions.csv`
- `live_wifi_packet_predictions.csv`
- `raw-window-csvs/`

---

## 9. Commands to run everything

## Step 1. Create environment

```powershell
conda create -n edgeids python=3.11 -y
conda activate edgeids
pip install pandas numpy joblib scikit-learn xgboost
```

Install Wireshark and make sure `tshark.exe` exists.

---

## Step 2. Train the model

```powershell
python experment/edge_iiot_experiment.py train
```

---

## Step 3. Extract saved PCAPs from `attack/`

```powershell
python experment/edge_iiot_experiment.py extract --tshark "C:\Program Files\Wireshark\tshark.exe"
```

---

## Step 4. Score the extracted CSVs

```powershell
python experment/edge_iiot_experiment.py score
```

---

## Step 5. Or do the full offline pipeline in one command

```powershell
python experment/edge_iiot_experiment.py run --tshark "C:\Program Files\Wireshark\tshark.exe"
```

---

## Step 6. List live interfaces

```powershell
python testoutside/live_wifi_edge_ids_pcap.py --list-interfaces --tshark "C:\Program Files\Wireshark\tshark.exe"
```

---

## Step 7. Calibrate a benign live baseline

Use this only when no attack is active.

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

---

## Step 8. Run live monitoring

```powershell
python testoutside/live_wifi_edge_ids_pcap.py `
  --tshark "C:\Program Files\Wireshark\tshark.exe" `
  --interface 5 `
  --window_seconds 30 `
  --pause_seconds 5 `
  --output_dir testoutside/live-output
```

Replace `5` with your actual interface number.

---

## Step 9. Use the live script to score the `attack/` folder too

If you want the live script to score saved attack PCAPs instead of live traffic:

```powershell
python testoutside/live_wifi_edge_ids_pcap.py `
  --tshark "C:\Program Files\Wireshark\tshark.exe" `
  --pcap_dir attack `
  --pcap_glob "*.pcap*" `
  --output_dir testoutside/live-output
```

This does **not** require changing the script code.

---

## 10. Suggested explanation to your dr

You can explain the project like this:

> We trained an XGBoost IDS model on the Edge-IIoT dataset, which contains Wireshark/tshark-style packet fields.  
> During training, we removed duplicate rows, dropped identity and payload-heavy columns to reduce memorization, built binary attack labels, and trained an XGBoost model with a saved preprocessing bundle.  
> For offline replay, we use saved PCAPs in the `attack/` folder, extract the same tshark feature fields, and score them with the trained bundle using `edge_iiot_experiment.py`.  
> For live monitoring, we use `live_wifi_edge_ids_pcap.py`, which captures live traffic in windows with `tshark`, extracts the same field representation, and scores each window with the same model.  
> We also calibrate a benign baseline so normal network traffic does not cause too many false alerts.  
> The reason this pipeline works is that the training features and inference features are aligned: both are based on the same tshark/Wireshark-style packet fields.

---

## 11. Final recommendation

Use this as your final setup:

- `edge_iiot_experiment.py` for:
  - training
  - offline extraction
  - offline scoring
- `live_wifi_edge_ids_pcap.py` for:
  - live monitoring
  - live baseline calibration
  - optional saved-PCAP scoring by passing `--pcap_dir attack`

That keeps the project simple and easy to explain.
