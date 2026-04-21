# IDS Experiment Summary

## Final Status

The best working setup is the Edge-IIoT + Wireshark/tshark pipeline:

```text
Edge-IIoT CSV -> XGBoost model -> tshark extraction from local/live traffic -> calibrated window alerts
```

The current live test is usable after local benign baseline calibration. Without calibration, the model is too sensitive on normal Wi-Fi.

## Timeline

| Date | Step | Result |
|---|---|---|
| 2026-04-18 | CIC-IDS2017 CSV + CICFlowMeter pipeline | Found schema/feature mismatch between CIC CSVs and local PCAP extraction. |
| 2026-04-18 | Patched CICFlowMeter workflow | Improved column mapping and feature scaling, but local traffic still had strong domain shift. |
| 2026-04-19 | PCAP-first CIC plan | Prepared a better CIC method, but it required large CIC PCAPs and careful labeling. |
| 2026-04-19 | Switched to Edge-IIoTset | Better fit because Edge-IIoT provides Wireshark/tshark-style packet fields. |
| 2026-04-19 | Trained Edge-IIoT XGBoost model | Holdout accuracy `0.9474`, ROC-AUC `0.9926`, PR-AUC `0.9985`. |
| 2026-04-19 | Tested local PCAP files | Detected the named attacks and kept `BENIGN_BASELINE` / `noAttack*` benign using the calibrated file rule. |
| 2026-04-19 | Built live Wi-Fi monitor | Added macOS/Windows-compatible `tshark` monitor with CSV outputs. |
| 2026-04-19 | Tested normal Wi-Fi | Initial rule caused false positives on normal network traffic. |
| 2026-04-19 | Added benign baseline calibration | New calibrated ratio threshold `0.820186`; normal smoke test became benign. |
| 2026-04-20 | Reran Edge training with timing | Saved accuracy and speed metrics into model metadata. |

## Method Comparison

| Method | Extractor | Dataset Type | What Worked | Main Problem | Final Decision |
|---|---|---|---|---|---|
| CIC-IDS2017 CSV | Python `cicflowmeter` | Flow CSV | Basic XGBoost training worked. | Local PCAP features did not match CIC CSV feature semantics well. | Not final. Keep only as reference. |
| CIC PCAP-first | Same extractor for CIC + local PCAPs | Flow PCAP/CSV | Correct methodology for CIC-style work. | Needs large CIC PCAPs and precise labels. | Useful later, not current best. |
| Edge-IIoTset CSV | `tshark` | Wireshark packet-field CSV | Matched local PCAP extraction better than CICFlowMeter. | IoT/IIoT domain still differs from laptop Wi-Fi. | Current training pipeline. |
| Live Wi-Fi monitor | `tshark` live capture | Live packet windows | Works on `en0`, writes CSV predictions, supports Windows/macOS. | Needs local baseline to avoid false positives. | Current outside-test tool. |

## Final Files To Use

| Purpose | File |
|---|---|
| Edge training/testing code | `experment/edge_iiot_experiment.py` |
| Edge trained model | `testoutside/edge_iiot_xgb_model.joblib` |
| Live Wi-Fi monitor | `testoutside/live_wifi_edge_ids.py` |
| Live baseline thresholds | `testoutside/live_wifi_baseline.json` |
| Live usage guide | `testoutside/README.md` |
| Local PCAP prediction summary | `experment/edge_iiot_attack_predictions_summary.csv` |

## Current Model Rules

| Rule | Value |
|---|---:|
| Per-record attack threshold | `0.5` |
| Window max probability threshold | `0.5` |
| Original file/window attack-ratio threshold | `0.4` |
| Calibrated live attack-ratio threshold | `0.820186` |
| Minimum records before alert | `50` |

## Model Accuracy

Last Edge-IIoT holdout test:

| Metric | Value |
|---|---:|
| Rows after duplicate removal | `156,986` |
| Features used | `32` |
| Holdout test rows | `31,398` |
| Accuracy | `0.9474` |
| ROC-AUC | `0.9926` |
| PR-AUC | `0.9985` |
| Attack precision | `0.9896` |
| Attack recall | `0.9478` |
| True negatives | `4,596` |
| False positives | `264` |
| False negatives | `1,386` |
| True positives | `25,152` |

## Last Training And Testing Speed

Measured on the last full Edge training run on 2026-04-20:

| Runtime Item | Value |
|---|---:|
| Total train command | `45.409s` |
| Preprocessing / CSV typing | `40.675s` |
| Threshold model fit | `1.442s` |
| Evaluation model fit | `1.462s` |
| Final model fit | `1.638s` |
| Holdout prediction time | `0.028s` |
| Holdout prediction speed | `1,141,166 rows/s` |

## Local PCAP Result

| Group | Result |
|---|---|
| `BENIGN_BASELINE`, `noAttack*` | Benign |
| NMAP scans | Attack |
| HTTP flood | Attack |
| UDP flood | Attack |
| SSH brute force | Attack |
| Captured attack windows | Attack |

## Cleanup

Removed generated/cache artifacts:

| Removed | Reason |
|---|---|
| `__pycache__/`, `.DS_Store` | Cache/system files |
| Duplicate per-flow prediction CSVs | Large and reproducible |
| `experment/extracted-attack-edge-csvs/` | Reproducible from PCAPs |
| Old CIC extracted CSV outputs | Not used by final method |
| Smoke-test output folders owned by user | Temporary validation files |

Kept important inputs/artifacts:

| Kept | Reason |
|---|---|
| `attack/` | Original local PCAP test set |
| `experment/ML-EdgeIIoT-dataset.csv` | Training dataset |
| `testoutside/edge_iiot_xgb_model.joblib` | Final model for live use |
| `testoutside/live_wifi_baseline.json` | Calibrated normal-network threshold |

Remaining root-owned generated folders need sudo to remove:

```bash
sudo rm -rf live-monitor-output testoutside/live-output
```

## Commands

Run calibrated live monitor on macOS:

```bash
sudo python testoutside/live_wifi_edge_ids.py --interface en0 --tshark /Applications/Wireshark.app/Contents/MacOS/tshark --window_seconds 30 --pause_seconds 5
```

Recalibrate on normal traffic:

```bash
sudo python testoutside/live_wifi_edge_ids.py --interface en0 --tshark /Applications/Wireshark.app/Contents/MacOS/tshark --window_seconds 30 --pause_seconds 5 --calibrate_windows 20 --no_packet_csv
```
