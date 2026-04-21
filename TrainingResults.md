Training data:
Rows                  : 156,986
Features used          : 32
Numeric features       : 32
Categorical features   : 0
Dropped ID/payload cols : 15
Dropped empty cols      : 0
Dropped constant cols   : 14
Class distribution:
Attack_label
normal     24301
attack    132685

Threshold selection:
Strategy           : fixed
Selected threshold : 0.500000000

=== EDGE-IIOT HOLDOUT TEST ===
Threshold : 0.500000000
Accuracy  : 0.9472
ROC-AUC   : 0.9926
PR-AUC    : 0.9985
              precision    recall  f1-score   support

      Normal       0.77      0.95      0.85      4860
      Attack       0.99      0.95      0.97     26538

    accuracy                           0.95     31398
   macro avg       0.88      0.95      0.91     31398
weighted avg       0.96      0.95      0.95     31398

Confusion matrix [ [TN, FP], [FN, TP] ]
[[ 4600   260]
 [ 1398 25140]]

Top feature importances:
                    feature  importance
              num__mqtt.len    0.242288
num__mqtt.conflag.cleansess    0.173165
             num__tcp.flags    0.117073
         num__mqtt.conflags    0.083966
               num__tcp.seq    0.066995
         num__mqtt.hdrflags    0.060569
               num__tcp.ack    0.057286
               num__tcp.len    0.044894
          num__mqtt.msgtype    0.038050
    num__tcp.connection.rst    0.037907
    num__tcp.connection.syn    0.021654
    num__dns.retransmission    0.012090
            num__udp.stream    0.005694
           num__icmp.seq_le    0.005616
 num__tcp.connection.synack    0.005603
         num__icmp.checksum    0.004709
        num__udp.time_delta    0.003337
    num__tcp.connection.fin    0.003247
   num__http.content_length    0.003108
           num__tcp.ack_raw    0.002878
            num__dns.qry.qu    0.002479
         num__tcp.flags.ack    0.001919
            num__arp.opcode    0.001248
           num__arp.hw.size    0.001074

Runtime:
Threshold model fit : 1.813s
Eval model fit      : 2.146s
Final model fit     : 2.916s
Holdout prediction : 0.057s (547863 rows/s)

Saved model bundle: experment\edge_iiot_xgb_model.joblib
Saved feature importance: experment\edge_iiot_xgb_model.feature_importance.csv
Saved metadata: experment\edge_iiot_xgb_model.metadata.json
Total train command: 104.106s