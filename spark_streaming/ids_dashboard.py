from __future__ import annotations

from datetime import datetime

import pandas as pd
import streamlit as st
from pymongo import MongoClient


st.set_page_config(page_title="Edge-IIoT IDS Dashboard", layout="wide")


def refresh_meta(seconds: int) -> None:
    st.markdown(f'<meta http-equiv="refresh" content="{seconds}">', unsafe_allow_html=True)


def mongo_client(uri: str) -> MongoClient:
    return MongoClient(uri, serverSelectionTimeoutMS=3000)


def fetch_collection(
    client: MongoClient,
    db_name: str,
    collection_name: str,
    limit: int = 50,
    sort_field: str = "created_at",
) -> pd.DataFrame:
    cursor = client[db_name][collection_name].find({}, {"_id": 0}).sort(sort_field, -1).limit(limit)
    rows = list(cursor)
    if not rows:
        return pd.DataFrame()
    return pd.json_normalize(rows)


def show_metrics(windows_df: pd.DataFrame, predictions_df: pd.DataFrame, alerts_df: pd.DataFrame) -> None:
    total_windows = int(len(windows_df))
    total_predictions = int(len(predictions_df))
    total_alerts = int(len(alerts_df))
    latest_ratio = (
        float(predictions_df.iloc[0]["attack_record_ratio"])
        if not predictions_df.empty and "attack_record_ratio" in predictions_df.columns
        else 0.0
    )
    latest_prob = (
        float(predictions_df.iloc[0]["max_attack_probability"])
        if not predictions_df.empty and "max_attack_probability" in predictions_df.columns
        else 0.0
    )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Windows", f"{total_windows:,}")
    col2.metric("Predictions", f"{total_predictions:,}")
    col3.metric("Alerts", f"{total_alerts:,}")
    col4.metric("Latest max prob", f"{latest_prob:.3f}")

    st.caption(
        f"Latest attack ratio: {latest_ratio:.3f} | "
        f"Refreshed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )


def chart_predictions(predictions_df: pd.DataFrame) -> None:
    if predictions_df.empty:
        st.info("No prediction data yet.")
        return

    chart_df = predictions_df.copy()
    if "window_end" in chart_df.columns:
        chart_df["window_end"] = pd.to_datetime(chart_df["window_end"], errors="coerce")
        chart_df = chart_df.sort_values("window_end")
        chart_df = chart_df.dropna(subset=["window_end"])

    if chart_df.empty:
        st.info("Prediction timestamps are not available yet.")
        return

    cols = [col for col in ["attack_record_ratio", "max_attack_probability"] if col in chart_df.columns]
    if not cols:
        st.info("Prediction score columns are not available yet.")
        return

    chart_df = chart_df.set_index("window_end")[cols]
    st.line_chart(chart_df)


def main() -> None:
    st.title("Edge-IIoT Live IDS")
    st.write("Spark Structured Streaming -> MongoDB -> live dashboard")

    with st.sidebar:
        st.header("Connection")
        mongo_uri = st.text_input("Mongo URI", value="mongodb://localhost:27017")
        db_name = st.text_input("Database", value="edgeids")
        windows_coll = st.text_input("Windows collection", value="windows")
        predictions_coll = st.text_input("Predictions collection", value="predictions")
        alerts_coll = st.text_input("Alerts collection", value="alerts")
        limit = st.number_input("Rows to load", min_value=10, max_value=1000, value=200, step=10)
        refresh_seconds = st.number_input("Auto refresh seconds", min_value=3, max_value=120, value=10, step=1)
        refresh_meta(int(refresh_seconds))

    try:
        client = mongo_client(mongo_uri)
        client.admin.command("ping")
    except Exception as exc:
        st.error(f"Could not connect to MongoDB: {exc}")
        return

    windows_df = fetch_collection(client, db_name, windows_coll, int(limit), sort_field="ingested_at")
    predictions_df = fetch_collection(client, db_name, predictions_coll, int(limit), sort_field="created_at")
    alerts_df = fetch_collection(client, db_name, alerts_coll, int(limit), sort_field="created_at")

    show_metrics(windows_df, predictions_df, alerts_df)

    left, right = st.columns(2)
    with left:
        st.subheader("Recent alerts")
        if alerts_df.empty:
            st.info("No alerts yet.")
        else:
            st.dataframe(alerts_df, use_container_width=True, hide_index=True)

    with right:
        st.subheader("Recent predictions")
        if predictions_df.empty:
            st.info("No predictions yet.")
        else:
            st.dataframe(predictions_df, use_container_width=True, hide_index=True)

    st.subheader("Prediction trend")
    chart_predictions(predictions_df)

    st.subheader("Raw windows")
    if windows_df.empty:
        st.info("No captured windows yet.")
    else:
        st.dataframe(windows_df, use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()
