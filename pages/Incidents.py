import streamlit as st
import pandas as pd

if not st.session_state.get("logged_in"):
    st.switch_page("Home.py")

st.title("Cybersecurity Incidents Dashboard")

try:
    df = pd.read_csv("DATA/cyber_incidents.csv")
except Exception as e:
    st.warning("No data found. Using demo data.")
    df = pd.DataFrame([
        {"ID": 1, "Type": "Phishing", "Status": "Open", "Severity": "High", "Reported_At": "2025-11-01"},
        {"ID": 2, "Type": "Malware", "Status": "Closed", "Severity": "Medium", "Reported_At": "2025-10-21"},
    ])

st.write("## Current Incidents")
st.dataframe(df)

total = len(df)
open_count = df[df["Status"]=="Open"].shape[0]
closed_count = df[df["Status"]=="Closed"].shape[0]
st.metric(label="Total Incidents", value=total)
st.metric(label="Open Incidents", value=open_count, delta=open_count - closed_count)
st.metric(label="Closed Incidents", value=closed_count)

chart_df = df["Type"].value_counts().rename_axis('Incident Type').reset_index(name='Count')
st.write("## Incidents by Type")
st.bar_chart(chart_df.set_index("Incident Type"))