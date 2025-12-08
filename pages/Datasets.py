import streamlit as st
import pandas as pd

if not st.session_state.get("logged_in"):
    st.switch_page("Home.py")


if st.session_state.get("role") != "analyst":
    pass

st.title("Data Science Datasets Dashboard")

try:
    df = pd.read_csv("DATA/datasets_metadata.csv")
except Exception as e:
    df = pd.DataFrame([
        {"ID": 1, "Name": "Sales Q1", "Records": 1200, "Status": "Active", "Created_At": "2025-04-01"},
        {"ID": 2, "Name": "Customer Survey", "Records": 340, "Status": "Archived", "Created_At": "2025-05-19"},
    ])

st.write("## Current Datasets")
st.dataframe(df)

active_count = df[df["Status"]=="Active"]["Records"].sum()
archived_count = df[df["Status"]=="Archived"]["Records"].sum()
total_count = df["Records"].sum()
st.metric("Active data", active_count)
st.metric("Archived data", archived_count)
st.metric("Total records", total_count)

st.write("## Records per Dataset")
st.bar_chart(df.set_index("Name")["Records"])