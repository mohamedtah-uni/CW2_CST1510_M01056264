import streamlit as st
import pandas as pd

if not st.session_state.get("logged_in"):
    st.switch_page("Home.py")

st.title("IT Operations Tickets Dashboard")

try:
    df = pd.read_csv("DATA/it_tickets.csv")
except Exception as e:
    st.warning("No data found. Using demo data.")
    df = pd.DataFrame([
        {"ID": 1, "Subject": "Server Down", "Status": "Open", "Priority": "Critical", "Opened_At": "2025-11-12"},
        {"ID": 2, "Subject": "Printer Issue", "Status": "Resolved", "Priority": "Low", "Opened_At": "2025-10-29"},
    ])

st.write("## Current Tickets")
st.dataframe(df)

st.metric("Total Tickets", len(df))
open_tickets = df[df["Status"]=="Open"].shape[0]
resolved_tickets = df[df["Status"]=="Resolved"].shape[0]
critical_tickets = df[df["Priority"]=="Critical"].shape[0]
st.metric("Open", open_tickets)
st.metric("Resolved", resolved_tickets)
st.metric("Critical", critical_tickets)

chart_df = df["Priority"].value_counts().rename_axis('Priority').reset_index(name='Count')
st.write("## Tickets by Priority")
st.bar_chart(chart_df.set_index("Priority"))