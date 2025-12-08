
import streamlit as st

def authenticate():
    if not st.session_state.get("logged_in", False):
        st.switch_page("Home.py")

authenticate()

st.title("Analytics Page")