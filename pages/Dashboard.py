import streamlit as st


def authenticate():
    if not st.session_state.get("logged_in", False):
        st.switch_page("Home.py")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

authenticate()

st.title("Dashboard")

# navigate to role based dashboard
# or render dashboard according to user's role