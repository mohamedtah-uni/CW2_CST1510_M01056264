import streamlit as st
from Assistant import Assistant

def authenticate():
    if not st.session_state.get("logged_in", False):
        st.switch_page("Home.py")

authenticate()

st.title("A.I Assistant")


domain = st.selectbox("Domain", ["Cyber Security", "I.T Ops", "Data Science"])

prompt = st.text_input("Prompt the A.I Asistant", placeholder="Prompt...")



if st.button("send"):
    assistant = Assistant(domain)
    response = assistant.prompt(prompt)

    st.write(response)