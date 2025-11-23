import streamlit as st
st.title("Hello, S")


st.set_page_config()
st.text_input("login")

if st.button("Analytics"):
    st.switch_page("pages/Analytics")
