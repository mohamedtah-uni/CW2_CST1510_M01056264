import streamlit as st
from app.services.user_service import login_user, get_user_by_username
from app.DatabaseManager import DatabaseManager



st.set_page_config(
    page_title="Dashboard",
    layout="wide"
)




if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.role = ""



db = DatabaseManager()


st.write("# Authenticate")
if not st.session_state.logged_in:
    with st.expander("Login"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            
            auth_res = login_user(username, password)

            if auth_res[0]:

                user = db.get_user(username)
                
                st.session_state.logged_in = True
                st.session_state.username = user.username
                st.session_state.role = user.role
                st.success("Logged in!")
                
                if user.role=="analyst":
                    st.switch_page("pages/Incidents_Dashboard.py")

                elif user.role=="it":
                    st.switch_page("pages/Tickets_Dashboard.py")


                elif user.role=="user":
                    st.switch_page("pages/Datasets_Dashboard.py")


            else:
                st.error(auth_res[1])



    with st.expander("Signup"):
        roles = ["user", "analyst", "it"]
        username = st.text_input("New Username")
        password = st.text_input("New Password", type="password")
        role = st.selectbox("Role", roles)


        if st.button("Signup"):
            auth_res = db.signup_user(username, password, role)


            if auth_res[0]:

                user = db.get_user(username)
                
                st.session_state.logged_in = True
                st.session_state.username = user.username
                st.session_state.role = user.role
                st.success("Signed up!")

                if user.role=="analyst":
                    st.switch_page("pages/Incidents_Dashboard.py")

                elif user.role=="it":
                    st.switch_page("pages/Tickets_Dashboard.py")


                elif user.role=="user":
                    st.switch_page("pages/Datasets_Dashboard.py")


            else:
                st.error(auth_res[1])







else:
    st.button("Logout", on_click=lambda: st.session_state.update({"logged_in": False, "username": "", "role": ""}))
    st.write(f"Welcome {st.session_state.username}, Role: {st.session_state.role}")