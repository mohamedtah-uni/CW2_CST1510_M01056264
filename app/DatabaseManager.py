from .data.db import connect_database
from .services.user_service import login_user, register_user
from .data.users import get_user_by_username


class User:
    def __init__(self, data: tuple = None):
        if data==None or len(data) != 4:
            # if there's no user data we'll return an anonymous user
            self.id = None
            self.username = "Anonymous"
            self.hashed_password = ""
            self.role = "guest" # anonymous user has the role guest

        else:
            self.id = data[0]
            self.username = data[1]
            self.hashed_password = data[2]
            self.role = data[3]




class DatabaseManager:
    def __init__(self):
        self.db = connect_database()


    def verify_user(self, username, password):
        return login_user(username, password)


    def get_user(self, username: str) -> User:
        user = get_user_by_username(username)
        return User(data=user)



    def signup_user(self, username, password, role="user"):
        return register_user(username, password, role="user")

