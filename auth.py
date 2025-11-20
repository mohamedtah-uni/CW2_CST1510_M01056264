import bcrypt
import os
import time
import secrets
from datetime import datetime


USER_DATA_FILE = "users.txt"


if not os.path.exists(USER_DATA_FILE):
    with open(USER_DATA_FILE, "w") as f:
        f.write("")


def hash_password(plain_text_password: str) -> str:  # returns password hash (str format)
    # TODO: Encode the password to bytes (bcrypt requires byte strings)
    password = plain_text_password.encode()

    # TODO: Generate a salt using bcrypt.gensalt()
    salt = bcrypt.gensalt()

    # TODO: Hash the password using bcrypt.hashpw()
    hashed = bcrypt.hashpw(password, salt)

    # TODO: Decode the hash back to a string to store in a text file
    return hashed.decode()


def verify_password(plain_text_password: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain_text_password.encode(), hashed.encode())


def user_exists(username: str) -> bool:

    with open(USER_DATA_FILE, "r") as f:
        records = f.read().split("\n")

        for record in records:
            # username and hashed passwd are coma seperated so use split(,) to get the username at 0 and hash at 1
            record = record.split(",")
            if username == record[0]:
                return True

    return False


def register_user(username: str, password: str, role="user"):
    if user_exists(username):
        print(f"[-] User with this username already exists!")
        exit(1)

    hashed = hash_password(password)

    with open(USER_DATA_FILE, "a") as f:
        f.write(f"{username},{hashed},{role}\n")

    return True


def login_user(username: str, password: str):
    if not user_exists(username):
        raise ValueError(
            f"[-] No user found with the given username: {username}")

    with open(USER_DATA_FILE, "r") as f:
        records = f.read().split("\n")

        for record in records:
            record = record.split(",")
            uname, passwd = record[0], record[1]

            if username == uname:
                if verify_password(password, passwd):
                    return True

                else:
                    return False


def validate_username(username: str):

    # main rule is min_len = 4 and max length is 12

    allowed_special = ["_", "."]

    if len(username) < 4 or len(username) > 12:
        return ("Username must be between 4 and 12 characters of length!", False)

    for i in username:

        if i.isalpha():
            continue

        # if its numeric and its the first char
        elif i.isnumeric() and username.index(i) == 0:
            return ("Username can't start with a number!", False)

        elif i.isprintable() and i not in allowed_special:
            return ("Username can only have _ and . no other special characters allowed!", False)

    return (None, True)


def validate_password(password: str):
    if len(password) < 8:
        return ("Password must be longer than or equal to 8 characters of length.", False)

    # if the passwd has no numbers or special chars
    elif password.isalpha():
        return ("Password must have a number or a special character.", False)

    return (None, True)


def display_menu():
    """Displays the main menu options."""
    print("\n" + "="*50)
    print(" MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print(" Secure Authentication System")
    print("="*50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-"*50)


def create_session(username):

    token = secrets.token_hex(16)

    timestamp = datetime.now().timestamp()

    with open("sessions.txt", "a") as f:
        f.write(f"{username}:{token}:{timestamp}\n")

    return token


def main():
    """Main program loop."""
    print("\nWelcome to the Week 7 Authentication System!")

    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == '1':
            # Registration flow
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()

            # Validate username
            error_msg, is_valid = validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            password = input("Enter a password: ").strip()

            # Validate password
            error_msg, is_valid = validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            # Confirm password
            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("Error: Passwords do not match.")
                continue

            # Register the user
            register_user(username, password)

        elif choice == '2':
            # Login flow

            attempts = 0

            if os.path.exists("attempts.txt"):
                with open("attempts.txt", "r") as f:
                    attempts = len(f.readlines())

            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()

            if attempts >= 3:
                print("Lockout for 5 minutes")

                # sleep for 5 minutes
                time.sleep(300)

                os.remove("attempts.txt")  # remove attempts.txt file

                continue

            # Attempt login
            if login_user(username, password):
                print("\nYou are now logged in.")

                # Optional: Ask if they want to logout or exit
                input("\nPress Enter to return to main menu...")

                # remove attempts.txt file if the login is successful
                os.remove("attempts.txt")

            else:
                with open("attempts.txt", "a") as f:
                    f.write("Failed Attempt!\n")

        elif choice == '3':
            # Exit
            print("\nThank you for using the authentication system.")
            print("Exiting...")
            break

        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()
