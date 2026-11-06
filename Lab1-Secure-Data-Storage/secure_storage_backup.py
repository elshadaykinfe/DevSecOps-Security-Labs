
import json
from pathlib import Path

FILE_NAME = Path("users.json")


def add_user():
    username = input("Enter username: ").strip()
    email = input("Enter email: ").strip()

    if not username or not email:
        print("Username and email cannot be empty.")
        return

    if FILE_NAME.exists():
        with open(FILE_NAME, "r", encoding="utf-8") as file:
            users = json.load(file)
    else:
        users = []

    new_user = {
        "id": max((user["id"] for user in users), default=0) + 1,
        "username": username,
        "email": email
    }

    users.append(new_user)

    with open(FILE_NAME, "w", encoding="utf-8") as file:
        json.dump(users, file, indent=4)

    print("User data stored successfully.")


add_user()
