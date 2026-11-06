
import hashlib
import hmac
import secrets
from getpass import getpass

# Role hierarchy
ROLE_LEVELS = {
    "Guest": 1,
    "Nurse": 2,
    "Doctor": 3,
    "Admin": 4
}

# Permissions inherited through the hierarchy
ROLE_PERMISSIONS = {
    "Guest": {"view_public"},
    "Nurse": {"view_public", "view_patient"},
    "Doctor": {
        "view_public",
        "view_patient",
        "update_patient"
    },
    "Admin": {
        "view_public",
        "view_patient",
        "update_patient",
        "manage_users",
        "manage_files"
    }
}

# Demo users
# Passwords are hashed, not stored in plaintext
users = {}


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200000
    )


def add_user(username, password, role):
    salt = secrets.token_bytes(16)

    users[username] = {
        "salt": salt,
        "password_hash": hash_password(password, salt),
        "role": role,
        "failed_attempts": 0,
        "locked": False
    }


def setup_users():
    print("Set passwords for four demonstration accounts.")

    for username, role in [
        ("admin1", "Admin"),
        ("doctor1", "Doctor"),
        ("nurse1", "Nurse"),
        ("guest1", "Guest")
    ]:
        password = getpass(
            f"Create password for {username} ({role}): "
        )
        add_user(username, password, role)

    print("Four demonstration users created.")


def authenticate():
    username = input("Username: ").strip()
    password = getpass("Password: ")

    user = users.get(username)

    if user is None:
        print("Authentication failed.")
        return None

    if user["locked"]:
        print("Account locked.")
        return None

    candidate = hash_password(password, user["salt"])

    if not hmac.compare_digest(
        candidate,
        user["password_hash"]
    ):
        user["failed_attempts"] += 1

        if user["failed_attempts"] >= 3:
            user["locked"] = True
            print("Account locked after 3 failed attempts.")
        else:
            print("Authentication failed.")

        return None

    user["failed_attempts"] = 0
    print("Authentication successful.")
    return username


def show_permissions(username):
    role = users[username]["role"]

    print("\nUser:", username)
    print("Role:", role)
    print("Hierarchy level:", ROLE_LEVELS[role])
    print("Permissions:")

    for permission in sorted(ROLE_PERMISSIONS[role]):
        print(" -", permission)


def check_permission(username, permission):
    role = users[username]["role"]
    allowed = permission in ROLE_PERMISSIONS[role]

    if allowed:
        print("ACCESS GRANTED:", permission)
    else:
        print("ACCESS DENIED:", permission)

    return allowed


def main():
    setup_users()

    while True:
        print("\n=== Secure File System Simulator ===")
        print("1. Login and view role permissions")
        print("2. Display role hierarchy")
        print("3. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            username = authenticate()

            if username:
                show_permissions(username)

                check_permission(
                    username,
                    "view_patient"
                )
                check_permission(
                    username,
                    "manage_files"
                )

        elif choice == "2":
            print("\nRole hierarchy:")
            for role, level in sorted(
                ROLE_LEVELS.items(),
                key=lambda item: item[1],
                reverse=True
            ):
                print(f"{role}: Level {level}")

        elif choice == "3":
            print("Exiting simulator.")
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
