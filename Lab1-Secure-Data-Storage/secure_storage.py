
import json
import hashlib
import hmac
import os
from pathlib import Path
from cryptography.fernet import Fernet

FILE_NAME = Path("users.json")
KEY_FILE = Path("secret.key")
HMAC_FILE = Path("hmac.key")


def load_or_create_key(path, generator):
    if path.exists():
        return path.read_bytes()

    key = generator()
    path.write_bytes(key)
    return key


encryption_key = load_or_create_key(
    KEY_FILE, Fernet.generate_key
)
cipher = Fernet(encryption_key)

hmac_key = load_or_create_key(
    HMAC_FILE, lambda: os.urandom(32)
)


def calculate_hash(record):
    data = {
        "id": record["id"],
        "username": record["username"],
        "encrypted_email": record["encrypted_email"]
    }

    message = json.dumps(
        data, sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    return hmac.new(
        hmac_key, message, hashlib.sha256
    ).hexdigest()


def save_users(users):
    with open(FILE_NAME, "w", encoding="utf-8") as file:
        json.dump(users, file, indent=4)


def prepare_existing_records():
    with open(FILE_NAME, "r", encoding="utf-8") as file:
        users = json.load(file)

    for user in users:
        if "email" in user:
            encrypted = cipher.encrypt(
                user.pop("email").encode("utf-8")
            )
            user["encrypted_email"] = encrypted.decode("utf-8")

        user["hash"] = calculate_hash(user)

    save_users(users)
    print("All records encrypted and hashed successfully.")


def verify_users():
    with open(FILE_NAME, "r", encoding="utf-8") as file:
        users = json.load(file)

    for user in users:
        expected = calculate_hash(user)
        stored = user.get("hash", "")

        if hmac.compare_digest(expected, stored):
            print(f"User {user['id']}: Integrity verified")
        else:
            print(f"User {user['id']}: Integrity FAILED")


prepare_existing_records()
verify_users()
