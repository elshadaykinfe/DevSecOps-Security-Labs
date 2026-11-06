
import json
import hashlib
import hmac
from pathlib import Path

HMAC_KEY = Path("hmac.key").read_bytes()


def calculate_hash(record):
    data = {
        "id": record["id"],
        "username": record["username"],
        "encrypted_email": record["encrypted_email"]
    }

    message = json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    return hmac.new(
        HMAC_KEY,
        message,
        hashlib.sha256
    ).hexdigest()


def verify_file(filename):
    with open(filename, "r", encoding="utf-8") as file:
        users = json.load(file)

    for user in users:
        expected = calculate_hash(user)
        stored = user.get("hash", "")

        if hmac.compare_digest(expected, stored):
            print(f"User {user['id']}: Integrity verified")
        else:
            print(f"User {user['id']}: TAMPERING DETECTED")


verify_file("users_tampered.json")
