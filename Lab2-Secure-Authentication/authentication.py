
import json
import bcrypt
import logging
import secrets
import time
import uuid
import jwt

from pathlib import Path
from getpass import getpass
from datetime import datetime, timedelta, timezone

# File locations
BASE_DIR = Path(__file__).parent
USER_FILE = BASE_DIR / "users.json"
LOG_FILE = BASE_DIR / "login_attempts.log"
OTP_FILE = BASE_DIR / "otp_store.txt"
TOKEN_FILE = BASE_DIR / "tokens.txt"
JWT_KEY_FILE = BASE_DIR / "jwt_secret.key"

# Security settings
MAX_FAILED_ATTEMPTS = 5
MAX_OTP_ATTEMPTS = 3
OTP_EXPIRATION = 60
TOKEN_EXPIRATION = 120

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)


def log_login(username, result):
    logging.info(
        "Username=%s | Result=%s",
        username,
        result
    )


# Load and save users
def load_users():
    if USER_FILE.exists():
        with open(USER_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    return {}


def save_users(users):
    with open(USER_FILE, "w", encoding="utf-8") as file:
        json.dump(users, file, indent=4)


# Task 1: Password registration
def register_user():
    users = load_users()
    username = input("Enter username: ").strip()

    if not username:
        print("Username cannot be empty.")
        return

    if username in users:
        print("Username already exists.")
        return

    password = getpass("Enter password: ")
    confirm = getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    if len(password) < 12:
        print("Password must contain at least 12 characters.")
        return

    if len(password.encode("utf-8")) > 72:
        print("Password exceeds bcrypt's 72-byte limit.")
        return

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    users[username] = {
        "password_hash": password_hash,
        "failed_attempts": 0,
        "locked": False
    }

    save_users(users)
    print("User registered successfully.")


# Task 2: OTP generation
def generate_otp(username):
    otp = f"{secrets.randbelow(1000000):06d}"

    record = {
        "username": username,
        "otp": otp,
        "expires_at": time.time() + OTP_EXPIRATION,
        "attempts": 0
    }

    with open(OTP_FILE, "w", encoding="utf-8") as file:
        json.dump(record, file, indent=4)

    print("OTP generated successfully.")
    print("OTP expires in 60 seconds.")
    print("Lab demonstration OTP:", otp)


# Task 2: OTP verification
def verify_otp(username):
    if not OTP_FILE.exists():
        print("No OTP found.")
        return False

    with open(OTP_FILE, "r", encoding="utf-8") as file:
        record = json.load(file)

    if record["username"] != username:
        print("OTP belongs to another user.")
        return False

    if time.time() >= record["expires_at"]:
        OTP_FILE.unlink(missing_ok=True)
        print("OTP expired and removed.")
        return False

    if record["attempts"] >= MAX_OTP_ATTEMPTS:
        OTP_FILE.unlink(missing_ok=True)
        print("OTP attempt limit reached.")
        return False

    entered = input("Enter your six-digit OTP: ").strip()

    if time.time() >= record["expires_at"]:
        OTP_FILE.unlink(missing_ok=True)
        print("OTP expired and removed.")
        return False

    if secrets.compare_digest(entered, record["otp"]):
        OTP_FILE.unlink(missing_ok=True)
        print("OTP verification successful.")
        print("OTP invalidated after use.")
        return True

    record["attempts"] += 1

    if record["attempts"] >= MAX_OTP_ATTEMPTS:
        OTP_FILE.unlink(missing_ok=True)
        print("OTP rejected after 3 incorrect attempts.")
    else:
        with open(OTP_FILE, "w", encoding="utf-8") as file:
            json.dump(record, file, indent=4)

        print("Invalid OTP.")
        print("Failed OTP attempts:", record["attempts"])

    return False


# Task 3: JWT signing key
def load_jwt_secret():
    if JWT_KEY_FILE.exists():
        return JWT_KEY_FILE.read_text(encoding="utf-8")

    secret = secrets.token_hex(32)
    JWT_KEY_FILE.write_text(secret, encoding="utf-8")
    return secret


JWT_SECRET = load_jwt_secret()


# Load token records
def load_tokens():
    if not TOKEN_FILE.exists():
        return []

    records = []

    with open(TOKEN_FILE, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                records.append(json.loads(line))

    return records


def save_tokens(records):
    with open(TOKEN_FILE, "w", encoding="utf-8") as file:
        for record in records:
            file.write(json.dumps(record) + "\n")


# Task 3: JWT generation
def generate_token(username):
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=TOKEN_EXPIRATION)

    payload = {
        "sub": username,
        "iat": now,
        "exp": expires,
        "jti": str(uuid.uuid4())
    }

    token = jwt.encode(
        payload,
        JWT_SECRET,
        algorithm="HS256"
    )

    record = {
        "username": username,
        "token": token,
        "jti": payload["jti"],
        "expires_at": expires.isoformat(),
        "revoked": False
    }

    with open(TOKEN_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\n")

    print("JWT generated successfully.")
    print("Token expires in 120 seconds.")
    print("Lab demonstration token:", token)

    return token


# Task 3: Token validation
def validate_token(token):
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            options={"require": ["sub", "exp", "iat", "jti"]}
        )

    except jwt.ExpiredSignatureError:
        print("Token expired. Access denied.")
        return None

    except jwt.InvalidTokenError:
        print("Invalid token. Access denied.")
        return None

    records = load_tokens()

    for record in records:
        if (
            secrets.compare_digest(record["token"], token)
            and record["jti"] == payload["jti"]
        ):
            if record["revoked"]:
                print("Token revoked. Access denied.")
                return None

            users = load_users()

            if (
                payload["sub"] not in users
                or users[payload["sub"]].get("locked", False)
            ):
                print("User account unavailable. Access denied.")
                return None

            print("Token validation successful.")
            return payload

    print("Token not found in active token records.")
    return None


# Task 3: Token revocation
def revoke_token(token):
    records = load_tokens()

    for record in records:
        if secrets.compare_digest(record["token"], token):
            if record["revoked"]:
                print("Token already revoked.")
                return

            record["revoked"] = True
            save_tokens(records)

            print("Token revoked successfully.")
            return

    print("Token not found.")


# Task 3: Protected resource
def protected_resource(token):
    payload = validate_token(token)

    if payload is None:
        print("Protected resource access denied.")
        return

    print("Protected resource access granted.")
    print("Authenticated user:", payload["sub"])
    print("Confidential lab resource accessed.")


# Tasks 1, 2 and 3: Login process
def login_user():
    users = load_users()
    username = input("Enter username: ").strip()

    if username not in users:
        log_login(username, "UNKNOWN_USER")
        print("Invalid username or password.")
        return

    if users[username].get("locked", False):
        log_login(username, "ACCOUNT_LOCKED")
        print("Account is locked. Access denied.")
        return

    password = getpass("Enter password: ")

    stored_hash = users[username]["password_hash"]

    try:
        password_valid = bcrypt.checkpw(
            password.encode("utf-8"),
            stored_hash.encode("utf-8")
        )
    except ValueError:
        password_valid = False

    if not password_valid:
        users[username]["failed_attempts"] += 1

        if users[username]["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            users[username]["locked"] = True
            log_login(username, "ACCOUNT_LOCKED_AFTER_FAILURES")
            print("Account locked after 5 failed attempts.")
        else:
            log_login(username, "INVALID_PASSWORD")
            print("Invalid username or password.")
            print(
                "Failed login attempts:",
                users[username]["failed_attempts"]
            )

        save_users(users)
        return

    users[username]["failed_attempts"] = 0
    save_users(users)

    log_login(username, "PASSWORD_VERIFIED")
    print("Password verification successful.")

    generate_otp(username)

    otp_verified = False

    for attempt in range(MAX_OTP_ATTEMPTS):
        if verify_otp(username):
            otp_verified = True
            break

        if not OTP_FILE.exists():
            break

    if otp_verified:
        log_login(username, "MFA_SUCCESS")
        print("Multi-factor authentication successful.")
        generate_token(username)
    else:
        log_login(username, "MFA_FAILED")
        print("Multi-factor authentication failed.")


# Main menu
def main():
    while True:
        print("\n=== Secure Authentication System ===")
        print("1. Register user")
        print("2. Login with password and OTP")
        print("3. Validate JWT")
        print("4. Access protected resource")
        print("5. Revoke JWT")
        print("6. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            register_user()

        elif choice == "2":
            login_user()

        elif choice == "3":
            token = input("Enter JWT: ").strip()
            validate_token(token)

        elif choice == "4":
            token = input("Enter JWT: ").strip()
            protected_resource(token)

        elif choice == "5":
            token = input("Enter JWT to revoke: ").strip()
            revoke_token(token)

        elif choice == "6":
            print("Exiting authentication system.")
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
