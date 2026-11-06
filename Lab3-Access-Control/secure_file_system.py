
import hashlib
import hmac
import json
import secrets
from datetime import datetime
from getpass import getpass
from pathlib import Path


# ============================================================
# LAB 3 - ACCESS CONTROL AND SECURE FILE OPERATIONS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "patient_data"
DATA_DIR.mkdir(exist_ok=True)

AUDIT_LOG = BASE_DIR / "audit.log"
INTEGRITY_FILE = BASE_DIR / "integrity_metadata.json"

ROLE_LEVELS = {
    "Guest": 1,
    "Nurse": 2,
    "Doctor": 3,
    "Admin": 4
}

ROLE_PERMISSIONS = {
    "Guest": {
        "view_public"
    },
    "Nurse": {
        "view_public",
        "view_patient"
    },
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

users = {}

file_metadata = {
    "patient_record.txt": {
        "owner": "doctor1",
        "owner_permissions": "rw-",
        "other_permissions": "r--"
    },
    "public_notice.txt": {
        "owner": "admin1",
        "owner_permissions": "rwx",
        "other_permissions": "r--"
    }
}


# ============================================================
# SECTION 4.1 - RBAC AND AUTHENTICATION
# ============================================================

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
    print("\nSet passwords for four demonstration accounts.")

    accounts = [
        ("admin1", "Admin"),
        ("doctor1", "Doctor"),
        ("nurse1", "Nurse"),
        ("guest1", "Guest")
    ]

    for username, role in accounts:
        while True:
            password = getpass(
                f"Create password for {username} ({role}): "
            )

            if password:
                add_user(username, password, role)
                break

            print("Password cannot be empty.")

    print("\nFour demonstration users created.")


def audit_activity(username, action, filename, result):
    timestamp = datetime.now().isoformat(timespec="seconds")

    message = (
        f"{timestamp} | User: {username} | "
        f"Action: {action} | File: {filename} | "
        f"Result: {result}"
    )

    with open(AUDIT_LOG, "a", encoding="utf-8") as log:
        log.write(message + "\n")

    print("AUDIT:", message)


def register_security_failure(username, action, filename, reason):
    print("SECURITY ALERT:", reason)

    audit_activity(
        username,
        action,
        filename,
        "FAILURE"
    )

    user = users.get(username)

    if user is not None and not user["locked"]:
        user["failed_attempts"] += 1

        print(
            "Security failure count:",
            user["failed_attempts"]
        )

        if user["failed_attempts"] >= 3:
            user["locked"] = True

            print(
                "SECURITY ALERT: Account locked "
                "after 3 failed attempts"
            )

            audit_activity(
                username,
                "account_lockout",
                filename,
                "SUCCESS"
            )

    return False


def authenticate():
    username = input("Username: ").strip()
    password = getpass("Password: ")

    user = users.get(username)

    if user is None:
        print("Authentication failed.")
        audit_activity(
            username,
            "login",
            "N/A",
            "FAILURE"
        )
        return None

    if user["locked"]:
        print("Account locked.")
        audit_activity(
            username,
            "login",
            "N/A",
            "FAILURE"
        )
        return None

    candidate = hash_password(
        password,
        user["salt"]
    )

    if not hmac.compare_digest(
        candidate,
        user["password_hash"]
    ):
        register_security_failure(
            username,
            "login",
            "N/A",
            "Invalid password"
        )
        return None

    user["failed_attempts"] = 0

    print("Authentication successful.")

    audit_activity(
        username,
        "login",
        "N/A",
        "SUCCESS"
    )

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
    user = users.get(username)

    if user is None or user["locked"]:
        print("ACCESS DENIED:", permission)
        return False

    role = user["role"]

    allowed = permission in ROLE_PERMISSIONS[role]

    if allowed:
        print("ACCESS GRANTED:", permission)
    else:
        print("ACCESS DENIED:", permission)

    return allowed


def display_role_hierarchy():
    print("\n=== Role Hierarchy ===")

    for role, level in sorted(
        ROLE_LEVELS.items(),
        key=lambda item: item[1],
        reverse=True
    ):
        print(f"{role}: Level {level}")


# ============================================================
# SECTION 4.2 - UNIX-STYLE FILE PERMISSIONS
# ============================================================

def check_file_permission(username, filename, operation):
    if username not in users:
        print("FILE PERMISSION DENIED: Unknown user")
        return False

    if filename not in file_metadata:
        print("FILE PERMISSION DENIED: File not found")
        return False

    if operation not in ("r", "w", "x"):
        print("FILE PERMISSION DENIED: Invalid operation")
        return False

    metadata = file_metadata[filename]

    if username == metadata["owner"]:
        permissions = metadata["owner_permissions"]
    else:
        permissions = metadata["other_permissions"]

    allowed = operation in permissions

    print("\nFile:", filename)
    print("User:", username)
    print("Owner:", metadata["owner"])
    print("Requested permission:", operation)
    print("Available permissions:", permissions)

    if allowed:
        print("FILE PERMISSION GRANTED")
    else:
        print("FILE PERMISSION DENIED")

    return allowed


def demonstrate_file_permissions():
    print("\n=== Unix-style File Permission Tests ===")

    check_file_permission(
        "doctor1",
        "patient_record.txt",
        "w"
    )

    check_file_permission(
        "nurse1",
        "patient_record.txt",
        "r"
    )

    check_file_permission(
        "nurse1",
        "patient_record.txt",
        "w"
    )

    check_file_permission(
        "guest1",
        "public_notice.txt",
        "r"
    )

    check_file_permission(
        "guest1",
        "public_notice.txt",
        "w"
    )


# ============================================================
# SECTION 4.4 - SHA-256 INTEGRITY MONITORING
# ============================================================

def load_integrity_metadata():
    if not INTEGRITY_FILE.exists():
        return {}

    try:
        with open(
            INTEGRITY_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            metadata = json.load(file)

        if not isinstance(metadata, dict):
            raise ValueError("Invalid metadata format")

        return metadata

    except (OSError, json.JSONDecodeError, ValueError):
        print(
            "SECURITY ALERT: Integrity metadata "
            "cannot be loaded"
        )
        return None


def save_integrity_metadata(metadata):
    temporary_file = INTEGRITY_FILE.with_suffix(".tmp")

    try:
        with open(
            temporary_file,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(metadata, file, indent=4)

        temporary_file.replace(INTEGRITY_FILE)
        return True

    except OSError as error:
        print("SECURITY ALERT: Metadata save failed:", error)
        return False


def calculate_file_hash(path):
    sha256 = hashlib.sha256()

    with open(path, "rb") as file:
        for block in iter(
            lambda: file.read(65536),
            b""
        ):
            sha256.update(block)

    return sha256.hexdigest()


def update_file_integrity(filename):
    metadata = load_integrity_metadata()

    if metadata is None:
        return False

    path = DATA_DIR / filename

    try:
        new_hash = calculate_file_hash(path)
    except OSError as error:
        print("SECURITY ALERT: Hash calculation failed:", error)
        return False

    metadata[filename] = new_hash

    if not save_integrity_metadata(metadata):
        return False

    print("SHA-256 HASH GENERATED:", new_hash)
    return True


def verify_file_integrity(filename):
    metadata = load_integrity_metadata()

    if metadata is None:
        return False

    expected_hash = metadata.get(filename)

    if expected_hash is None:
        print("SECURITY ALERT: No stored integrity hash")
        return False

    path = DATA_DIR / filename

    try:
        actual_hash = calculate_file_hash(path)
    except OSError as error:
        print("SECURITY ALERT: Cannot verify file:", error)
        return False

    print("Stored SHA-256:", expected_hash)
    print("Current SHA-256:", actual_hash)

    if not hmac.compare_digest(
        actual_hash,
        expected_hash
    ):
        print(
            "SECURITY ALERT: FILE INTEGRITY "
            "BREACH DETECTED"
        )
        return False

    print("FILE INTEGRITY VERIFIED")
    return True


def remove_file_integrity(filename):
    metadata = load_integrity_metadata()

    if metadata is None:
        return False

    metadata.pop(filename, None)

    return save_integrity_metadata(metadata)


# ============================================================
# SECTION 4.3 - SECURE FILE OPERATIONS
# ============================================================

def secure_file_operation(username, filename, action, content=""):
    action_permissions = {
        "create": "manage_files",
        "read": "view_patient",
        "write": "update_patient",
        "delete": "manage_files"
    }

    file_permissions = {
        "read": "r",
        "write": "w",
        "delete": "w"
    }

    user = users.get(username)

    if user is None or user["locked"]:
        return register_security_failure(
            username,
            action,
            filename,
            "Invalid or locked account"
        )

    if action not in action_permissions:
        return register_security_failure(
            username,
            action,
            filename,
            "Invalid file operation"
        )

    if (
        not filename.endswith(".txt")
        or Path(filename).name != filename
        or filename in (".", "..")
    ):
        return register_security_failure(
            username,
            action,
            filename,
            "Invalid filename"
        )

    role_permission = action_permissions[action]

    if not check_permission(username, role_permission):
        return register_security_failure(
            username,
            action,
            filename,
            "RBAC permission denied"
        )

    path = DATA_DIR / filename

    # CREATE OPERATION
    if action == "create":
        if path.exists() or filename in file_metadata:
            return register_security_failure(
                username,
                action,
                filename,
                "File already exists"
            )

        try:
            with open(
                path,
                "x",
                encoding="utf-8"
            ) as file:
                file.write(content)

            file_metadata[filename] = {
                "owner": username,
                "owner_permissions": "rw-",
                "other_permissions": "r--"
            }

            if not update_file_integrity(filename):
                path.unlink(missing_ok=True)
                file_metadata.pop(filename, None)

                return register_security_failure(
                    username,
                    action,
                    filename,
                    "Unable to store file integrity hash"
                )

            print("SUCCESS: File created")

            audit_activity(
                username,
                action,
                filename,
                "SUCCESS"
            )

            return True

        except OSError as error:
            return register_security_failure(
                username,
                action,
                filename,
                f"File creation failed: {error}"
            )

    # CHECK FILE EXISTENCE
    if filename not in file_metadata or not path.is_file():
        return register_security_failure(
            username,
            action,
            filename,
            "File does not exist"
        )

    # CHECK UNIX-STYLE FILE PERMISSIONS
    required = file_permissions[action]

    if not check_file_permission(
        username,
        filename,
        required
    ):
        return register_security_failure(
            username,
            action,
            filename,
            "File permission denied"
        )

    # VERIFY INTEGRITY BEFORE FILE OPERATIONS
    if not verify_file_integrity(filename):
        return register_security_failure(
            username,
            action,
            filename,
            "File integrity verification failed"
        )

    try:
        # READ OPERATION
        if action == "read":
            print("\nFILE CONTENT:")
            print(path.read_text(encoding="utf-8"))

        # WRITE OPERATION
        elif action == "write":
            with open(
                path,
                "a",
                encoding="utf-8"
            ) as file:
                file.write("\n" + content)

            if not update_file_integrity(filename):
                return register_security_failure(
                    username,
                    action,
                    filename,
                    "Unable to update file integrity hash"
                )

            print("SUCCESS: File updated")

        # DELETE OPERATION
        elif action == "delete":
            if not remove_file_integrity(filename):
                return register_security_failure(
                    username,
                    action,
                    filename,
                    "Unable to update integrity metadata"
                )

            try:
                path.unlink()
            except OSError:
                update_file_integrity(filename)
                raise

            del file_metadata[filename]

            print("SUCCESS: File deleted")

        audit_activity(
            username,
            action,
            filename,
            "SUCCESS"
        )

        return True

    except (OSError, UnicodeError) as error:
        return register_security_failure(
            username,
            action,
            filename,
            f"File operation failed: {error}"
        )


# ============================================================
# SECTION 4.3 - OPERATION TESTS
# ============================================================

def demonstrate_secure_operations():
    print("\n=== Section 4.3 Secure File Operations ===")

    filename = "demo_patient.txt"

    print("\nTEST 1: Admin creates a file")
    secure_file_operation(
        "admin1",
        filename,
        "create",
        "Fictional patient test record"
    )

    print("\nTEST 2: Doctor reads the file")
    secure_file_operation(
        "doctor1",
        filename,
        "read"
    )

    print("\nTEST 3: Doctor attempts unauthorized modification")
    secure_file_operation(
        "doctor1",
        filename,
        "write",
        "Unauthorized modification"
    )

    print("\nTEST 4: Guest attempts unauthorized access")
    secure_file_operation(
        "guest1",
        filename,
        "read"
    )

    print("\nTEST 4B: Admin successfully updates the file")
    secure_file_operation(
        "admin1",
        filename,
        "write",
        "Authorized update by Admin"
    )

    print("\nTEST 5: Admin deletes the file")
    secure_file_operation(
        "admin1",
        filename,
        "delete"
    )


# ============================================================
# SECTION 4.4 - FILE TAMPERING DEMONSTRATION
# ============================================================

def demonstrate_integrity_monitoring():
    print("\n=== Section 4.4 SHA-256 Integrity Tests ===")

    filename = "integrity_test.txt"
    path = DATA_DIR / filename

    # Remove a leftover demonstration file only if it
    # belongs to the previous integrity test.
    # The normal test creates and cleans up its own file.

    if path.exists():
        print(
            "Test file already exists. "
            "Remove or rename it before rerunning this test."
        )
        return

    print("\nTEST 1: Create a protected file")

    created = secure_file_operation(
        "admin1",
        filename,
        "create",
        "Original fictional patient information"
    )

    if not created:
        return

    print("\nTEST 2: Verify the original file")

    secure_file_operation(
        "doctor1",
        filename,
        "read"
    )

    print("\nTEST 3: Simulate unauthorized file tampering")

    # This direct modification deliberately bypasses
    # the secure_file_operation access checks.
    # It is used only to demonstrate integrity detection.

    with open(path, "a", encoding="utf-8") as file:
        file.write("\nUnauthorized external modification")

    print("SIMULATED TAMPERING COMPLETED")

    print("\nTEST 4: Attempt to read the modified file")

    secure_file_operation(
        "doctor1",
        filename,
        "read"
    )

    print("\nTEST 5: Confirm the integrity alert was logged")

    print(
        "Review audit.log for the failed read operation "
        "and integrity alert."
    )

    print(
        "\nThe tampered file remains available for "
        "inspection. It has not been deleted."
    )


# ============================================================
# SECTION 4.6 - ACCOUNT LOCKOUT TEST
# ============================================================

def demonstrate_account_lockout():
    print("\n=== Account Lockout Demonstration ===")

    username = "guest1"

    if users[username]["locked"]:
        print("Guest account is already locked.")
        return

    print("Testing three unauthorized patient record requests.")

    for attempt in range(1, 4):
        print(f"\nUnauthorized attempt {attempt}")

        secure_file_operation(
            username,
            "demo_patient.txt",
            "read"
        )

    print("\nAccount locked:", users[username]["locked"])


# ============================================================
# MAIN MENU
# ============================================================

def main():
    setup_users()

    while True:
        print("\n=== Secure File System Simulator ===")
        print("1. Login and view role permissions")
        print("2. Display role hierarchy")
        print("3. Test Unix-style file permissions")
        print("4. Test secure file operations")
        print("5. Test SHA-256 file integrity")
        print("6. Test account lockout")
        print("7. Exit")

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
            display_role_hierarchy()

        elif choice == "3":
            demonstrate_file_permissions()

        elif choice == "4":
            demonstrate_secure_operations()

        elif choice == "5":
            demonstrate_integrity_monitoring()

        elif choice == "6":
            demonstrate_account_lockout()

        elif choice == "7":
            print("Exiting simulator.")
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
