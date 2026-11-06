from pathlib import Path
import json
import hmac
import secrets
import hashlib

# Lab 5 - Task 1
# SHA-256 Hashing of Strings

def generate_sha256(user_input):
    encoded_input = user_input.encode("utf-8")
    hash_value = hashlib.sha256(encoded_input).hexdigest()
    return hash_value


def test_string_hashing():
    print("=== LAB 5 - TASK 1: SHA-256 STRING HASHING ===")

    user_input = input("Enter a string to hash: ")

    hash_value = generate_sha256(user_input)

    print("\nOriginal Input:", user_input)
    print("SHA-256 Hash:", hash_value)
    print("Hash Length:", len(hash_value), "hexadecimal characters")

    print("\nPASS: SHA-256 hash generated successfully")

# Lab 5 - Task 2
# Message Authentication Code (HMAC)

def generate_hmac(secret_key, message):
    return hmac.new(
        secret_key,
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def verify_hmac(secret_key, message, expected_mac):
    calculated_mac = generate_hmac(secret_key, message)

    return hmac.compare_digest(calculated_mac, expected_mac)


def test_hmac():
    print("\n=== LAB 5 - TASK 2: HMAC VERIFICATION ===")

    # Generate a secret key for this demonstration
    secret_key = secrets.token_bytes(32)

    original_message = "Patient record approved"
    modified_message = "Patient record rejected"

    original_mac = generate_hmac(secret_key, original_message)

    print("\nOriginal Message:", original_message)
    print("Generated HMAC:", original_mac)

    valid_result = verify_hmac(
        secret_key,
        original_message,
        original_mac
    )

    print("\nValid Message Verification:", valid_result)

    modified_result = verify_hmac(
        secret_key,
        modified_message,
        original_mac
    )

    print("Modified Message:", modified_message)
    print("Modified Message Verification:", modified_result)

    if valid_result and not modified_result:
        print("\nPASS: HMAC detected unauthorized message modification")
    else:
        print("\nFAIL: Unexpected HMAC verification result")

# Lab 5 - Task 3
# NONCE Replay Protection

used_nonces = set()


def generate_nonce():
    return secrets.token_hex(16)


def process_request(nonce):
    print("\nProcessing request with NONCE:", nonce)

    if nonce in used_nonces:
        print("REJECTED: Duplicate NONCE detected")
        return False

    used_nonces.add(nonce)
    print("ACCEPTED: New NONCE")
    return True


def test_nonce_protection():
    print("\n=== LAB 5 - TASK 3: NONCE REPLAY PROTECTION ===")

    first_nonce = generate_nonce()
    second_nonce = generate_nonce()

    print("\nTEST 1 - FIRST REQUEST")
    first_result = process_request(first_nonce)

    print("\nTEST 2 - REPLAY SAME REQUEST")
    replay_result = process_request(first_nonce)

    print("\nTEST 3 - NEW REQUEST")
    second_result = process_request(second_nonce)

    if first_result and not replay_result and second_result:
        print("\nPASS: Replay attack successfully detected")
    else:
        print("\nFAIL: Unexpected NONCE validation result")

# Lab 5 - Task 4
# File Tampering Detection

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "patient_data.txt"
HASH_FILE = BASE_DIR / "file_hash.json"


def calculate_file_hash(file_path):
    digest = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            digest.update(chunk)

    return digest.hexdigest()


def create_file_baseline():
    if not DATA_FILE.exists():
        print("ERROR: patient_data.txt does not exist")
        return

    original_hash = calculate_file_hash(DATA_FILE)

    with open(HASH_FILE, "w", encoding="utf-8") as file:
        json.dump({"sha256": original_hash}, file, indent=4)

    print("\n=== FILE INTEGRITY BASELINE ===")
    print("File:", DATA_FILE.name)
    print("Original Hash:", original_hash)
    print("Baseline saved to:", HASH_FILE.name)


def verify_file_integrity():
    if not DATA_FILE.exists() or not HASH_FILE.exists():
        print("ERROR: Data file or baseline is missing")
        return

    with open(HASH_FILE, "r", encoding="utf-8") as file:
        stored_hash = json.load(file)["sha256"]

    current_hash = calculate_file_hash(DATA_FILE)

    print("\n=== FILE INTEGRITY VERIFICATION ===")
    print("Original Hash:", stored_hash)
    print("New Hash:", current_hash)

    if hmac.compare_digest(stored_hash, current_hash):
        print("PASS: File integrity verified")
    else:
        print("ALERT: File has been tampered!")


def test_file_tampering():
    print("\n=== LAB 5 - TASK 4: FILE TAMPERING DETECTION ===")

    print("1. Create original file hash")
    print("2. Verify file integrity")
    choice = input("Select an option (1 or 2): ").strip()

    if choice == "1":
        create_file_baseline()
    elif choice == "2":
        verify_file_integrity()
    else:
        print("Invalid selection")


if __name__ == "__main__":
    test_string_hashing()
    test_hmac()
    test_nonce_protection()
    test_file_tampering()
