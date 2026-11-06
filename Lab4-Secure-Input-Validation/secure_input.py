from pathlib import Path
import re


# Lab 4 - Section 4.1A
# Email Input Validation

def validate_email(email):
    print("\nChecking email:", email)

    if not isinstance(email, str):
        print("REJECTED: Email must be text")
        return False

    if len(email) > 254:
        print("REJECTED: Email exceeds maximum length")
        return False

    # Reject HTML and script-related characters
    if any(character in email for character in "<>\"'"):
        print("REJECTED: Potential script or unsafe characters")
        return False

    # Restrict email to a simple, safe format
    pattern = (
        r"^[A-Za-z0-9._%+-]+@"
        r"(?:[A-Za-z0-9-]+\.)+"
        r"[A-Za-z]{2,63}$"
    )

    if not re.fullmatch(pattern, email):
        print("REJECTED: Invalid email format or domain")
        return False

    print("ACCEPTED: Valid email format")
    return True


def test_email_validation():
    print("=== LAB 4 - EMAIL VALIDATION TESTS ===")

    test_emails = [
        "doctor@hospital.com",
        "nurse@healthcare.org",
        "admin@hospital",
        "invalid-email",
        "user@.com",
        "<script>alert('Hacked')</script>@hospital.com"
    ]

    for email in test_emails:
        validate_email(email)


# Lab 4 - Section 4.1B
# Secure Filename Validation

def validate_filename(filename):
    print("\nChecking filename:", filename)

    if not isinstance(filename, str) or not filename:
        print("REJECTED: Filename must be nonempty text")
        return False

    if ".." in filename:
        print("REJECTED: Potential directory traversal")
        return False

    if filename.startswith("."):
        print("REJECTED: Hidden files are not allowed")
        return False

    if not re.fullmatch(r"[A-Za-z0-9_.]+", filename):
        print("REJECTED: Invalid filename characters")
        return False

    print("ACCEPTED: Valid filename")
    return True


def test_filename_validation():
    print("\n=== LAB 4 - FILENAME VALIDATION TESTS ===")

    test_filenames = [
        "patient_record.txt",
        "report_2026.pdf",
        "data123.csv",
        "../passwords.txt",
        ".env",
        "patient/records.txt",
        "report file.txt",
        "notes<script>.txt"
    ]

    for filename in test_filenames:
        validate_filename(filename)

# Lab 4 - Section 4.1C
# Secure File Path Validation

SAFE_BASE_DIR = Path(__file__).resolve().parent / "safe_files"


def validate_file_path(user_path):
    print("\nChecking file path:", user_path)

    if not isinstance(user_path, str) or not user_path.strip():
        print("REJECTED: Invalid or empty file path")
        return False

    try:
        base_directory = SAFE_BASE_DIR.resolve()
        base_directory.mkdir(parents=True, exist_ok=True)

        # Reject absolute paths and Windows-style path separators
        if Path(user_path).is_absolute() or "\\" in user_path:
            print("REJECTED: Absolute or unsafe path")
            return False

        # Normalize and resolve the requested path
        requested_path = (base_directory / user_path).resolve()

        # Ensure the resolved path remains inside the safe directory
        if not requested_path.is_relative_to(base_directory):
            print("REJECTED: Directory traversal detected")
            return False

        print("ACCEPTED: Path is inside the safe directory")
        print("Normalized path:", requested_path)
        return True

    except (OSError, ValueError) as error:
        print("REJECTED: Invalid path:", error)
        return False


def test_file_path_validation():
    print("\n=== LAB 4 - FILE PATH VALIDATION TESTS ===")

    test_paths = [
        "patient_record.txt",
        "reports/summary.txt",
        "reports/../patient_record.txt",
        "../passwords.txt",
        "../../Windows/System32/config",
        "C:\\Windows\\System32\\config",
        "/etc/passwd"
    ]

    for path in test_paths:
        validate_file_path(path)

if __name__ == "__main__":
    test_email_validation()
    test_filename_validation()
    test_file_path_validation()
