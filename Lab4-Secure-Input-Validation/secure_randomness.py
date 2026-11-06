
import random
import secrets
from collections import Counter

# Lab 4 - Section 4.5
# Secure Random Number Generation

def generate_tokens():
    print("=== SECURE TOKEN GENERATION ===")

    session_token = secrets.token_urlsafe(32)
    reset_token = secrets.token_urlsafe(32)

    print("Session token:", session_token)
    print("Password reset token:", reset_token)
    print("Session token length:", len(session_token))
    print("Password reset token length:", len(reset_token))
    print("Tokens are different:", session_token != reset_token)


def compare_randomness():
    print("\n=== INSECURE VS SECURE RANDOMNESS ===")

    insecure_number = random.randint(1, 100)
    secure_number = secrets.randbelow(100) + 1

    print("random.randint(1, 100):", insecure_number)
    print("secrets.randbelow(100) + 1:", secure_number)


def analyze_distribution():
    print("\n=== RANDOMNESS DISTRIBUTION ANALYSIS ===")

    sample_size = 1000

    insecure_values = [
        random.randint(1, 100)
        for _ in range(sample_size)
    ]

    secure_values = [
        secrets.randbelow(100) + 1
        for _ in range(sample_size)
    ]

    insecure_counts = Counter(insecure_values)
    secure_counts = Counter(secure_values)

    print("Total values generated:", sample_size)
    print("Expected average per number:", sample_size / 100)

    print("\nINSECURE RANDOM DISTRIBUTION")
    print("Unique numbers:", len(insecure_counts))
    print("Minimum frequency:", min(insecure_counts.values()))
    print("Maximum frequency:", max(insecure_counts.values()))

    print("\nSECURE RANDOM DISTRIBUTION")
    print("Unique numbers:", len(secure_counts))
    print("Minimum frequency:", min(secure_counts.values()))
    print("Maximum frequency:", max(secure_counts.values()))

    print("\nFREQUENCY COMPARISON FOR NUMBERS 1 TO 10")

    print("Number | random | secrets")
    for number in range(1, 11):
        print(
            f"{number:6} | "
            f"{insecure_counts[number]:6} | "
            f"{secure_counts[number]:7}"
        )

    print("\nPASS: Generated and analyzed 1000 values per method")


if __name__ == "__main__":
    generate_tokens()
    compare_randomness()
    analyze_distribution()
