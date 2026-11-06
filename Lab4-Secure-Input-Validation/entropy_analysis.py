
import random
import secrets
import math
from collections import Counter

# Lab 4 - Section 4.6
# Entropy and Predictability Analysis


def demonstrate_weak_randomness():
    print("=== WEAK SEED-BASED RANDOMNESS ===")

    first_generator = random.Random(12345)
    second_generator = random.Random(12345)

    first_sequence = [
        first_generator.randint(1, 100)
        for _ in range(10)
    ]

    second_sequence = [
        second_generator.randint(1, 100)
        for _ in range(10)
    ]

    print("First sequence:", first_sequence)
    print("Second sequence:", second_sequence)
    print("Sequences identical:",
          first_sequence == second_sequence)

    print("Security risk: A known seed can reproduce the sequence.")


def demonstrate_secure_randomness():
    print("\n=== CRYPTOGRAPHIC RANDOMNESS ===")

    first_sequence = [
        secrets.randbelow(100) + 1
        for _ in range(10)
    ]

    second_sequence = [
        secrets.randbelow(100) + 1
        for _ in range(10)
    ]

    print("First sequence:", first_sequence)
    print("Second sequence:", second_sequence)
    print("Sequences identical:",
          first_sequence == second_sequence)

    print(
        "Security benefit: secrets uses a "
        "cryptographically secure random source."
    )


def calculate_entropy(values):
    counts = Counter(values)
    total = len(values)

    entropy = 0.0

    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy


def analyze_entropy():
    print("\n=== ENTROPY ANALYSIS ===")

    predictable = [1] * 1000

    secure_samples = [
        secrets.randbelow(100)
        for _ in range(1000)
    ]

    predictable_entropy = calculate_entropy(predictable)
    secure_sample_entropy = calculate_entropy(secure_samples)

    maximum_entropy = math.log2(100)

    print("Predictable sequence entropy:",
          round(predictable_entropy, 4), "bits")

    print("Secure sample empirical entropy:",
          round(secure_sample_entropy, 4), "bits")

    print("Maximum entropy for 100 equally likely values:",
          round(maximum_entropy, 4), "bits")

    print(
        "Note: Sample entropy does not prove "
        "cryptographic unpredictability."
    )


def explain_attack_scenarios():
    print("\n=== SECURITY ATTACK SCENARIOS ===")

    print(
        "Token prediction: If an attacker can predict "
        "future authentication tokens, they may gain "
        "unauthorized access."
    )

    print(
        "Session hijacking: A predicted or stolen "
        "session token can allow an attacker to "
        "impersonate a legitimate user."
    )

    print(
        "Prevention: Use secrets for security tokens, "
        "protect tokens in transit and storage, "
        "and enforce token expiration."
    )


if __name__ == "__main__":
    demonstrate_weak_randomness()
    demonstrate_secure_randomness()
    analyze_entropy()
    explain_attack_scenarios()
