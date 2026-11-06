
import html
import re

# Lab 4 - Section 4.3
# Cross-Site Scripting Prevention

def sanitize_input(user_input):
    # Remove HTML tags from user input
    return re.sub(r"<[^>]*>", "", user_input)


def encode_output(user_input):
    # Encode HTML special characters
    return html.escape(user_input, quote=True)


def test_xss_prevention():
    print("=== LAB 4 - XSS PREVENTION TESTS ===")

    test_inputs = [
        "Patient appointment confirmed",
        "<script>alert('Hacked')</script>",
        "<img src=x onerror=alert('Hacked')>",
        "<b>Important Notice</b>"
    ]

    for user_input in test_inputs:
        print("\nOriginal input:", user_input)

        sanitized = sanitize_input(user_input)
        encoded = encode_output(user_input)

        print("Sanitized input:", sanitized)
        print("HTML encoded output:", encoded)

        if "<" not in encoded and ">" not in encoded:
            print("PASS: HTML characters safely encoded")
        else:
            print("REVIEW: Unsafe HTML characters detected")


if __name__ == "__main__":
    test_xss_prevention()
