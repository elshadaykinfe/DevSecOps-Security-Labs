
# Lab 4 - Section 4.4
# Formatting and Buffer Overflow Awareness

def demonstrate_formatting():
    print("=== LAB 4 - FORMATTING SAFETY TESTS ===")

    test_inputs = [
        "Patient record accessed",
        "%x %x %x",
        "%s %s"
    ]

    for user_input in test_inputs:
        print("\nUser input:", user_input)

        print("UNSAFE C PATTERN (NOT EXECUTED):")
        print("printf(user_input)")

        print("SAFE C PATTERN:")
        print('printf("%s", user_input)')

        print("Python safe output:", "%s" % (user_input,))
        print("PASS: Input treated as data")


def explain_buffer_overflow():
    print("\n=== BUFFER OVERFLOW AWARENESS ===")

    print(
        "A buffer overflow occurs when a program writes "
        "more data into a fixed-size memory buffer "
        "than it can hold."
    )

    print(
        "Python manages memory and checks bounds for "
        "built-in data structures, reducing traditional "
        "buffer overflow risks."
    )

    print(
        "However, native C extensions and unsafe "
        "external libraries can still introduce "
        "memory safety vulnerabilities."
    )


if __name__ == "__main__":
    demonstrate_formatting()
    explain_buffer_overflow()
