
import sqlite3

# Lab 4 - Section 4.2
# SQL Injection Prevention Demonstration

def setup_database():
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    cursor.executemany(
        "INSERT INTO users (username, role) VALUES (?, ?)",
        [
            ("admin", "Administrator"),
            ("doctor", "Doctor"),
            ("nurse", "Nurse")
        ]
    )

    connection.commit()
    return connection


def vulnerable_search(connection, user_input):
    print("\nVULNERABLE QUERY")
    query = (
        "SELECT username, role FROM users WHERE username = '"
        + user_input + "'"
    )

    print("SQL:", query)

    try:
        rows = connection.execute(query).fetchall()
        print("Results:", rows)
        return rows
    except sqlite3.Error as error:
        print("SQL error:", error)
        return []


def secure_search(connection, user_input):
    print("\nSECURE PARAMETERIZED QUERY")

    query = "SELECT username, role FROM users WHERE username = ?"

    print("SQL:", query)
    print("Parameter:", repr(user_input))

    rows = connection.execute(query, (user_input,)).fetchall()
    print("Results:", rows)
    return rows


def run_tests():
    connection = setup_database()

    try:
        print("=== LAB 4 - SQL INJECTION TESTS ===")

        print("\nTEST 1 - NORMAL USERNAME")
        normal_input = "doctor"
        vulnerable_search(connection, normal_input)
        secure_search(connection, normal_input)

        print("\nTEST 2 - SQL INJECTION ATTEMPT")
        injection_input = "' OR '1'='1"
        vulnerable_results = vulnerable_search(
            connection, injection_input
        )
        secure_results = secure_search(
            connection, injection_input
        )

        print("\n=== SECURITY COMPARISON ===")
        print("Vulnerable query returned:",
              len(vulnerable_results), "records")
        print("Secure query returned:",
              len(secure_results), "records")

        if len(vulnerable_results) > 1 and not secure_results:
            print("PASS: SQL injection succeeded only in the vulnerable query")
        else:
            print("REVIEW: Unexpected demonstration result")

    finally:
        connection.close()


if __name__ == "__main__":
    run_tests()
