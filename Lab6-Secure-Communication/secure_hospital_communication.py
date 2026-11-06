import shutil
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from pathlib import Path
from getpass import getpass

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# Lab 6 - Part 2
# RSA Key Infrastructure Setup

BASE_DIR = Path(__file__).resolve().parent
KEY_DIR = BASE_DIR / "hospital_keys"


def generate_hospital_keys(hospital_name, password):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    public_key = private_key.public_key()

    private_key_path = KEY_DIR / f"{hospital_name}_private.pem"
    public_key_path = KEY_DIR / f"{hospital_name}_public.pem"

    encrypted_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password
        )
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(private_key_path, "xb") as file:
        file.write(encrypted_private_key)

    with open(public_key_path, "xb") as file:
        file.write(public_key_bytes)

    return private_key_path, public_key_path


def test_hospital_key_setup():
    print("=== LAB 6 - PART 2: RSA KEY INFRASTRUCTURE ===")

    KEY_DIR.mkdir(exist_ok=True)

    password = getpass(
        "Enter a password to encrypt the private keys: "
    ).encode("utf-8")

    if not password:
        print("ERROR: Password cannot be empty")
        return

    hospitals = [
        "hospital_A",
        "hospital_B"
    ]

    for hospital in hospitals:
        try:
            private_path, public_path = generate_hospital_keys(
                hospital, password
            )

            print(f"\nHospital: {hospital}")
            print("RSA Key Size: 3072 bits")
            print("Private Key:", private_path.name)
            print("Private Key Protection: Encrypted PEM")
            print("Public Key:", public_path.name)
            print("Public Key Export: Successful")

        except FileExistsError:
            print(f"\nHospital: {hospital}")
            print("Keys already exist. Existing keys were not overwritten.")

    print("\nKey infrastructure setup completed.")

# Lab 6 - Part 2B
# Secure Public Key Exchange

def test_public_key_exchange():
    print("\n=== LAB 6 - PART 2B: PUBLIC KEY EXCHANGE ===")

    hospital_a_dir = BASE_DIR / "hospital_A_received"
    hospital_b_dir = BASE_DIR / "hospital_B_received"

    hospital_a_dir.mkdir(exist_ok=True)
    hospital_b_dir.mkdir(exist_ok=True)

    # Public keys already generated in Part 2
    hospital_a_public = KEY_DIR / "hospital_A_public.pem"
    hospital_b_public = KEY_DIR / "hospital_B_public.pem"

    # Simulate public key exchange
    hospital_a_received = hospital_a_dir / "hospital_B_public.pem"
    hospital_b_received = hospital_b_dir / "hospital_A_public.pem"

    shutil.copyfile(hospital_b_public, hospital_a_received)
    shutil.copyfile(hospital_a_public, hospital_b_received)

    print("Hospital A received Hospital B public key")
    print("Hospital B received Hospital A public key")

    # Calculate SHA-256 fingerprint
    def fingerprint(file_path):
        with open(file_path, "rb") as file:
            return hashlib.sha256(file.read()).hexdigest()

    # Simulated trusted fingerprints.
    # In a real system these must be obtained through an
    # independently authenticated channel.
    trusted_a = fingerprint(hospital_a_public)
    trusted_b = fingerprint(hospital_b_public)

    received_a = fingerprint(hospital_b_received)
    received_b = fingerprint(hospital_a_received)

    print("\nHospital A Public Key Fingerprint:", trusted_a)
    print("Hospital B Public Key Fingerprint:", trusted_b)

    print("\nHospital A verified Hospital B public key:",
          received_b == trusted_b)

    print("Hospital B verified Hospital A public key:",
          received_a == trusted_a)

    if received_b == trusted_b and received_a == trusted_a:
        print("\nPASS: Public keys exchanged and verified")
    else:
        print("\nFAIL: Public key verification failed")

# Lab 6 - Part 3
# Secure RSA Message Encryption and Decryption

def encrypt_message(public_key_path, message):
    with open(public_key_path, "rb") as file:
        public_key = serialization.load_pem_public_key(
            file.read()
        )

    ciphertext = public_key.encrypt(
        message.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext


def decrypt_message(private_key_path, ciphertext, password):
    with open(private_key_path, "rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=password
        )

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext.decode("utf-8")


def test_secure_message_transfer():
    print("\n=== LAB 6 - PART 3: RSA MESSAGE ENCRYPTION ===")

    message = (
        "Patient ID 98321 requires immediate cardiac intervention."
    )

    public_key_path = KEY_DIR / "hospital_B_public.pem"
    private_key_path = KEY_DIR / "hospital_B_private.pem"

    password = getpass(
        "Enter Hospital B private key password: "
    ).encode("utf-8")

    try:
        ciphertext = encrypt_message(public_key_path, message)

        print("\nSender: Hospital A")
        print("Recipient: Hospital B")
        print("Original Message:", message)
        print("Encrypted Ciphertext (hex):", ciphertext.hex())

        decrypted_message = decrypt_message(
            private_key_path,
            ciphertext,
            password
        )

        print("\nDecrypted Message:", decrypted_message)

        if decrypted_message == message:
            print("PASS: RSA encryption and decryption successful")
        else:
            print("FAIL: Decrypted message does not match")

    except (ValueError, TypeError) as error:
        print("ERROR: Unable to decrypt message.")
        print("Check the private key password and key files.")

# Lab 6 - Part 4
# RSA Digital Signatures

def sign_message(private_key_path, message, password):
    with open(private_key_path, "rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=password
        )

    signature = private_key.sign(
        message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def verify_signature(public_key_path, message, signature):
    from cryptography.exceptions import InvalidSignature

    with open(public_key_path, "rb") as file:
        public_key = serialization.load_pem_public_key(
            file.read()
        )

    try:
        public_key.verify(
            signature,
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True

    except InvalidSignature:
        return False


def test_digital_signatures():
    print("\n=== LAB 6 - PART 4: DIGITAL SIGNATURES ===")

    original_message = "Glucose level: 6.5 mmol/L"

    modified_message = "Glucose level: 16.5 mmol/L"

    private_key_path = KEY_DIR / "hospital_A_private.pem"
    public_key_path = KEY_DIR / "hospital_A_public.pem"

    password = getpass(
        "Enter Hospital A private key password: "
    ).encode("utf-8")

    try:
        signature = sign_message(
            private_key_path,
            original_message,
            password
        )

        print("\nOriginal Message:", original_message)
        print("Digital Signature (hex):", signature.hex())

        valid_result = verify_signature(
            public_key_path,
            original_message,
            signature
        )

        print("\nOriginal Message Verification:", valid_result)

        modified_result = verify_signature(
            public_key_path,
            modified_message,
            signature
        )

        print("Modified Message:", modified_message)
        print("Modified Message Verification:", modified_result)

        if valid_result and not modified_result:
            print("\nPASS: Digital signature detected message modification")
        else:
            print("\nFAIL: Unexpected signature verification result")

    except (ValueError, TypeError):
        print("ERROR: Check Hospital A private key password")


# Lab 6 - Part 5
# RSA Session Key Exchange and Hybrid Encryption

def test_rsa_session_key_exchange():
    print("\n=== LAB 6 - PART 5: RSA SESSION KEY EXCHANGE ===")

    public_key_path = KEY_DIR / "hospital_B_public.pem"
    private_key_path = KEY_DIR / "hospital_B_private.pem"

    password = getpass(
        "Enter Hospital B private key password: "
    ).encode("utf-8")

    # Hospital A generates a secure 256-bit AES session key
    session_key = secrets.token_bytes(32)

    print("\nSender: Hospital A")
    print("Recipient: Hospital B")
    print("Session Key Size:", len(session_key) * 8, "bits")

    with open(public_key_path, "rb") as file:
        public_key = serialization.load_pem_public_key(
            file.read()
        )

    # Encrypt session key with Hospital B public key
    encrypted_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("\nEncrypted Session Key (hex):", encrypted_key.hex())

    # Hospital B decrypts the session key
    with open(private_key_path, "rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=password
        )

    recovered_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    keys_match = secrets.compare_digest(
        session_key,
        recovered_key
    )

    print("\nRecovered Session Key Size:",
          len(recovered_key) * 8, "bits")
    print("Session Keys Match:", keys_match)

    if not keys_match:
        print("FAIL: Session key exchange unsuccessful")
        return

    print("PASS: RSA session key exchange successful")

    # Demonstrate hybrid encryption with AES-GCM
    message = b"Confidential patient transfer approved"

    aes_sender = AESGCM(session_key)
    nonce = secrets.token_bytes(12)

    ciphertext = aes_sender.encrypt(nonce, message, None)

    print("\n=== HYBRID ENCRYPTION TEST ===")
    print("Original Message:", message.decode())
    print("AES-GCM Ciphertext (hex):", ciphertext.hex())

    aes_receiver = AESGCM(recovered_key)
    decrypted_message = aes_receiver.decrypt(
        nonce, ciphertext, None
    )

    print("Decrypted Message:", decrypted_message.decode())

    if decrypted_message == message:
        print("PASS: Hybrid encryption and decryption successful")
    else:
        print("FAIL: Hybrid encryption test failed")

# Lab 6 - Part 6
# Diffie-Hellman Key Exchange

def test_diffie_hellman():
    print("\n=== LAB 6 - PART 6: DIFFIE-HELLMAN KEY EXCHANGE ===")

    # Both hospitals agree on the same public parameters
    parameters = dh.generate_parameters(
        generator=2,
        key_size=2048
    )

    print("DH Parameter Size: 2048 bits")

    # Each hospital generates its own private key
    hospital_a_private = parameters.generate_private_key()
    hospital_b_private = parameters.generate_private_key()

    # Public keys are exchanged between hospitals
    hospital_a_public = hospital_a_private.public_key()
    hospital_b_public = hospital_b_private.public_key()

    print("Hospital A private key generated")
    print("Hospital B private key generated")
    print("Hospital A public key generated")
    print("Hospital B public key generated")
    print("Public key exchange completed")

    # Hospital A independently calculates the shared secret
    hospital_a_secret = hospital_a_private.exchange(
        hospital_b_public
    )

    # Hospital B independently calculates the shared secret
    hospital_b_secret = hospital_b_private.exchange(
        hospital_a_public
    )

    secrets_match = secrets.compare_digest(
        hospital_a_secret,
        hospital_b_secret
    )

    print("\nHospital A Shared Secret Length:",
          len(hospital_a_secret), "bytes")
    print("Hospital B Shared Secret Length:",
          len(hospital_b_secret), "bytes")

    print("Shared Secrets Match:", secrets_match)

    if secrets_match:
        print("PASS: Diffie-Hellman key exchange successful")
    else:
        print("FAIL: Shared secrets do not match")

if __name__ == "__main__":
    test_hospital_key_setup()
    test_public_key_exchange()
    test_secure_message_transfer()
    test_digital_signatures()
    test_rsa_session_key_exchange()
    test_diffie_hellman()
