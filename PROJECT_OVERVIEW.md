# DevSecOps Security Labs

## Project Overview

This repository contains six hands-on cybersecurity labs developed as part of my graduate studies. The projects focus on secure software development, authentication, access control, input validation, cryptographic integrity, and secure communication.

I implemented the labs using Python and tested them in Visual Studio Code on Windows. Each lab demonstrates security principles through practical implementation, testing, and analysis of potential vulnerabilities.

## Lab Overview

| Lab | Topic | Main Security Concepts |
|---|---|---|
| 1 | Secure Data Storage | Secure handling and protection of stored information |
| 2 | Secure Authentication | Authentication mechanisms and security controls |
| 3 | Access Control | Role-Based Access Control, file permissions, SHA-256 integrity checks, audit logging |
| 4 | Secure Input Validation | Email and filename validation, path traversal prevention, SQL injection, XSS prevention, secure randomness |
| 5 | Integrity Protection | SHA-256 hashing, HMAC, replay protection, file tampering detection |
| 6 | Secure Communication | RSA encryption, digital signatures, AES-GCM hybrid encryption, public key exchange, Diffie–Hellman |

## Lab 1 — Secure Data Storage

This lab explores techniques for protecting stored information and reducing the risk of unauthorized data exposure.

**Focus:** Secure data storage and protection of sensitive information.

## Lab 2 — Secure Authentication

This lab focuses on implementing and understanding authentication security controls.

**Focus:** Authentication mechanisms and secure access to applications.

## Lab 3 — Access Control and Secure File Operations

I developed a Python-based access control system that applies Role-Based Access Control to a simulated healthcare environment.

The implementation includes:

- Admin, Doctor, Nurse, and Guest roles
- Role hierarchy and permission enforcement
- Unix-style file permissions
- Secure file creation, reading, writing, and deletion
- SHA-256 file integrity verification
- Security event logging and unauthorized access detection
- Account lockout after repeated failed access attempts

## Lab 4 — Secure Input Validation

This lab demonstrates how input validation and secure coding practices reduce common application vulnerabilities.

I implemented and tested:

- Email address validation
- Filename validation
- Directory traversal prevention
- SQL injection prevention using parameterized queries
- Cross-Site Scripting prevention through HTML encoding
- Secure formatting practices
- Cryptographically secure random number generation
- Entropy analysis and predictable random sequence demonstrations

## Lab 5 — Cryptographic Integrity Protection

This lab focuses on protecting information against unauthorized modification and replay attacks.

I implemented:

- SHA-256 string hashing
- HMAC generation and verification
- Detection of modified messages
- Nonce-based replay protection
- File integrity baseline generation
- File tampering detection through hash comparison

## Lab 6 — Secure Hospital Communication

I developed a Python demonstration of secure communication between two simulated hospitals.

The implementation includes:

- Generation of 3072-bit RSA key pairs
- Password-encrypted private key storage
- Public key export and simulated exchange
- SHA-256 public key fingerprint comparison
- RSA message encryption and decryption
- RSA digital signatures for message integrity
- Detection of modified medical information
- RSA session key exchange
- AES-GCM hybrid encryption
- Diffie–Hellman shared secret establishment

The public key exchange is a local simulation. A production implementation would require authenticated key distribution, such as validated digital certificates. The Diffie–Hellman demonstration uses finite-field parameters for educational purposes.

## Technologies Used

- Python 3
- Visual Studio Code
- Git and GitHub
- Python `cryptography` library
- Python `hashlib`, `hmac`, `secrets`, `sqlite3`, and other standard libraries
- Windows PowerShell

## Running the Labs

Clone the repository:

```bash
git clone https://github.com/elshadaykinfe/DevSecOps-Security-Labs.git
cd DevSecOps-Security-Labs
```

Install the cryptography dependency for Lab 6:

```bash
python -m pip install cryptography
```

Run an individual lab by opening its folder and executing the relevant Python script.

For example:

```bash
cd Lab5-Integrity-Protection
python integrity_system.py
```

Some labs require interactive input, and Lab 6 uses locally generated RSA key files. Private keys, passwords, and runtime data should not be committed to this repository.

## Security Considerations

These labs are educational demonstrations rather than production-ready security systems. They were developed in a controlled environment to understand security mechanisms, identify weaknesses, and practice defensive programming.

Real-world deployments require additional safeguards, including secure credential management, authenticated key exchange, appropriate authorization policies, protected logging, and ongoing security testing.

## Learning Outcomes

Through these projects, I gained practical experience in secure Python programming, authentication and authorization, cryptographic integrity, vulnerability prevention, security testing, and secure communication design.

The labs strengthened my ability to connect cybersecurity concepts with working implementations and evaluate how security controls behave under normal and malicious inputs.

## Repository Purpose

I maintain this repository as a record of my practical cybersecurity development work and continued learning in secure software design and DevSecOps.