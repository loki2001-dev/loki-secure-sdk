# loki-secure-sdk (C++20 & OpenSSL)
- A modern, modular cryptographic utility SDK powered by OpenSSL and C++20.
- Designed for high-reliability embedded and networked systems that require secure communications and data protection.

---

## Features
- OpenSSL 3.x compatible wrapper classes
- SHA256, SHA512, MD5, CHACHA20, AES encryption/decryption support
- Public key crypto support: RSA, DSA, EC (Elliptic Curve)
- X.509 certificate parsing, CSR generation, and CRL handling
- Secure random number generation
- PEM/DER format helpers for encoding/decoding
- Secure memory and exception utilities
- Thread-safe OpenSSL initialization handling
- Logging support via spdlog (modular and optional)
- Builds as static or shared library (`BUILD_SHARED_LIBS` supported)

---

## Directory Structure

| Directory        | Description                                   |
|------------------|-----------------------------------------------|
| `src/core/`      | Base utilities (memory, traits, exceptions)   |
| `src/crypto/`    | Symmetric/Hash crypto (AES, SHA, MD5, etc.)   |
| `src/asym/`      | Asymmetric crypto (RSA, DSA, EC)              |
| `src/x509/`      | X.509 certs, CSR, CRL wrappers                |
| `src/tls/`       | TLS-related interfaces and SSL abstraction    |
| `src/io/`        | BIO and I/O utilities                         |
| `3rdparty/`      | External dependencies (e.g., spdlog)          |
| `main.cpp`       | Example application demo                      |

---

## Getting Started

### Prerequisites
- Linux (Ubuntu 20.04 or later recommended)
- Requires CMake 3.14 or later
- Requires C++20 or later compiler
- OpenSSL 3.0 or later (libssl-dev)
  [spdlog](https://github.com/gabime/spdlog) (included as a submodule)

---

## Build Instructions

```bash
# Clone the repository
git clone https://github.com/loki2001-dev/loki-secure-sdk.git
cd loki-secure-sdk

# Initialize submodules
git submodule update --init --recursive

# Build the project
. ./build_project.sh