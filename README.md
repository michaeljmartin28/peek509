# Peek509

**Peek509** is a lightweight VS Code extension that lets you decode and inspect X.509 certificates directly from `.pem` or `.crt` files. Right-click a certificate file and instantly view its contents in a clean, human-readable format — no terminal commands required.

---

## Features

- Right-click to decode `.pem` and `.crt` files
- Human-readable certificate viewer:
  - Subject and Issuer details
  - Validity period
  - Serial number
  - Signature algorithm
  - Public key details (RSA/ECDSA)
  - SHA-256 fingerprint
  - Raw signature preview
- Opens decoded output in a new tab

---

## Usage

1. Open your project in VS Code.
2. Right-click any `.pem` or `.crt` file in the Explorer.
3. Select **"Peek509: Decode x509 Certificate"**.
4. A new tab will open with the decoded certificate.

---

## Installation

Search for **Peek509** in the [Visual Studio Marketplace](https://marketplace.visualstudio.com/) or install via the Extensions panel in VS Code.

---

## Roadmap

Planned for future versions:

- Extension decoding (subjectAltName, keyUsage, etc.)
- Webview UI with copy/export buttons
- Multi-cert file support
- CSR and CRL decoding
- Decode PEM strings directly from highlighted text

---

## License

MIT License — see [LICENSE](./LICENSE) for details.
