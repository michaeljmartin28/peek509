# Peek509

**Peek509** is a lightweight VS Code extension that lets you decode and inspect X.509 certificates directly from `.pem` or `.crt` files. Right-click a certificate file or run the command from the palette to instantly view its contents in a clean, human-readable format. No terminal commands required.

---

## Features

- Decode `.pem` and `.crt` files via:
  - Right-click in Explorer
  - Command Palette (with file picker fallback)
- Human-readable certificate viewer:
  - Subject and Issuer details
  - Validity period
  - Serial number
  - SHA-256 fingerprint
  - Signature preview
  - Public key details (RSA/ECDSA)
- Opens decoded output in a virtual tab (no save prompt)
- Clean indentation and aligned formatting for readability

---

## Usage

### Option 1: Right-click

- Open your project in VS Code.
- Right-click any `.pem` or `.crt` file in the Explorer.
- Select "**Peek509: Decode x509 Certificate**".
- A new tab will open with the decoded certificate.

### Option 2: Command Palette

- Open the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P`).
- Run "**Peek509: Decode x509 Certificate**".
- Select a certificate file from anywhere on your system.
- View the decoded output in a virtual tab.

---

## Installation

Search for **Peek509** in the [Visual Studio Marketplace](https://marketplace.visualstudio.com/) or install via the Extensions panel in VS Code.

---

## Roadmap

Planned for future versions:

- Extension decoding (e.g., subjectAltName, keyUsage)
- Webview UI with copy/export buttons and collapsible sections
- Multi-cert file support
- CSR and CRL decoding
- Decode PEM strings directly from highlighted text
- Certificate/key generation (RSA/ECDSA)
- Signature verification check

---

## License

MIT License — see [LICENSE](./LICENSE) for details.
