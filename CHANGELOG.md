# Changelog

All notable changes to this project will be documented here.

---

## [1.0.0] - 2025-10-25

### Added

- Initial release of Peek509
- Right-click context menu for `.pem` and `.crt` files
- Certificate decoding using Node Forge
- Human-readable formatting of:
  - Subject / Issuer
  - Validity dates
  - Serial number
  - Signature algorithm
  - Public key (RSA/ECDSA)
  - SHA-256 fingerprint
  - Signature preview
- Error handling for invalid or unreadable certs

## [1.1.0] - 2025-10-25

### Added

- Support for running "Decode x509 Certificate" from the Command Palette
- File picker fallback for decoding certs outside the workspace
- Improved formatting with aligned and indented output

### Changed

- Changes output to use a virtual document provider to prevent users being prompted to save decoded output.

## [1.1.1] - 2025-10-27

### Changed

- Changes the minimum VSCode version requirement to 1.101.0
