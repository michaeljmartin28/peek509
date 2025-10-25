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
