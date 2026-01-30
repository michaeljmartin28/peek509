# Changelog

All notable changes to this project will be documented here.

---

## [1.3.2] - 2026-01-30

### Fixes

- The path to the GIF so it works on both GitHub and the VS Code Marketplace.

## [1.3.1] - 2026-01-30

### Added

- Adds an MP4 Demo clip to the README and VS Code Marketplace.

## [1.3.0] - 2026-01-09

### Added

- New Webview-based certificate viewer with Tailwind styling for a richer, more readable UI
- `peek509.renderMode` configuration option to choose between Webview and text output
- Light/Dark theme support for the Webview (`peek509.webviewTheme`)
- HTML formatters for supported X.509 extensions, improving readability and structure
- Collapsible sections in the Webview for cleaner navigation
- Copy-to-clipboard buttons for long fields such as:
  - SHA-256 fingerprint
  - RSA modulus
  - EC public key
- - Raw extension data is now displayed in the Webview for all X.509 extensions, including those not yet fully parsed

### Changed

- Integrated ASN.1 parsing pipeline into the Webview renderer
- Improved internal architecture to support future UI enhancements
- README updates for clarity

### Fixed

- Resolved an issue where reopening a modified PEM/CRT file would display stale cached data

## [1.2.1] - 2025-11-02

### Changed

- Updated README to reflect new extension support and public key parsing

## [1.2.0] - 2025-11-02

### Added

- Manual ASN.1 parsing of certificate fields using asn1js and pkijs
- Expanded public key support: RSA, ECDSA, and future extensibility for EdDSA
- Support for parsing additional X.509 extensions:
  - keyUsage
  - extendedKeyUsage
  - subjectKeyIdentifier
  - authorityKeyIdentifier
  - prettyPrintExtension() and formatExtensionText() now render parsed extension values with fallback messaging and warnings
  - OID mapping for subject/issuer attributes and extensions for cleaner, more readable output

### Changed

- Refactored decodeCertificate() to remove dependency on node-forge
- SHA-256 fingerprinting now uses Node’s built-in crypto module
- Centralized ASN.1 decoding logic for extension parsers via shared utility

### Removed

- Removed node-forge from runtime dependencies

## [1.1.1] - 2025-10-27

### Changed

- Changes the minimum VSCode version requirement to 1.101.0

## [1.1.0] - 2025-10-25

### Added

- Support for running "Decode x509 Certificate" from the Command Palette
- File picker fallback for decoding certs outside the workspace
- Improved formatting with aligned and indented output

### Changed

- Changes output to use a virtual document provider to prevent users being prompted to save decoded output.

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
