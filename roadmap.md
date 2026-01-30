# Peek509 – Development Notes & Future Ideas

This file tracks potential features, settings, and architectural ideas for future versions of Peek509. These are not yet implemented, but may be prioritized based on user feedback and feasibility.

---

## 🧩 Proposed Settings (Not Yet Active)

| Key                                | Type                    | Default     | Description                                        |
| ---------------------------------- | ----------------------- | ----------- | -------------------------------------------------- |
| `peek509.renderMode`               | `"webview"` \| `"text"` | `"webview"` | Choose between rich HTML view or plain text output |
| `peek509.showOIDMapping`           | `boolean`               | `true`      | Display friendly OID names instead of raw values   |
| `peek509.extensionCollapseDefault` | `boolean`               | `true`      | Collapse all extensions by default in the webview  |

---

## 🧠 Feature Ideas

- [ ] Export DER decoded cert as JSON or PEM
- [ ] Signature verification (basic trust check)
- [ ] Webview dark mode support
- [ ] Search/filter extensions by OID or name
- [ ] Inline ASN.1 tree view for raw DER
- [ ] Cert chain visualization (if multiple certs detected)
- [ ] Status bar toggle for render mode
- [ ] Auto-decode certs in clipboard

---

## 🛠️ Technical Notes

- Consider migrating Tailwind to a precompiled CSS bundle for offline support

---

## 📌 Prioritization Thoughts

- Webview MVP: Webview rendering, copy buttons, collapsible extensions
- v1.3: Configurable render mode, raw data toggle, dark mode
- v1.4+: Export, chain support, trust indicators
