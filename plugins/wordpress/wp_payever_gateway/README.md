# WordPress payever WooCommerce Gateway Arbitrary File Upload Auditor (CVE-2026-93754)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--93754-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect WordPress web servers running vulnerable versions of the **payever – WooCommerce Gateway** plugin (`<= 4.8.0`) exposed to **CVE-2026-93754**.

---

## 🔍 Vulnerability Summary (CVE-2026-93754)

* **Severity**: **Critical (CVSS 9.8)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
* **CWE**: CWE-862 (Missing Authorization) / CWE-434 (Unrestricted Upload of File with Dangerous Type)
* **Affected Ecosystems**: WordPress sites using the **payever – WooCommerce Gateway** plugin (`payever-woocommerce-gateway`) in versions up to and including `4.8.0`.

### Flaw Mechanics
The payever – WooCommerce Gateway plugin for WordPress is vulnerable to **Arbitrary File Upload** in versions up to, and including, **`4.8.0`**.

Three WooCommerce-API callbacks (`payever_set_sandbox_api_keys`, `payever_toggle_subscription`, `payever_synchronization_incoming`) are registered with no authentication, capability check, or nonce, and the `upload_image()` routine writes remotely fetched files to the public uploads directory before validating the file type.

---

## 📋 Affected Versions & Patched Thresholds

| Component | Status | Vulnerable Versions | Patched / Safe Release |
|:---|:---:|:---:|:---:|
| **payever – WooCommerce Gateway (`payever-woocommerce-gateway`)** | Active | All releases **`<= 4.8.0`** | **`4.8.1+`** |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_payever_gateway/wp_payever_gateway_cve_2026_93754_audit.py your-wordpress-site.com -p 80 443
```

---

## 💡 Remediation
1. **Update Plugin Immediately**: Upgrade **payever – WooCommerce Gateway** to **`4.8.1`** or later.
2. **Audit Uploads & API Keys**: Inspect `wp-content/uploads/` and verify configured Payever API keys.
3. **Web Server Hardening**: Block direct public HTTP access to `/wp-content/plugins/payever-woocommerce-gateway/readme.txt`.
