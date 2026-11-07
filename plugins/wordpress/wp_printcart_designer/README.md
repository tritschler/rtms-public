# WordPress Printcart Product Designer Arbitrary File Upload Auditor (CVE-2026-19803)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--19803-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect WordPress web servers running vulnerable versions of the **Printcart Store – Web to Print Product Designer for WooCommerce** plugin (`<= 2.13.2`) exposed to **CVE-2026-19803**.

---

## 🔍 Vulnerability Summary (CVE-2026-19803)

* **Severity**: **Critical (CVSS 9.8)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
* **CWE**: CWE-22 (Path Traversal) / CWE-434 (Unrestricted Upload of File with Dangerous Type)
* **Affected Ecosystems**: WordPress sites using the **Printcart Store – Web to Print Product Designer for WooCommerce** plugin (`web-to-print-online-designer`) in versions up to and including `2.13.2`.

### Flaw Mechanics
The Printcart Store – Web to Print Product Designer for WooCommerce plugin for WordPress is vulnerable to **Arbitrary File Upload** in all versions up to, and including, **`2.13.2`**.

The `nbu_crop_image` AJAX handler accepts a user-supplied `url` parameter that `Nbdesigner_IO::convert_url_to_path()` concatenates onto the uploads base directory without normalizing or stripping `../` sequences, deriving both output directory and file extension from the unsanitized path.

---

## 📋 Affected Versions & Patched Thresholds

| Component | Status | Vulnerable Versions | Patched / Safe Release |
|:---|:---:|:---:|:---:|
| **Printcart Store – Web to Print Product Designer (`web-to-print-online-designer`)** | Active | All releases **`<= 2.13.2`** | **`2.13.3+`** |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_printcart_designer/wp_printcart_designer_cve_2026_19803_audit.py your-wordpress-site.com -p 80 443
```

---

## 💡 Remediation
1. **Update Plugin Immediately**: Upgrade **Printcart Store – Web to Print Product Designer** to **`2.13.3`** or later.
2. **Configuration Hardening**: Disable the *Advanced Upload Popup* (`nbdesigner_upload_popup_style = a`) setting if not required.
3. **Web Server Hardening**: Block direct public HTTP access to `/wp-content/plugins/*/readme.txt`.
