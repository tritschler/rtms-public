# WordPress PDF Invoice for WooCommerce — CVE-2026-136240 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress installation running the **PDF Invoice for WooCommerce + Drag and Drop Template Builder** plugin is affected by **CVE-2026-136240** (CVSS 9.1, Critical), a PHP Object Injection vulnerability via untrusted input deserialization.

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| PDF Invoice for WooCommerce + Drag and Drop Template Builder | `<= 7.2.0` | `7.2.1+` |

## Usage
```bash
python3 plugins/wordpress/wp_pdf_invoice_woocommerce/wp_pdf_invoice_woocommerce_cve_2026_136240_audit.py --target https://wp.example.local
```
