# WordPress Product Input Fields for WooCommerce — CVE-2026-104998 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress installation running the **Product Input Fields for WooCommerce** plugin (`product-input-fields-for-woocommerce`) is affected by **CVE-2026-104998** (CVSS 9.8, Critical), an unauthenticated arbitrary file upload vulnerability in `process_file_input_field`.

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Product Input Fields for WooCommerce | `<= 2.1.0` | `2.1.1+` |

## Usage
```bash
python3 plugins/wordpress/wp_product_input_fields_woocommerce/wp_product_input_fields_woocommerce_cve_2026_104998_audit.py --target https://wp.example.local
```
