# WooCommerce Hello Clever Gateway — CVE-2026-136113 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress/WooCommerce site running **Hello Clever Gateway for WooCommerce** (`cleverpay-gateway`) is affected by **CVE-2026-136113** (CVSS 9.3, Critical), an SQL injection vulnerability.

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Hello Clever Gateway for WooCommerce (`cleverpay-gateway`) | `<= 1.8.4` | `1.8.5+` |

## Usage
```bash
python3 plugins/wordpress/wp_hello_clever_gateway/wp_hello_clever_gateway_cve_2026_136113_audit.py --target https://wp.example.local
```
