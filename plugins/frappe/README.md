# Frappe Framework — CVE-2026-137550 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **Frappe Framework** (or ERPNext) deployment is affected by **CVE-2026-137550** (CVSS 9.3, Critical), a missing authorization check in `Document.update()`.

## Affected & Fixed Versions
| Release Branch | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Frappe Framework `<= 15.x` | `< 15.122.0` | `15.122.0` |
| Frappe Framework `16.x` | `16.0.0` to `< 16.50.0` | `16.50.0` |

## Usage
```bash
python3 plugins/frappe/frappe_cve_2026_137550_audit.py --target https://frappe.example.local
```
