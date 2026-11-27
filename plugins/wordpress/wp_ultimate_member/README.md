# WordPress Ultimate Member — CVE-2026-134481 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress installation running the **Ultimate Member** plugin (`ultimate-member`) is affected by **CVE-2026-134481** (CVSS 9.8, Critical), a deserialization of untrusted data (PHP Object Injection) vulnerability.

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Ultimate Member (`ultimate-member`) | `<= 2.14.1` | `2.14.2+` |

## Usage
```bash
python3 plugins/wordpress/wp_ultimate_member/wp_ultimate_member_cve_2026_134481_audit.py --target https://wp.example.local
```
