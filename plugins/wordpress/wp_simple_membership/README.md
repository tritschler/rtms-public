# WordPress Simple Membership — CVE-2026-133951 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a WordPress installation running the **Simple Membership** plugin (`simple-membership`) is affected by **CVE-2026-133951** (CVSS 9.1, Critical), a privilege escalation vulnerability caused by weak signing key generation (`uniqid`).

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Simple Membership (`simple-membership`) | `<= 4.8.9` | `4.8.10+` |

## Usage
```bash
python3 plugins/wordpress/wp_simple_membership/wp_simple_membership_cve_2026_133951_audit.py --target https://wp.example.local
```
