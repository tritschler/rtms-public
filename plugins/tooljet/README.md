# ToolJet — CVE-2026-137536 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **ToolJet** low-code platform instance is affected by **CVE-2026-137536** (CVSS 9.3, Critical), an authentication bypass vulnerability in the server OAuth SSO sign-in module.

## Affected & Fixed Versions
| Product | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| ToolJet | `< 3.21.94-beta` (`<= 3.21.93`) | `3.21.94-beta` / `3.21.94+` |

## Usage
```bash
python3 plugins/tooljet/tooljet_cve_2026_137536_audit.py --target https://tooljet.example.local
```
