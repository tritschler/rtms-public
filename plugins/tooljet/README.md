# ToolJet — CVE-2026-137536 & CVE-2026-137964 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **ToolJet** low-code platform deployment is affected by **CVE-2026-137536** (CVSS 9.3, Critical, OAuth SSO authentication bypass) and **CVE-2026-137964** (CVSS 9.3, Critical, command injection prior to `3.21.96-LTS`).

## Affected & Fixed Versions
| Product | CVE | Affected Versions | Patched Version |
| :--- | :--- | :--- | :--- |
| ToolJet | CVE-2026-137536 | `< 3.21.94-beta` (`<= 3.21.93`) | `3.21.94-beta+` |
| ToolJet | CVE-2026-137964 | `< 3.21.96-LTS` (`<= 3.21.95`) | `3.21.96-LTS+` |

## Usage
```bash
python3 plugins/tooljet/tooljet_cve_2026_137536_audit.py --target https://tooljet.example.local
```
