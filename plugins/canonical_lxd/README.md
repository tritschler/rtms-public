# Canonical LXD & pylxd — CVE-2026-135384 / CVE-2026-127163 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **Canonical LXD** daemon or **pylxd** deployment is affected by **CVE-2026-135384** (CVSS 9.2, OIDC bearer token verification authentication bypass in LXD) and **CVE-2026-127163** (CVSS 9.1, improper WebSocket certificate validation in `pylxd`).

## Affected & Fixed Versions
| Component | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Canonical LXD `5.0.x` | `< 5.0.12` | `5.0.12` |
| Canonical LXD `5.21.x` | `< 5.21.10` | `5.21.10` |
| Canonical LXD `6.x` | `< 6.10.2` | `6.10.2` |
| Canonical `pylxd` | `< 2.4.3` | `2.4.3` |

## Usage
```bash
python3 plugins/canonical_lxd/canonical_lxd_cve_2026_135384_audit.py --target https://lxd.example.local:8443
```
