# Pulp pulp_python — CVE-2026-126984 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **Pulp `pulp_python`** repository plugin deployment is affected by **CVE-2026-126984** (CVSS 10.0, Critical), a Server-Side Request Forgery (SSRF) and credential leak vulnerability in `get_remote_artifact_url()`.

## Affected & Fixed Versions
| Release Branch | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| `pulp_python` `3.6`–`3.11` | `3.6.0` to `< 3.11.10` | `3.11.10` |
| `pulp_python` `3.12.x` | `3.12.0` to `< 3.12.11` | `3.12.11` |
| `pulp_python` `3.13.x` | `3.13.0` to `< 3.13.9` | `3.13.9` |
| `pulp_python` `3.14`–`3.19` | `3.14.0` to `< 3.19.8` | `3.19.8` |
| `pulp_python` `3.20`–`3.27` | `3.20.0` to `< 3.27.10` | `3.27.10` |
| `pulp_python` `3.28`–`3.36` | `3.28.0` to `< 3.36.7` | `3.36.7` |
| `pulp_python` `3.37`–`3.38` | `3.37.0` to `< 3.38.2` | `3.38.2` |

## Usage
```bash
python3 plugins/pulp_python/pulp_python_cve_2026_126984_audit.py --target https://pulp.example.local
```
