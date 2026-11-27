# HKUDS nanobot — CVE-2026-137463 Passive Version Audit

## Overview
Passive compliance plugin verifying whether an **HKUDS nanobot** instance is affected by **CVE-2026-137463** (CVSS 9.1, Critical), an improper TLS certificate and hostname validation vulnerability in the OpenAI Codex provider retry path.

## Affected & Fixed Versions
| Product | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| HKUDS `nanobot` | `0.1.4` to `< 0.4.1` | `0.4.1` |

## Usage
```bash
python3 plugins/hkuds_nanobot/hkuds_nanobot_cve_2026_137463_audit.py --target https://nanobot.example.local
```
