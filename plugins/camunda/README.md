# Camunda 8 — CVE-2026-77230 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **Camunda 8** deployment is affected by **CVE-2026-77230** (CVSS 9.2, Critical), an insecure Java deserialization vulnerability in persistent web sessions.

## Affected & Fixed Versions
| Branch | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Camunda 8.8 | `8.8.0` – `8.8.46` | `8.8.47` |
| Camunda 8.9 | `8.9.0` – `8.9.28` | `8.9.29` |
| Camunda 8.10 | `8.10.0` – `8.10.9` | `8.10.10` |
| Camunda 8.11 | `8.11.0-alpha1` | `8.11.0` |

## Usage
```bash
python3 plugins/camunda/camunda_cve_2026_77230_audit.py --target https://camunda.example.local:8080
```
