# Mitel OpenScape 4000 & OpenScape 4000 Manager — CVE-2026-137721 / CVE-2026-137723 / CVE-2026-137724 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **Mitel OpenScape 4000** or **OpenScape 4000 Manager** instance is affected by **CVE-2026-137721** (CVSS 10.0), **CVE-2026-137724** (CVSS 10.0), and **CVE-2026-137723** (CVSS 9.6).

## Affected & Fixed Versions
| Product Branch | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Mitel OpenScape 4000 / Manager `V10` | `<= V10 R1.68` | `V10 R1.69+` |
| Mitel OpenScape 4000 / Manager `V11` | `V11 R0.22` through `V11 R2.11` | `V11 R2.12+` |

## Usage
```bash
python3 plugins/mitel_openscape/mitel_openscape_cve_2026_137721_audit.py --target https://openscape.example.local
```
