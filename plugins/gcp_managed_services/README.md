# Google Cloud Platform Managed Services — CVE-2026-106169, CVE-2026-85258 & CVE-2026-110739 Compliance Audit

## Overview
Passive compliance plugin verifying revision-date patch status for **Google Cloud Application Integration** (**CVE-2026-106169**, CVSS 9.4), **Google Cloud Vertex AI Assistant** (**CVE-2026-85258**, CVSS 9.3), and **Google Cloud GKE Fleet** (**CVE-2026-110739**, CVSS 9.0).

## Affected & Fixed Revisions
| Service | CVE | Affected Revisions | Patched Revision |
| :--- | :--- | :--- | :--- |
| Google Cloud Application Integration | CVE-2026-106169 | `< 2026-09-22` | `2026-09-22+` |
| Google Cloud Vertex AI Assistant | CVE-2026-85258 | `< 2026-04-13` | `2026-04-13+` |
| Google Cloud GKE Fleet | CVE-2026-110739 | `< 2026-09-25` | `2026-09-25+` |

## Usage
```bash
python3 plugins/gcp_managed_services/gcp_managed_services_cve_2026_106169_audit.py --target gcp-project.local --version 2026-09-25
```
