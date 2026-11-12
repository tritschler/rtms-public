# WatchGuard Fireware OS & SonicWall SMA1000 VPN Auditor (CVE-2026-93866 & CVE-2026-83548)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-10.0_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--93866-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WatchGuard Fireware OS (Access Portal / AuthPoint)** and **SonicWall SMA1000** appliances against **CVE-2026-93866**, **CVE-2026-103594**, **CVE-2026-121639**, and **CVE-2026-83548**.

---

## 🔍 Advisory Overview

* **CVE-2026-93866** (`CVSS 9.2 Critical`): Heap buffer overflow in WatchGuard Fireware OS Access Portal WebSocket connection handling.
* **CVE-2026-103594** (`CVSS 9.5 Critical`): Stack-based buffer overflow in WatchGuard Fireware OS WireGuard configuration processing.
* **CVE-2026-121639** (`CVSS 9.2 Critical`): Missing authentication for critical function in WatchGuard AuthPoint Gateway.
* **CVE-2026-83548** (`CVSS 10.0 Critical`): Pre-authentication SSRF in SonicWall SMA1000 (`SMA6210`, `SMA7210`, `SMA8200v`) WorkPlace interface.

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/watchguard_fireware/watchguard_fireware_cve_2026_93866_audit.py vpn.internal.corp -p 443 4100 8443
```
