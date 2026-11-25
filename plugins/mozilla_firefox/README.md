# Mozilla Firefox, Firefox ESR & Thunderbird Sandbox Escape Auditor (CVE-2026-135597..CVE-2026-135501)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.6_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--135597-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Mozilla Firefox**, **Firefox ESR**, **Headless Firefox / GeckoDriver / Selenium Grid**, and **Mozilla Thunderbird** endpoints against the November 2026 Mozilla security advisories (`< 161.0`, `ESR < 153.8`, and `ESR < 115.46`, covering 18 critical sandbox escape CVEs).

---

## 🔍 Advisory Overview (18 Critical CVEs — CVSS 9.6)

### Fixed in Firefox 161, Firefox ESR 115.46, Firefox ESR 153.8, Thunderbird 161 & 153.8
* **CVE-2026-135547**, **CVE-2026-135530**, **CVE-2026-135525**, **CVE-2026-135521**, **CVE-2026-135520**, **CVE-2026-135509**, **CVE-2026-135508** (`CVSS 9.6 Critical`): Sandbox escape vulnerabilities in DOM Networking, HTTP, WebRender, DOM Navigation, CanvasWebGL, and Graphics.

### Fixed in Firefox 161, Firefox ESR 153.8, Thunderbird 161 & 153.8
* **CVE-2026-135597**, **CVE-2026-135596**, **CVE-2026-135571**, **CVE-2026-135529**, **CVE-2026-135519**, **CVE-2026-135506** (`CVSS 9.6 Critical`): Sandbox escape vulnerabilities in DOM Navigation, WebRender, Panning and Zooming, Graphics: Text, and Networking.

### Fixed in Firefox 161 & Thunderbird 161
* **CVE-2026-135582**, **CVE-2026-135578**, **CVE-2026-135513**, **CVE-2026-135510**, **CVE-2026-135501** (`CVSS 9.6 Critical`): Sandbox escape vulnerabilities in Networking: HTTP, Machine Learning: On Device, and Audio/Video: cubeb.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Mozilla Firefox / Thunderbird** | `< 161.0` | `>= 161.0` |
| **Mozilla Firefox ESR / Thunderbird 153.x** | `< 153.8` | `>= 153.8` |
| **Mozilla Firefox ESR 115.x** | `< 115.46` | `>= 115.46` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/mozilla_firefox/mozilla_firefox_cve_2026_135597_audit.py selenium-grid.internal.corp -p 4444 9222 3000
```
