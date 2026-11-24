# FFmpeg libavfilter (`vf_deband` & `dynaudnorm`) Version Compliance Auditor (CVE-2026-135736 / CVE-2026-135743)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.2_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--135736-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **FFmpeg** media servers, streaming backends, and transcoding services against **CVE-2026-135736** and **CVE-2026-135743**.

---

## 🔍 Advisory Overview

* **CVE-2026-135736** (`CVSS 9.2 Critical`): Heap out-of-bounds read and write vulnerability in `libavfilter/vf_deband.c` in FFmpeg `4.4` before `9.1` triggered via runtime coupling commands.
* **CVE-2026-135743** (`CVSS 9.2 Critical`): Heap out-of-bounds read and write vulnerability in the `dynaudnorm` filter (`cqueue_resize()`) in FFmpeg `4.3` before `9.1` when `gausssize` changes at runtime.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **FFmpeg (`vf_deband` — CVE-2026-135736)** | `4.4` to `< 9.1` | `>= 9.1` |
| **FFmpeg (`dynaudnorm` — CVE-2026-135743)** | `4.3` to `< 9.1` | `>= 9.1` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/ffmpeg/ffmpeg_cve_2026_135736_audit.py media.internal.corp -p 8080 8090 8000 9000 443
```
