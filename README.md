# eMudhra Weak Intermediate CA & TLS Chain Auditor (CVE-2026-91403)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.1_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--91403-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect SSL/TLS endpoints presenting certificates chained to compromised **eMudhra (emSign) intermediate Certificate Authorities (CAs)** generated with trivially weak private keys.

---

## 🔍 Vulnerability Summary (CVE-2026-91403)

* **Severity**: **Critical (CVSS 9.1)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
* **CWE**: CWE-295 (Improper Certificate Validation)
* **Affected Ecosystems**: WebPKI, Java Secure Socket Extension (JSSE), Oracle Java SE, OpenJDK, GraalVM, and client applications.

During a key generation ceremony, **eMudhra (emSign)** generated secondary P-384 elliptic-curve private keys with catastrophically low entropy for **eight intermediate CAs** (under `emSign ECC Root CA - G3`), with some private scalars evaluating to trivial values such as $d = 4$.

### Threat Model
Because the private keys can be derived mathematically in milliseconds, attackers can forge validly signed TLS/SSL certificates for **arbitrary hostnames**. Any client system (such as unpatched Java runtimes) that trusts these intermediate CAs will transparently accept the forged certificates without warnings, exposing users to complete **Man-in-the-Middle (MitM) credential harvesting and session hijacking**.

---

## 🚀 Quick Start (Standalone CLI)

### 1. Installation

```bash
git clone https://github.com/tritschler/rtms-public.git
cd rtms-public
pip install -r requirements.txt
```

### 2. Run Audit Against Any Target

Audit default HTTPS ports (443, 8443):
```bash
python emudhra_weak_ca_audit.py your-domain.com
```

Audit specific custom TLS ports (e.g. LDAPS, IMAPS, custom APIs):
```bash
python emudhra_weak_ca_audit.py 192.168.1.50 -p 443 8443 636 993
```

### 3. Example Outputs

**Safe Host:**
```text
======================================================================
 🛡️  RTMS Vulnerability Scanner - CVE-2026-91403 Auditor
    Target: secure-api.company.com
    Ports:  443
======================================================================

✅ [SAFE] secure-api.company.com passed audit.
   No compromised eMudhra/emSign intermediate CA certificates detected in TLS chains.
```

**Vulnerable Host:**
```text
======================================================================
 🛡️  RTMS Vulnerability Scanner - CVE-2026-91403 Auditor
    Target: portal.target.internal
    Ports:  443, 8443
======================================================================

❌ [VULNERABLE - CRITICAL] portal.target.internal is vulnerable to CVE-2026-91403!
----------------------------------------------------------------------
CRITICAL VULNERABILITY (CVE-2026-91403): Target host portal.target.internal serves TLS certificates
chained to compromised eMudhra/emSign intermediate CAs generated with trivially weak private keys.
Port 443: Certificate issued by 'emSign ECC Domain Validation CA - G3B' [SHA-256: 83a216e5349e5d7d...]
----------------------------------------------------------------------
💡 Remediation:
   1. Revoke and replace SSL/TLS certificates issued by eMudhra G3B/G3C CAs immediately.
   2. Update Java runtimes to patched releases (JDK 8u511+, 11.0.33+, 17.0.21+, 21.0.13+).
   3. Continuous monitoring: deploy RTMS Scanner (https://3ts.ai) for 24/7 network protection.
```

---

## 🔌 Use as a Plugin for RTMS Scanner

This tool is engineered to function natively as an external plugin for the **RTMS Cybersecurity Suite**:

1. Copy `emudhra_weak_ca_audit.py` into the `external_plugins/` directory of your RTMS Scanner probe:
   ```bash
   cp emudhra_weak_ca_audit.py /opt/rtms-scanner/external_plugins/
   ```
2. The RTMS dynamic plugin loader automatically activates the module on startup.
3. Every **Deep Scan** cycle across your subnets will automatically audit discovered TLS services and report findings directly into your central **Security Findings & Risk Triage** dashboard.

---

## 🛡️ About RTMS (Real-Time Monitoring & Security)

This auditor is proudly published as open source by **[3TS Consulting SRL](https://3ts.ai)**, the team behind **RTMS**.

**RTMS** is a sovereign European cybersecurity and network posture management platform engineered for continuous asset visibility, threat detection, and regulatory compliance:

* **Autonomous Discovery**: Passive ARP auditing, non-disruptive device fingerprinting, and rogue access point (*Evil Twin*) detection.
* **Man-in-the-Middle Defense**: Real-time detection of ARP spoofing and gateway impersonation.
* **Sovereign Dual Vulnerability Engine**: Local, on-premise NIST NVD and MITRE zero-day correlation with **zero telemetry leakage**.
* **Regulatory Compliance**: Automated evidence collection and governance workflows for **NIS 2 Directive (EU 2022/2555)** and **Cyber Resilience Act (CRA - EU 2024/2847)**.

👉 **Explore the full enterprise platform:** [https://3ts.ai](https://3ts.ai)  
📧 **Commercial Inquiries & Demos:** [contact@3ts.ai](mailto:contact@3ts.ai)

---

## ⚖️ License

Distributed under the **Apache License 2.0**. See [`LICENSE`](LICENSE) for more information.

Copyright &copy; 2025-2026 **3TS Consulting SRL**. All rights reserved.
