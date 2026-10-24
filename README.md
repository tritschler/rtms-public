# eMudhra Weak Intermediate CA & TLS Chain Auditor (CVE-2026-91403)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
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

## 🐘 PHP Core Stale Global State RCE Auditor (CVE-2026-109619 / PHP2Shell)

[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.2_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--109619-orange.svg)]()

Audits web applications, API endpoints, and FastCGI/PHP-FPM services for PHP runtime versions affected by **CVE-2026-109619** ("PHP2Shell").

### Vulnerability Summary
* **Severity**: **Critical (CVSS 9.2)** — CWE-416 (Use-After-Free) / CWE-672 (Stale State)
* **Affected PHP Branches**:
  * PHP < 8.2.35 (including all EOL branches 5.x, 7.x, 8.0, 8.1)
  * PHP 8.3.0 through 8.3.35 (fixed in **8.3.36**)
  * PHP 8.4.0 through 8.4.26 (fixed in **8.4.27**)
  * PHP 8.5.0 through 8.5.11 (fixed in **8.5.12**)
* **Mechanism**: Stale global state pointers pointing to freed request memory persist across abnormal request termination, allowing subsequent requests to reuse memory and achieve arbitrary Remote Code Execution (RCE).

### Usage (Standalone CLI)
```bash
# Audit standard HTTP/HTTPS ports (80, 443, 8080, 8443)
python php2shell_cve_2026_109619_audit.py target-server.com

# Audit custom web or FastCGI ports
python php2shell_cve_2026_109619_audit.py 192.168.1.10 -p 80 443 8000 8088 8888 9000
```

---

## 🔌 Use as a Plugin for RTMS Scanner

This repository's audit tools are engineered to function natively as external plugins for the **RTMS Cybersecurity Suite**:

1. Copy the audit scripts into the `external_plugins/` directory of your RTMS Scanner probe:
   ```bash
   cp emudhra_weak_ca_audit.py /opt/rtms-scanner/external_plugins/
   cp php2shell_cve_2026_109619_audit.py /opt/rtms-scanner/external_plugins/
   ```
2. The RTMS dynamic plugin loader automatically validates AST security constraints and activates the modules on startup.
3. Use the web console (Targeted Plugin Audit modal in **Asset Management** or **Plugins**) or run automated **Deep Scans** across your subnets to continuously evaluate infrastructure.

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

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.

Copyright &copy; 2026 **RTMS Project Contributors**.
