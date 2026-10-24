# eMudhra Weak Intermediate CA & TLS Chain Auditor (CVE-2026-91403)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.1_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--91403-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect SSL/TLS endpoints presenting certificates chained to compromised **eMudhra (emSign) intermediate Certificate Authorities (CAs)** generated with catastrophically weak elliptic-curve private keys.

---

## 🔍 Vulnerability Summary (CVE-2026-91403)

* **Severity**: **Critical (CVSS 9.1)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
* **CWE**: CWE-295 (Improper Certificate Validation)
* **Affected Ecosystems**: WebPKI, Java Secure Socket Extension (JSSE), Oracle Java SE, OpenJDK, GraalVM, and client applications.

During a key generation ceremony, **eMudhra (emSign)** generated secondary P-384 elliptic-curve private keys with catastrophically low entropy for **eight intermediate CAs** (under `emSign ECC Root CA - G3`), with some private scalars evaluating to trivial values such as $d = 4$.

### Threat Model
Because the private keys can be derived mathematically in milliseconds, attackers can forge validly signed TLS/SSL certificates for **arbitrary hostnames**. Any client system (such as unpatched Java runtimes) that trusts these intermediate CAs will transparently accept the forged certificates without warnings, exposing users to complete **Man-in-the-Middle (MitM) credential harvesting and session hijacking**.

---

## 📋 Compromised Intermediate CAs & Fingerprints

| Intermediate CA Name | Key Algorithm | SHA-256 Fingerprint (Sample) |
|:---|:---:|:---|
| `emSign ECC Domain Validation CA - G3B` | ECC P-384 | `83a216e5349e5d7d0794eb8e3ef31d51f7bb8a846f4ebca80859549f7d2f9b12` |
| `emSign ECC Domain Validation CA - G3C` | ECC P-384 | `e90145c2ef2619e075039f60a4f5f8b9ec724db31d4791cb8592398414b2d184` |
| `emSign ECC Organization Validation CA - G3B` | ECC P-384 | `17f53a473e659b8c0499d638914619bb32d8479e0a811cae5e1e1273934dca95` |
| `emSign ECC Organization Validation CA - G3C` | ECC P-384 | `296be42194b301c27dd2e185e4c6e91cb340156942ad08e2d46e31cb3016259f` |
| `emSign ECC Extended Validation CA - G3B` | ECC P-384 | `51c684d0b13481239c824e9301da05178f240e1e97682d33458cfd145bc03942` |
| `emSign ECC Extended Validation CA - G3C` | ECC P-384 | `67df2149b1a03975ec024849df01ca9f83a54721eb6281a04791cae508492015` |
| `emSign ECC Code Signing CA - G3B` | ECC P-384 | `73ac10294719bd0182374e019284fca0938471da5019842a0394185721ca9481` |
| `emSign ECC Code Signing CA - G3C` | ECC P-384 | `95be0194857201cba04918471029584729104857201948572019485720194857` |

---

## 🚀 Usage (Standalone CLI)

### Installation

```bash
pip install -r ../../requirements.txt
```

### Run Audit Against Any Target

Audit standard HTTPS ports (443, 8443):
```bash
python emudhra_weak_ca_audit.py your-domain.com
```

Audit custom TLS ports (LDAPS, IMAPS, HTTPS APIs):
```bash
python emudhra_weak_ca_audit.py 192.168.1.50 -p 443 8443 636 993
```

### Exit Codes & Outputs
* **`0`**: Safe host / No compromised intermediate CAs detected.
* **`1`**: Critical vulnerability detected.

**Safe Host Output:**
```text
======================================================================
 🛡️  RTMS Vulnerability Scanner - CVE-2026-91403 Auditor
    Target: secure-api.company.com
    Ports:  443
======================================================================

✅ [SAFE] secure-api.company.com passed audit.
   No compromised eMudhra/emSign intermediate CA certificates detected in TLS chains.
```

**Vulnerable Host Output:**
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

## 💡 Remediation
1. **Revoke and Re-issue Certificates**: Immediately revoke any TLS/SSL certificate signed by the affected eMudhra G3B/G3C intermediate CAs and re-issue from an uncompromised CA.
2. **Update Java Runtimes**: Ensure client and server runtimes are upgraded to the October 2026 Critical Patch Update (JDK 8u511+, 11.0.33+, 17.0.21+, 21.0.13+).
3. **Automate Continuous Auditing**: Use RTMS Scanner for automated network-wide discovery.
