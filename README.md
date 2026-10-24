# RTMS Community Security Plugins & Fast-Response Auditors

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/Platform-RTMS_Suite-blue.svg)](https://3ts.ai)
[![Ecosystem](https://img.shields.io/badge/Ecosystem-Open_Source_Security-orange.svg)]()

Welcome to the official **RTMS Community Plugins** repository. This open-source hub contains standalone security audit tools and modular detection plugins engineered for the **[RTMS Cybersecurity Suite](https://3ts.ai)** (Real-Time Monitoring & Security).

Each plugin is developed to provide rapid, reliable, and non-destructive detection of critical emerging vulnerabilities, zero-days, and cryptographic flaws across enterprise networks.

---

## 📚 Available Security Plugins

| Plugin Name | Target CVE | Severity | Affected Systems | Plugin Directory | Quick Audit Command |
|:---|:---:|:---:|:---|:---:|:---|
| **eMudhra Weak Intermediate CA Audit** | **CVE-2026-91403** | `CRITICAL 9.1` | WebPKI, Java JSSE, TLS endpoints | [`plugins/emudhra_weak_ca/`](plugins/emudhra_weak_ca/) | `python plugins/emudhra_weak_ca/emudhra_weak_ca_audit.py <target>` |
| **PHP Core Stale Global State RCE Audit (PHP2Shell)** | **CVE-2026-109619** | `CRITICAL 9.2` | PHP 5.4 to 8.5.11, FastCGI, PAN-OS | [`plugins/php2shell/`](plugins/php2shell/) | `python plugins/php2shell/php2shell_cve_2026_109619_audit.py <target>` |

---

## 🗂️ Repository Structure

The repository follows a clean, modular structure where each plugin is self-contained with its dedicated technical documentation:

```text
rtms-public/
├── LICENSE                                # MIT Open-Source License
├── README.md                              # This catalog & community guide
├── pyproject.toml                         # Unified test & package configuration
├── requirements.txt                       # Consolidated Python dependencies
│
├── plugins/                               # Dedicated security plugins directory
│   ├── emudhra_weak_ca/                   # eMudhra Weak Intermediate CA Audit (CVE-2026-91403)
│   │   ├── README.md                      # Detailed vulnerability analysis & guidance
│   │   └── emudhra_weak_ca_audit.py       # Standalone CLI & RTMS BasePlugin script
│   │
│   └── php2shell/                         # PHP Core Stale Global State RCE (CVE-2026-109619)
│       ├── README.md                      # Detailed vulnerability analysis & guidance
│       └── php2shell_cve_2026_109619_audit.py # Standalone CLI & RTMS BasePlugin script
│
├── tests/                                 # Automated unit test suite
│   ├── test_audit.py                      # Tests for eMudhra CA auditor
│   └── test_php2shell_audit.py            # Tests for PHP2Shell auditor
│
├── emudhra_weak_ca_audit.py               # Root backward-compatibility wrapper
└── php2shell_cve_2026_109619_audit.py     # Root backward-compatibility wrapper
```

---

## 🚀 Quick Start (Standalone CLI Mode)

All plugins in this repository can be run directly from any terminal without requiring an active RTMS server deployment:

### 1. Installation

```bash
git clone https://github.com/tritschler/rtms-public.git
cd rtms-public
pip install -r requirements.txt
```

### 2. Running an Audit

You can execute plugins directly from their respective directory or from the repository root:

```bash
# Audit a host for compromised eMudhra intermediate TLS certificates (CVE-2026-91403)
python plugins/emudhra_weak_ca/emudhra_weak_ca_audit.py target-server.com -p 443 8443

# Audit a host for vulnerable PHP core runtime instances (CVE-2026-109619 / PHP2Shell)
python plugins/php2shell/php2shell_cve_2026_109619_audit.py 192.168.1.10 -p 80 443 8080 9000
```

---

## 🔌 Integration with RTMS Cybersecurity Suite

Plugins from this repository integrate natively with **RTMS Suite**:

### Option 1: File Drop into RTMS Scanner Probe
1. Copy desired plugin scripts into the `external_plugins/` directory of your scanner probe:
   ```bash
   cp plugins/php2shell/php2shell_cve_2026_109619_audit.py /opt/rtms-scanner/external_plugins/
   ```
2. The dynamic RTMS plugin loader automatically analyzes code via AST security guardrails and activates the plugin.
3. Every **Deep Scan** cycle across monitored subnets will automatically execute the checks and post findings to your dashboard.

### Option 2: Upload via RTMS Web UI
1. Navigate to **Administration > Plugins** in the RTMS Web Console.
2. Upload the Python plugin file.
3. The plugin immediately becomes available for:
   * **Automated subnet discovery cycles**
   * **Targeted Plugin Audits (Surgical IP Verification)** directly from **Asset Management** or the **Plugins Catalog**.

---

## 🛠️ Contributing a New Plugin

We welcome contributions from security researchers, network engineers, and system administrators! To submit a new detection plugin:

1. **Create a Dedicated Plugin Directory**:
   ```bash
   mkdir plugins/my_vulnerability_audit
   ```
2. **Implement your Plugin adhering to the RTMS `BasePlugin` Contract**:
   * Must declare a class inheriting from `BasePlugin`.
   * Must initialize `self.info` in `__init__` with `name`, `description`, `severity`, `cve`, `version`.
   * Must implement `check_requirements(self, target_ip, target_services) -> bool`.
   * Must implement `run_audit(self, target_ip, target_services, credentials=None) -> Dict[str, Any]`.
   * Include standard fallback class for standalone CLI execution (`if __name__ == "__main__":`).
3. **AST Security Compliance**:
   All plugins undergo static AST validation via `PluginCodeValidator`:
   * ❌ Forbidden modules: `subprocess`, `ctypes`, `shutil`, `pty`, `pickle`, `posix`, `winreg`.
   * ❌ Forbidden builtins: `eval()`, `exec()`, `compile()`, `__import__()`.
   * ❌ Forbidden system methods: `os.system()`, `os.popen()`, `os.kill()`.
4. **Document your Plugin**:
   Add a detailed `README.md` inside your plugin folder explaining the CVE, CVSS score, threat model, CLI examples, and remediation.
5. **Add Automated Unit Tests**:
   Add unit tests in `tests/test_my_vulnerability_audit.py` with mock network responses. Ensure tests pass:
   ```bash
   pytest tests/
   ```

---

## 🛡️ About RTMS (Real-Time Monitoring & Security)

Published with ❤️ by **[3TS Consulting SRL](https://3ts.ai)**, the team behind **RTMS**.

**RTMS** is a sovereign European cybersecurity and network posture management platform engineered for continuous asset visibility, threat detection, and regulatory compliance:
* **Zero Telemetry Leakage**: On-premise air-gapped vulnerability correlation.
* **Continuous Asset Discovery**: Passive ARP auditing, rogue AP (*Evil Twin*) detection, and non-disruptive fingerprinting.
* **Compliance Assurance**: Automated evidence collection and governance workflows for **NIS 2 Directive (EU 2022/2555)** and **Cyber Resilience Act (CRA - EU 2024/2847)**.

👉 **Explore the full enterprise platform:** [https://3ts.ai](https://3ts.ai)  
📧 **Contact & Security Inquiries:** [contact@3ts.ai](mailto:contact@3ts.ai)

---

## ⚖️ License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

Copyright &copy; 2026 **RTMS Project Contributors / 3TS Consulting SRL**.
