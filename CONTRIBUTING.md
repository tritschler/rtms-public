# Contributing Security Plugins to RTMS Public

Welcome to the **RTMS Community Plugins** repository! We are excited to collaborate with cybersecurity researchers, penetration testers, systems engineers, and network administrators.

This guide provides the complete technical specification and developer requirements for creating, testing, and submitting a new security audit plugin.

---

## 🎯 Dual-Execution Philosophy

Every plugin in `rtms-public` is engineered with a **dual-execution design**:
1. **Standalone CLI Mode**: Can be invoked directly from the terminal without any dependencies on the RTMS server infrastructure (`python plugins/my_plugin/my_plugin_audit.py <target>`).
2. **RTMS Scanner Native Engine**: Automatically discovered, validated, and executed during continuous **Deep Scan** cycles or targeted surgical IP audits across monitored enterprise subnets.

---

## 📋 The `BasePlugin` Technical Specification

To integrate with the RTMS scanning pipeline, every plugin script must adhere to the following contract.

### 1. Class Inheritance & Standalone Fallback
The script must define a class inheriting from `BasePlugin`. To support standalone CLI execution without the RTMS core installed, include the standard fallback block:

```python
try:
    from base_plugin import BasePlugin
except ImportError:
    class BasePlugin:  # type: ignore
        def __init__(self):
            self.info = {}
        def format_result(self, status: str, proof: str = "", details: str = ""):
            return {"plugin": self.info.get("name", "Unknown"), "status": status, "proof": proof, "details": details}
```

### 2. Plugin Metadata (`self.info`)
In `__init__()`, populate `self.info` with the following mandatory keys:

| Key | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `name` | `str` | Human-readable title of the audit | `"PHP Core Stale Global State RCE (PHP2Shell)"` |
| `description` | `str` | High-level explanation of the vulnerability and impact | `"Audits web endpoints for PHP runtime instances..."` |
| `severity` | `str` | Standard severity rating: `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"INFO"` | `"CRITICAL"` |
| `cve` | `Optional[str]` | The official CVE identifier or `None` for general audits | `"CVE-2026-109619"` |
| `version` | `str` | Semantic version string | `"1.0.0"` |

### 3. Pre-Flight Requirement Check (`check_requirements`)
```python
def check_requirements(self, target_ip: str, target_services: Any) -> bool:
```
* **Purpose**: Evaluates whether the target host is eligible for the audit (e.g. checks if target ports are open).
* **Return Value**: `True` if the audit should proceed; `False` to skip the target without sending network traffic.
* **Input Types**: `target_services` is typically a `set` or `list` of open port integers (e.g. `{80, 443}`) or a `dict` mapping port to service banner.

### 4. Audit Execution (`run_audit`)
```python
def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
```
* **Purpose**: Performs non-destructive, safe network inspection to verify if the vulnerability is present.
* **Return Value**: Must use `self.format_result(status, proof, details)`:
  * `status`:
    * `"Vulnerable"`: Flaw confirmed. Triggers an alert in the RTMS console.
    * `"Safe"`: Target inspected and verified not vulnerable.
    * `"Skipped"`: Pre-conditions not met or target not responsive.
    * `"Error"`: Gracefully caught network error or timeout.
  * `proof`: String containing technical evidence (e.g., extracted banner, response header, certificate fingerprint).
  * `details`: Explanatory description of the finding.

---

## 🛡️ AST Security Guardrails

All plugins undergo static AST (**Abstract Syntax Tree**) validation before execution. Code violating these rules will be rejected by `PluginCodeValidator`:

* ❌ **Forbidden Modules**: `subprocess`, `ctypes`, `shutil`, `pty`, `pickle`, `posix`, `winreg`.
* ❌ **Forbidden Builtin Calls**: `eval()`, `exec()`, `compile()`, `__import__()`.
* ❌ **Forbidden System Methods**: `os.system()`, `os.popen()`, `os.spawn*()`, `os.kill()`, `os.remove()`, `os.rmdir()`.
* ❌ **Forbidden Filesystem Write / Tampering Operations**: Opening files in write/append mode (`open(..., 'w'/'wb'/'a'/'w+')`), `Path.write_bytes()`, `Path.write_text()`, `os.rename()`, `os.chmod()`, `truncate()`. Security audit plugins are strictly read-only.
* ✅ **Allowed Networking & Parsing Modules**: `socket`, `ssl`, `http.client`, `urllib`, `requests`, `cryptography`, `hashlib`, `re`, `json`, `datetime`, `struct`, `bs4`, etc.

---

## 📝 Complete Plugin Boilerplate Template

```python
"""
my_cve_audit.py - Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits target hosts for CVE-2026-XXXXX.
"""

import socket
import ssl
from typing import Dict, Any, Set

try:
    from base_plugin import BasePlugin
except ImportError:
    class BasePlugin:  # type: ignore
        def __init__(self):
            self.info: Dict[str, Any] = {}
        def format_result(self, status: str, proof: str = "", details: str = "") -> Dict[str, Any]:
            return {"plugin": self.info.get("name", "Unknown"), "severity": self.info.get("severity", "Info"), "status": status, "proof": proof, "details": details}


class MyVulnerabilityAuditPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.info = {
            "name": "My Critical Vulnerability Audit (CVE-2026-XXXXX)",
            "description": "Audits endpoints for exposure to CVE-2026-XXXXX.",
            "severity": "CRITICAL",
            "cve": "CVE-2026-XXXXX",
            "version": "1.0.0"
        }
        self.target_ports = [80, 443, 8080]

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        ports = target_services if isinstance(target_services, (set, list)) else []
        return any(p in ports for p in self.target_ports)

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        try:
            is_vulnerable = False
            evidence = ""

            # Perform non-destructive probe...

            if is_vulnerable:
                return self.format_result(
                    status="Vulnerable",
                    proof=evidence,
                    details=f"Target {target_ip} is vulnerable to {self.info['cve']}."
                )
            return self.format_result(
                status="Safe",
                details="Target inspected and verified not vulnerable."
            )
        except Exception as e:
            return self.format_result(
                status="Error",
                details=f"Audit failed due to network exception: {str(e)}"
            )


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    plugin = MyVulnerabilityAuditPlugin()
    print(plugin.run_audit(host, {443}))
```

---

## 📂 Directory Layout & Contributions Checklist

When contributing a new plugin to `rtms-public`:

1. **Create Subdirectory**:
   ```text
   plugins/
   └── <plugin_slug>/
       ├── README.md               # Technical breakdown (CVE, CVSS, affected versions, remediation)
       └── <plugin_slug>_audit.py  # The plugin script
   ```

2. **Add Unit Tests**:
   Create a test file in `tests/test_<plugin_slug>.py` with mocked network calls:
   ```bash
   uv run --extra dev pytest tests/
   ```

3. **Submit a Pull Request**:
   * Ensure all unit tests pass with zero warnings.
   * Provide a concise PR description highlighting the CVE, CVSS score, and affected software.
