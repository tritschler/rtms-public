"""
emudhra_weak_ca_audit.py

Root backward-compatibility proxy for the eMudhra Weak Intermediate CA Audit Plugin (CVE-2026-91403).
Canonical implementation is located at: plugins/emudhra_weak_ca/emudhra_weak_ca_audit.py

License: MIT
SPDX-License-Identifier: MIT
Copyright (c) 2026 RTMS Project Contributors / 3TS Consulting SRL
"""

import sys
import os

_repo_root = os.path.dirname(os.path.abspath(__file__))
_plugin_dir = os.path.join(_repo_root, "plugins", "emudhra_weak_ca")
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

try:
    from base_plugin import BasePlugin
except ImportError:
    class BasePlugin:  # type: ignore
        def __init__(self):
            self.info = {}

        def format_result(self, status: str, proof: str = "", details: str = ""):
            return {
                "plugin": self.info.get("name", "Unknown"),
                "severity": self.info.get("severity", "Info"),
                "status": status,
                "proof": proof,
                "details": details
            }

        def execute(self, target_ip, target_services, credentials=None):
            return self.run_audit(target_ip, target_services, credentials)

from plugins.emudhra_weak_ca.emudhra_weak_ca_audit import (
    EmudhraWeakCAAuditPlugin as _TargetPlugin,
    KNOWN_COMPROMISED_FINGERPRINTS,
    COMPROMISED_EMUDHRA_CAS,
    EMUDHRA_KEYWORDS,
)


class EmudhraWeakCAAuditPlugin(_TargetPlugin, BasePlugin):
    """
    Backward-compatibility proxy class for EmudhraWeakCAAuditPlugin.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "eMudhra Weak Intermediate CA & TLS Chain Audit (CVE-2026-91403)",
            "description": "Audits SSL/TLS services for certificates chained to compromised eMudhra/emSign intermediate CAs generated with trivially weak private keys (CVE-2026-91403).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-91403",
            "version": "1.0.0"
        }

    def check_requirements(self, target_ip, target_services):
        return super().check_requirements(target_ip, target_services)

    def run_audit(self, target_ip, target_services, credentials=None):
        return super().run_audit(target_ip, target_services, credentials)


if __name__ == "__main__":
    import runpy
    target_script = os.path.join(_plugin_dir, "emudhra_weak_ca_audit.py")
    runpy.run_path(target_script, run_name="__main__")
