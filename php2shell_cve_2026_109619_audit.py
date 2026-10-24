"""
php2shell_cve_2026_109619_audit.py

Root backward-compatibility proxy for the PHP Core Stale Global State RCE Audit Plugin (CVE-2026-109619 / PHP2Shell).
Canonical implementation is located at: plugins/php2shell/php2shell_cve_2026_109619_audit.py

License: MIT
SPDX-License-Identifier: MIT
Copyright (c) 2026 RTMS Project Contributors / 3TS Consulting SRL
"""

import sys
import os

_repo_root = os.path.dirname(os.path.abspath(__file__))
_plugin_dir = os.path.join(_repo_root, "plugins", "php2shell")
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

from plugins.php2shell.php2shell_cve_2026_109619_audit import (
    PHP2ShellAuditPlugin as _TargetPlugin,
    parse_php_version,
    is_php_version_vulnerable,
    DEFAULT_WEB_PORTS,
    SSL_PORTS,
    PATCHED_THRESHOLDS,
)


class PHP2ShellAuditPlugin(_TargetPlugin, BasePlugin):
    """
    Backward-compatibility proxy class for PHP2ShellAuditPlugin.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "PHP Core Stale Global State RCE Audit (CVE-2026-109619)",
            "description": "Audits HTTP/HTTPS and FastCGI endpoints for PHP runtime instances vulnerable to remote code execution via request-memory stale global state reuse (CVE-2026-109619 / PHP2Shell).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-109619",
            "version": "1.0.0"
        }

    def check_requirements(self, target_ip, target_services):
        return super().check_requirements(target_ip, target_services)

    def run_audit(self, target_ip, target_services, credentials=None):
        return super().run_audit(target_ip, target_services, credentials)


if __name__ == "__main__":
    import runpy
    target_script = os.path.join(_plugin_dir, "php2shell_cve_2026_109619_audit.py")
    runpy.run_path(target_script, run_name="__main__")
