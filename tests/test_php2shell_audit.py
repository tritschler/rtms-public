"""
test_php2shell_audit.py - Unit tests for PHP Core Stale Global State RCE Audit Tool (CVE-2026-109619 / PHP2Shell).
"""

import pytest
from unittest.mock import MagicMock, patch

from plugins.php2shell.php2shell_cve_2026_109619_audit import (
    PHP2ShellAuditPlugin,
    parse_php_version,
    is_php_version_vulnerable,
    DEFAULT_WEB_PORTS
)


def test_plugin_metadata():
    plugin = PHP2ShellAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-109619"
    assert plugin.info["severity"] == "CRITICAL"
    assert "PHP" in plugin.info["name"]
    assert "1.0.0" == plugin.info["version"]


def test_version_parsing():
    assert parse_php_version("PHP/8.3.12") == (8, 3, 12, "8.3.12")
    assert parse_php_version("Apache/2.4.52 (Ubuntu) PHP/8.2.14") == (8, 2, 14, "8.2.14")
    assert parse_php_version("PHP/8.4.26-1ubuntu2.4") == (8, 4, 26, "8.4.26")
    assert parse_php_version("PHP 7.4.33") == (7, 4, 33, "7.4.33")
    assert parse_php_version("nginx/1.22.0") is None
    assert parse_php_version("") is None


def test_version_vulnerability_logic():
    # EOL versions (< 8.2) are vulnerable
    vuln, _ = is_php_version_vulnerable(7, 4, 33)
    assert vuln is True
    vuln, _ = is_php_version_vulnerable(8, 1, 2)
    assert vuln is True
    vuln, _ = is_php_version_vulnerable(5, 6, 40)
    assert vuln is True

    # 8.2 branch: fixed in 8.2.35
    vuln, _ = is_php_version_vulnerable(8, 2, 34)
    assert vuln is True
    vuln, _ = is_php_version_vulnerable(8, 2, 35)
    assert vuln is False
    vuln, _ = is_php_version_vulnerable(8, 2, 36)
    assert vuln is False

    # 8.3 branch: fixed in 8.3.36
    vuln, _ = is_php_version_vulnerable(8, 3, 35)
    assert vuln is True
    vuln, _ = is_php_version_vulnerable(8, 3, 36)
    assert vuln is False
    vuln, _ = is_php_version_vulnerable(8, 3, 37)
    assert vuln is False

    # 8.4 branch: fixed in 8.4.27
    vuln, _ = is_php_version_vulnerable(8, 4, 26)
    assert vuln is True
    vuln, _ = is_php_version_vulnerable(8, 4, 27)
    assert vuln is False

    # 8.5 branch: fixed in 8.5.12
    vuln, _ = is_php_version_vulnerable(8, 5, 11)
    assert vuln is True
    vuln, _ = is_php_version_vulnerable(8, 5, 12)
    assert vuln is False

    # Future releases (8.6+) are safe
    vuln, _ = is_php_version_vulnerable(8, 6, 0)
    assert vuln is False


def test_check_requirements():
    plugin = PHP2ShellAuditPlugin()

    # Ports as list
    assert plugin.check_requirements("10.0.0.1", [80, 443]) is True
    assert 80 in plugin.discovered_ports
    assert 443 in plugin.discovered_ports

    # Service dict
    services = {
        8080: {"name": "http-alt"},
        9000: {"name": "php-fpm"},
        22: {"name": "ssh"}
    }
    assert plugin.check_requirements("10.0.0.1", services) is True
    assert 8080 in plugin.discovered_ports
    assert 9000 in plugin.discovered_ports
    assert 22 not in plugin.discovered_ports

    # Non-web ports
    assert plugin.check_requirements("10.0.0.1", [22, 21, 25]) is False
    assert plugin.discovered_ports == []


def test_inspect_target_port_vulnerable_x_powered_by(mocker):
    plugin = PHP2ShellAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 80,
        "status_code": 200,
        "headers": {"x-powered-by": "PHP/8.3.12"},
        "body_snippet": "<html>Home</html>"
    })

    hit = plugin.inspect_target_port("192.168.1.100", 80)
    assert hit is not None
    assert hit["php_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "8.3.12"
    assert "8.3.36" in hit["reason"]


def test_inspect_target_port_patched(mocker):
    plugin = PHP2ShellAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "status_code": 200,
        "headers": {"x-powered-by": "PHP/8.3.36"},
        "body_snippet": "<html>Home</html>"
    })

    hit = plugin.inspect_target_port("192.168.1.100", 443)
    assert hit is not None
    assert hit["php_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["version"] == "8.3.36"
    assert "patched" in hit["reason"]


def test_inspect_target_port_server_header(mocker):
    plugin = PHP2ShellAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8080,
        "status_code": 200,
        "headers": {"server": "Apache/2.4.58 (Unix) PHP/8.2.14"},
        "body_snippet": "<html>Dashboard</html>"
    })

    hit = plugin.inspect_target_port("192.168.1.100", 8080)
    assert hit is not None
    assert hit["php_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "8.2.14"


def test_inspect_target_port_concealed_version(mocker):
    plugin = PHP2ShellAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 80,
        "status_code": 200,
        "headers": {"set-cookie": "PHPSESSID=da39a3ee5e6b4b0d3255bfef95601890afd80709; path=/"},
        "body_snippet": "<html>Login</html>"
    })

    hit = plugin.inspect_target_port("192.168.1.100", 80)
    assert hit is not None
    assert hit["php_detected"] is True
    assert hit["concealed"] is True
    assert "expose_php = Off" in hit["reason"]


def test_run_audit_vulnerable_target(mocker):
    plugin = PHP2ShellAuditPlugin()
    plugin.discovered_ports = [80]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 80,
        "php_detected": True,
        "version": "8.3.15",
        "source": "Header 'X-Powered-By: PHP/8.3.15'",
        "is_vulnerable": True,
        "reason": "PHP 8.3.15 is vulnerable to CVE-2026-109619 (requires >= 8.3.36)."
    })

    res = plugin.run_audit("10.0.0.50", [80])
    assert res["status"] == "Vulnerable"
    assert res["severity"] == "CRITICAL"
    assert "CVE-2026-109619" in res["proof"]
    assert "8.3.15" in res["details"]
    assert "8.3.36" in res["details"]


def test_run_audit_safe_target(mocker):
    plugin = PHP2ShellAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "php_detected": True,
        "version": "8.4.27",
        "source": "Header 'X-Powered-By: PHP/8.4.27'",
        "is_vulnerable": False,
        "reason": "PHP 8.4.27 is patched against CVE-2026-109619 (patched in 8.4.27+)."
    })

    res = plugin.run_audit("10.0.0.51", [443])
    assert res["status"] == "OK"
    assert "patched versions" in res["details"]
