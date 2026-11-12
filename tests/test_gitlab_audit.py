"""
test_gitlab_audit.py - Unit tests for GitLab CE/EE Version Compliance Audit (CVE-2026-110264 & CVE-2026-85706).
"""

from plugins.gitlab.gitlab_cve_2026_110264_audit import (
    GitLabAuditPlugin,
    parse_gitlab_version,
    is_gitlab_version_vulnerable,
)


def test_plugin_metadata():
    plugin = GitLabAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-110264"
    assert plugin.info["severity"] == "CRITICAL"
    assert "GitLab" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_gitlab_version('{"version":"19.3.2-ee","revision":"abcdef"}') == (19, 3, 2, "19.3.2")
    assert parse_gitlab_version('gon.version = "19.4.1";') == (19, 4, 1, "19.4.1")
    assert parse_gitlab_version("GitLab Community Edition 19.2.6") == (19, 2, 6, "19.2.6")
    assert parse_gitlab_version("nginx/1.24.0") is None


def test_version_vulnerability_logic():
    vuln_191, reason_191 = is_gitlab_version_vulnerable(19, 1, 5)
    assert vuln_191 is True
    assert "CVE-2026-110264" in reason_191

    vuln_192, _ = is_gitlab_version_vulnerable(19, 2, 8)
    assert vuln_192 is True

    safe_192, _ = is_gitlab_version_vulnerable(19, 2, 9)
    assert safe_192 is False

    vuln_193, _ = is_gitlab_version_vulnerable(19, 3, 5)
    assert vuln_193 is True

    safe_193, _ = is_gitlab_version_vulnerable(19, 3, 6)
    assert safe_193 is False

    vuln_194, _ = is_gitlab_version_vulnerable(19, 4, 2)
    assert vuln_194 is True

    safe_194, _ = is_gitlab_version_vulnerable(19, 4, 3)
    assert safe_194 is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = GitLabAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "19.3.2",
            "source": "GitLab API v4 /version metadata",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-110264",
        },
    )
    res = plugin.run_audit("10.0.0.10", [443])
    assert res["status"] == "Vulnerable"
    assert "19.3.2" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "19.4.3",
            "source": "GitLab API v4 /version metadata",
            "is_vulnerable": False,
            "reason": "Patched >= 19.4.3",
        },
    )
    res_safe = plugin.run_audit("10.0.0.10", [443])
    assert res_safe["status"] == "OK"
