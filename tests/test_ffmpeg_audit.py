"""
test_ffmpeg_audit.py - Unit tests for FFmpeg libavfilter Heap Out-of-Bounds
Compliance Audit (CVE-2026-135736 / CVE-2026-135743).
"""

from plugins.ffmpeg.ffmpeg_cve_2026_135736_audit import (
    FFmpegAuditPlugin,
    parse_ffmpeg_version,
    is_ffmpeg_version_vulnerable,
)


def test_plugin_metadata():
    plugin = FFmpegAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-135736"
    assert plugin.info["severity"] == "CRITICAL"
    assert "FFmpeg" in plugin.info["name"]


def test_version_parsing():
    assert parse_ffmpeg_version("ffmpeg version 7.1.1 Copyright (c) 2000-2026") == (7, 1, 1, "7.1.1")
    assert parse_ffmpeg_version("X-FFmpeg-Version: 9.1") == (9, 1, 0, "9.1.0")
    assert parse_ffmpeg_version('{"ffmpeg_version": "4.3.8"}') == (4, 3, 8, "4.3.8")
    assert parse_ffmpeg_version("<html>Not ffmpeg</html>") is None


def test_version_vulnerability_logic():
    vuln_both, reason_both = is_ffmpeg_version_vulnerable(7, 1, 1)
    assert vuln_both is True
    assert "CVE-2026-135736" in reason_both
    assert "CVE-2026-135743" in reason_both

    vuln_43, reason_43 = is_ffmpeg_version_vulnerable(4, 3, 5)
    assert vuln_43 is True
    assert "CVE-2026-135743" in reason_43

    safe_patched, _ = is_ffmpeg_version_vulnerable(9, 1, 0)
    assert safe_patched is False

    safe_old, _ = is_ffmpeg_version_vulnerable(4, 2, 9)
    assert safe_old is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = FFmpegAuditPlugin()
    plugin.discovered_ports = [8080]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "version": "7.1.1",
            "source": "FFmpeg Media API Version Endpoint (/api/version)",
            "is_vulnerable": True,
            "reason": "Affected 4.4 to < 9.1",
        },
    )
    res = plugin.run_audit("10.0.0.85", [8080])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-135736" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "version": "9.1.0",
            "source": "FFmpeg Media API Version Endpoint (/api/version)",
            "is_vulnerable": False,
            "reason": "Patched >= 9.1.0",
        },
    )
    res_safe = plugin.run_audit("10.0.0.85", [8080])
    assert res_safe["status"] == "OK"
