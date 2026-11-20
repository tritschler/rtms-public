"""
test_wp_photo_album_plus_audit.py - Unit tests for WordPress WP Photo Album Plus Code Injection Audit
(CVE-2026-129048).
"""

from plugins.wordpress.wp_photo_album_plus.wp_photo_album_plus_cve_2026_129048_audit import (
    WPPhotoAlbumPlusAuditPlugin,
    parse_wp_photo_album_plus_version,
    is_wp_photo_album_plus_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPPhotoAlbumPlusAuditPlugin()
    assert "CVE-2026-129048" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "WP Photo Album Plus" in plugin.info["name"]


def test_version_parsing():
    html = '<script src="/wp-content/plugins/wp-photo-album-plus/js/wppa.min.js?ver=9.3.06.003"></script>'
    assert parse_wp_photo_album_plus_version(html) == (9, 3, 6, 3, "9.3.06.003")
    assert parse_wp_photo_album_plus_version("Stable tag: 9.3.06.004\n") == (9, 3, 6, 4, "9.3.06.004")
    assert parse_wp_photo_album_plus_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_wp_photo_album_plus_version_vulnerable(9, 3, 6, 3, "9.3.06.003")
    assert vuln is True
    assert "CVE-2026-129048" in reason

    safe, _ = is_wp_photo_album_plus_version_vulnerable(9, 3, 6, 4, "9.3.06.004")
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPPhotoAlbumPlusAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "9.3.06.003",
            "source": "WP Photo Album Plus readme.txt",
            "is_vulnerable": True,
            "reason": "Affected <= 9.3.06.003 (< 9.3.06.004)",
        },
    )
    res = plugin.run_audit("10.0.0.52", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-129048" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "9.3.06.004",
            "source": "WP Photo Album Plus readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 9.3.06.004",
        },
    )
    res_safe = plugin.run_audit("10.0.0.52", [443])
    assert res_safe["status"] == "OK"
