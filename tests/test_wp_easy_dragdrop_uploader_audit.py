"""
test_wp_easy_dragdrop_uploader_audit.py - Unit tests for WordPress Easy DragDrop File Uploader Arbitrary File Deletion Audit (CVE-2026-124822).
"""

from plugins.wordpress.wp_easy_dragdrop_uploader.wp_easy_dragdrop_uploader_cve_2026_124822_audit import (
    WPEasyDragDropUploaderAuditPlugin,
    parse_easy_dragdrop_version,
    is_easy_dragdrop_version_vulnerable,
)


def test_plugin_metadata():
    plugin = WPEasyDragDropUploaderAuditPlugin()
    assert "CVE-2026-124822" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Easy" in plugin.info["name"]


def test_version_parsing():
    html = '<link href="/wp-content/plugins/easy-dragdrop-file-uploader/assets/css/style.css?ver=1.1.9" />'
    assert parse_easy_dragdrop_version(html) == (1, 1, 9, "1.1.9")
    assert parse_easy_dragdrop_version("Stable tag: 1.1.10\n") == (1, 1, 10, "1.1.10")
    assert parse_easy_dragdrop_version("<html>No plugin</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_easy_dragdrop_version_vulnerable(1, 1, 9)
    assert vuln is True
    assert "CVE-2026-124822" in reason

    safe, _ = is_easy_dragdrop_version_vulnerable(1, 1, 10)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WPEasyDragDropUploaderAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.1.9",
            "source": "Easy DragDrop File Uploader readme.txt",
            "is_vulnerable": True,
            "reason": "Affected < 1.1.10 (<= 1.1.9)",
        },
    )
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-124822" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "plugin_detected": True,
            "version": "1.1.10",
            "source": "Easy DragDrop File Uploader readme.txt",
            "is_vulnerable": False,
            "reason": "Patched >= 1.1.10",
        },
    )
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
