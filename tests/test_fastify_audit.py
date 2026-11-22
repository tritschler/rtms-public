"""
test_fastify_audit.py - Unit tests for Fastify Middleware (@fastify/express & @fastify/middie)
Multi-CVE Compliance Audit (CVE-2026-133120, CVE-2026-129504, CVE-2026-133867, CVE-2026-124626, CVE-2026-133250).
"""

from plugins.fastify.fastify_cve_2026_133120_audit import (
    FastifyMiddlewareAuditPlugin,
    parse_fastify_middleware_version,
    is_fastify_middleware_version_vulnerable,
)


def test_plugin_metadata():
    plugin = FastifyMiddlewareAuditPlugin()
    assert "CVE-2026-133120" in plugin.info["cve"]
    assert "CVE-2026-133250" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"


def test_version_parsing():
    manifest = '{"dependencies": {"@fastify/express": "^4.0.8"}}'
    assert parse_fastify_middleware_version(manifest) == ("@fastify/express", 4, 0, 8, "4.0.8")

    banner = "X-Powered-By: Fastify (@fastify/middie/9.3.7)"
    assert parse_fastify_middleware_version(banner) == ("@fastify/middie", 9, 3, 7, "9.3.7")

    assert parse_fastify_middleware_version("<html>OK</html>") is None


def test_version_vulnerability_logic():
    vuln_exp, reason_exp = is_fastify_middleware_version_vulnerable("@fastify/express", 4, 0, 8)
    assert vuln_exp is True
    assert "CVE-2026-133120" in reason_exp
    assert "CVE-2026-129504" in reason_exp
    assert "CVE-2026-124626" in reason_exp
    assert "CVE-2026-133867" in reason_exp

    safe_exp, _ = is_fastify_middleware_version_vulnerable("@fastify/express", 4, 0, 10)
    assert safe_exp is False

    vuln_mid, reason_mid = is_fastify_middleware_version_vulnerable("@fastify/middie", 9, 3, 7)
    assert vuln_mid is True
    assert "CVE-2026-133250" in reason_mid

    safe_mid, _ = is_fastify_middleware_version_vulnerable("@fastify/middie", 9, 3, 8)
    assert safe_mid is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = FastifyMiddlewareAuditPlugin()
    plugin.discovered_ports = [3000]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 3000,
            "service_detected": True,
            "package": "@fastify/express",
            "version": "4.0.9",
            "source": "Fastify Version Endpoint (/version)",
            "is_vulnerable": True,
            "reason": "Affected < 4.0.10",
        },
    )
    res = plugin.run_audit("10.0.0.60", [3000])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-133120" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 3000,
            "service_detected": True,
            "package": "@fastify/express",
            "version": "4.0.10",
            "source": "Fastify Version Endpoint (/version)",
            "is_vulnerable": False,
            "reason": "Patched >= 4.0.10",
        },
    )
    res_safe = plugin.run_audit("10.0.0.60", [3000])
    assert res_safe["status"] == "OK"
