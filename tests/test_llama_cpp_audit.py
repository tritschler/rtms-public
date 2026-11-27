from plugins.llama_cpp.llama_cpp_cve_2026_137567_audit import (
    LlamaCppAuditPlugin,
    is_llama_cpp_build_vulnerable,
    parse_llama_cpp_build,
)


def test_parse_llama_cpp_build():
    assert parse_llama_cpp_build("b12000") == 12000
    assert parse_llama_cpp_build("b12658") == 12658
    assert parse_llama_cpp_build("") is None


def test_is_llama_cpp_build_vulnerable():
    assert is_llama_cpp_build_vulnerable(11450)[0] is True
    assert is_llama_cpp_build_vulnerable(12657)[0] is True
    assert is_llama_cpp_build_vulnerable(12658)[0] is False


def test_llama_cpp_run_audit():
    res_v = LlamaCppAuditPlugin("llama.local", {"llama_build": "b12000"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-137567" in res_v["cve"]

    res_ok = LlamaCppAuditPlugin("llama.local", {"llama_build": "b12658"}).run_audit()
    assert res_ok["status"] == "OK"
