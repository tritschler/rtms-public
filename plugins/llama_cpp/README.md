# llama.cpp — CVE-2026-137567 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **llama.cpp** server deployment is affected by **CVE-2026-137567** (CVSS 9.3, Critical), a heap out-of-bounds write vulnerability in the `ggml` RPC server.

## Affected & Fixed Versions
| Product | Affected Versions | Patched Build |
| :--- | :--- | :--- |
| `llama.cpp` | `b11450` before `b12658` (`11450 <= build < 12658`) | `b12658` |

## Usage
```bash
python3 plugins/llama_cpp/llama_cpp_cve_2026_137567_audit.py --target http://llama.example.local:8080
```
