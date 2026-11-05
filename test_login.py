#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_login.py - Isolated diagnostic for the Rapidgator /user/login TLS failure
seen in the production job (SSLError: BoringSSL SSL_connect: Connection closed
abruptly / SSL_ERROR_SYSCALL, during curl_cffi Chrome-impersonated login).

This script does ONLY the login call, with three independent backends, so we
can tell apart:
  (a) a TLS-fingerprint / WAF block specific to plain `requests`
  (b) a block that also hits curl_cffi's Chrome impersonation (i.e. the same
      failure the production job hit)
  (c) a transient network issue local to one request (would show as
      inconsistent results between backends/attempts)

It does NOT download or upload anything. Credentials are read from env vars
and immediately masked from the Actions log via ::add-mask::.

Exit code is always 0 - this script's job is to report, not to gate a build.
"""

import json
import os
import socket
import ssl
import sys
import time
import urllib.request
import urllib.error

RG_API = "https://rapidgator.net/api/v2"
TIMEOUT = 30

rg_email = os.environ.get("RG_EMAIL", "")
rg_password = os.environ.get("RG_PASSWORD", "")
rg_link = os.environ.get("RG_LINK", "")

# Mask secrets from the log immediately (GitHub Actions log-command syntax).
if rg_email:
    print(f"::add-mask::{rg_email}")
if rg_password:
    print(f"::add-mask::{rg_password}")

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

results = {}


def banner(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def show_egress_ip():
    """What IP is this runner actually seen as by the outside world."""
    banner("0. Runner egress IP (for correlating with any block)")
    for url in ("https://api.ipify.org?format=json", "https://ifconfig.me/all.json"):
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                print(f"[*] {url} -> {r.read().decode('utf-8', 'replace').strip()}")
            return
        except Exception as exc:
            print(f"[!] {url} failed: {type(exc).__name__}: {exc}")
    print("[!] Could not determine egress IP via any provider.")


def test_plain_requests():
    """Backend A: plain `requests` (python-requests TLS fingerprint)."""
    banner("1. Backend: plain `requests` (default python TLS fingerprint)")
    try:
        import requests
    except ImportError:
        print("[!] `requests` not installed - skipping.")
        results["requests"] = {"attempted": False}
        return

    try:
        t0 = time.time()
        res = requests.get(
            f"{RG_API}/user/login",
            params={"login": rg_email, "password": rg_password},
            timeout=TIMEOUT,
            headers={"Accept": "application/json"},
        )
        dt = time.time() - t0
        print(f"[*] HTTP {res.status_code} in {dt:.2f}s")
        print(f"[*] Response snippet: {res.text[:300]!r}")
        results["requests"] = {
            "attempted": True,
            "ok": res.status_code == 200,
            "status_code": res.status_code,
            "duration_s": round(dt, 2),
        }
    except Exception as exc:
        dt = time.time() - t0
        print(f"[x] FAILED after {dt:.2f}s: {type(exc).__name__}: {exc}")
        results["requests"] = {
            "attempted": True,
            "ok": False,
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "duration_s": round(dt, 2),
        }


def test_curl_cffi():
    """Backend B: curl_cffi impersonating Chrome (what the production job uses)."""
    banner("2. Backend: curl_cffi (Chrome TLS/HTTP2 fingerprint) - PRODUCTION BACKEND")
    try:
        from curl_cffi import requests as curl_http
    except ImportError:
        print("[!] curl_cffi not installed - skipping.")
        results["curl_cffi"] = {"attempted": False}
        return

    try:
        t0 = time.time()
        session = curl_http.Session(impersonate="chrome")
        res = session.get(
            f"{RG_API}/user/login",
            params={"login": rg_email, "password": rg_password},
            timeout=TIMEOUT,
            headers={"Accept": "application/json"},
        )
        dt = time.time() - t0
        print(f"[*] HTTP {res.status_code} in {dt:.2f}s")
        print(f"[*] Response snippet: {res.text[:300]!r}")
        results["curl_cffi"] = {
            "attempted": True,
            "ok": res.status_code == 200,
            "status_code": res.status_code,
            "duration_s": round(dt, 2),
        }
    except Exception as exc:
        dt = time.time() - t0
        print(f"[x] FAILED after {dt:.2f}s: {type(exc).__name__}: {exc}")
        results["curl_cffi"] = {
            "attempted": True,
            "ok": False,
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "duration_s": round(dt, 2),
        }


def test_raw_tls_handshake():
    """Backend C: bare TLS handshake to rapidgator.net:443, no HTTP request at
    all. Isolates whether the block happens at the TLS layer (before any HTTP
    payload / TLS fingerprint is even relevant) or later."""
    banner("3. Raw TLS handshake only (no HTTP request, isolates TLS-layer block)")
    host = "rapidgator.net"
    try:
        t0 = time.time()
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                dt = time.time() - t0
                cipher = tls_sock.cipher()
                print(f"[*] TLS handshake OK in {dt:.2f}s, cipher={cipher}")
                results["raw_tls"] = {
                    "attempted": True,
                    "ok": True,
                    "duration_s": round(dt, 2),
                }
    except Exception as exc:
        dt = time.time() - t0
        print(f"[x] FAILED after {dt:.2f}s: {type(exc).__name__}: {exc}")
        results["raw_tls"] = {
            "attempted": True,
            "ok": False,
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "duration_s": round(dt, 2),
        }


def summarize():
    banner("SUMMARY")
    print(json.dumps(results, indent=2))

    raw = results.get("raw_tls", {})
    req = results.get("requests", {})
    cc = results.get("curl_cffi", {})

    print("\n[Interpretation]")
    if raw.get("attempted") and not raw.get("ok"):
        print("- Raw TLS handshake itself failed -> block/drop happens before any")
        print("  HTTP-level fingerprint matters (pure IP/TLS-layer block, e.g. WAF")
        print("  dropping the connection by source IP or TLS ClientHello shape).")
    elif raw.get("ok") and req.get("attempted") and not req.get("ok") and cc.get("attempted") and not cc.get("ok"):
        print("- Raw TLS handshake succeeded, but BOTH `requests` and curl_cffi logins")
        print("  failed -> likely not a TLS-fingerprint issue; more likely app-layer")
        print("  rate limiting / WAF rule on the /user/login endpoint itself, or bad")
        print("  credentials (check error_message above for a login-rejected response")
        print("  vs. a connection-level error).")
    elif raw.get("ok") and req.get("attempted") and not req.get("ok") and cc.get("ok"):
        print("- Raw TLS OK, curl_cffi (Chrome fingerprint) login OK, but plain")
        print("  `requests` login failed -> CONFIRMS the original diagnosis: Rapidgator")
        print("  is fingerprinting the TLS/HTTP client and only blocking the")
        print("  non-browser-like `requests` fingerprint. The curl_cffi fix in")
        print("  production is the correct mitigation for this failure mode.")
    elif cc.get("ok"):
        print("- curl_cffi login succeeded this run. If the production job still")
        print("  fails intermittently, this points to a transient/IP-reputation issue")
        print("  (e.g. this runner's IP got a temporary rate-limit) rather than a")
        print("  permanent fingerprint block, since the same backend worked here.")
    else:
        print("- Inconclusive from automated rules; inspect error_type/error_message")
        print("  per backend above.")

    if rg_link:
        print(f"\n[*] (Not used) rg_link was supplied: {rg_link!r} - this script only")
        print("    tests login, not file info/download, per the test scope.")


if __name__ == "__main__":
    show_egress_ip()
    test_raw_tls_handshake()
    test_plain_requests()
    test_curl_cffi()
    summarize()
    sys.exit(0)
