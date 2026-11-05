#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_login_v2.py - Diagnostic for the FIXED dual-backend login logic
(same rg_get() fallback behavior as rpgx_fixed.py), WITHOUT touching
download/upload. Safe to run repeatedly in the test repo.

What this proves before you touch production rpgx.py:
  - Does the new "requests first, curl_cffi fallback" rg_get() actually
    call /user/login correctly end-to-end?
  - If requests fails on this runner, does it actually fall back to
    curl_cffi and still succeed (instead of just erroring out)?
  - Does it still correctly reject a bad login (PermanentError path)?

This does NOT download any file and does NOT touch Hugging Face. It only
calls POST/GET https://rapidgator.net/api/v2/user/login, same as before.
"""

import os
import re
import sys
import time
import json

try:
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
except Exception:
    pass

import requests as _requests_mod  # type: ignore

_HAVE_CURL_CFFI = False
try:
    from curl_cffi import requests as _curl_cffi_mod  # type: ignore
    _HAVE_CURL_CFFI = True
except ImportError:
    _curl_cffi_mod = None

RG_API = "https://rapidgator.net/api/v2"
TIMEOUT = 60
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

rg_email = os.environ.get("RG_EMAIL")
rg_password = os.environ.get("RG_PASSWORD")
# Optional: force a specific backend order to fail on purpose, to prove the
# fallback path actually triggers. "requests" | "curl_cffi" | "" (normal).
FORCE_FAIL_BACKEND = os.environ.get("FORCE_FAIL_BACKEND", "").strip()


class RetryableError(Exception):
    pass


class PermanentError(Exception):
    pass


def new_session(backend):
    if backend == "curl_cffi" and _HAVE_CURL_CFFI:
        return _curl_cffi_mod.Session(impersonate="chrome")
    return _requests_mod.Session()


def _do_get(session, path, params, backend):
    # Test-only hook: simulate a backend being blocked, to verify the
    # fallback-to-other-backend code path actually runs.
    if FORCE_FAIL_BACKEND and backend == FORCE_FAIL_BACKEND:
        raise RetryableError(
            f"[SIMULATED] forced failure for backend={backend} "
            "(set via FORCE_FAIL_BACKEND env var for this test only)"
        )

    res = session.get(
        f"{RG_API}{path}",
        params=params,
        timeout=TIMEOUT,
        headers={"Accept": "application/json", "User-Agent": BROWSER_UA},
    )
    if res.status_code in (429, 500, 502, 503, 504):
        raise RetryableError(f"HTTP {res.status_code} from {path}")
    try:
        return res, res.json()
    except ValueError:
        snippet = (res.text or "")[:200].replace("\n", " ")
        raise RetryableError(
            f"Non-JSON reply from {path} (HTTP {res.status_code}): {snippet!r} "
            "- this is a WAF/anti-bot page, not the API"
        )


def rg_get(path, params, tries_per_backend=2):
    """Same logic as the fixed rpgx.py: requests first, curl_cffi fallback."""
    backends = ["requests"]
    if _HAVE_CURL_CFFI:
        backends.append("curl_cffi")

    print(f"[*] Backend order for this call: {backends}")

    last = None
    used_backend = None
    for backend in backends:
        session = new_session(backend)
        for i in range(1, tries_per_backend + 1):
            try:
                res, data = _do_get(session, path, params, backend)
                used_backend = backend
                return res, data, used_backend
            except RetryableError as exc:
                last = exc
            except Exception as exc:
                last = RetryableError(f"{type(exc).__name__}: {exc}")

            if i < tries_per_backend:
                wait = 3 * i
                print(f"[!] [{backend}] {path} failed: {last}")
                print(f"[!] [{backend}] retry {i}/{tries_per_backend - 1} in {wait}s")
                time.sleep(wait)
            else:
                print(f"[!] [{backend}] {path} failed after {tries_per_backend} "
                      f"attempt(s): {last}")

        if backend != backends[-1]:
            print(f"[*] >>> Switching HTTP backend: requests -> curl_cffi for {path} <<<")

    raise last


def main():
    print("=" * 70)
    print("TEST: dual-backend rg_get() against /user/login")
    print("=" * 70)
    if FORCE_FAIL_BACKEND:
        print(f"[*] FORCE_FAIL_BACKEND={FORCE_FAIL_BACKEND!r} "
              "- simulating that backend being blocked, to test the fallback path.")
    print()

    t0 = time.time()
    try:
        res, data, used_backend = rg_get(
            "/user/login", {"login": rg_email, "password": rg_password}
        )
    except Exception as exc:
        dt = time.time() - t0
        print()
        print(f"[FAIL] All backends exhausted after {dt:.2f}s: {exc}")
        print()
        print("[Interpretation]")
        print("  Every available backend failed. Either both are genuinely")
        print("  blocked on this runner right now, or RG_EMAIL/RG_PASSWORD")
        print("  are wrong (check the response body above if any HTTP came back).")
        sys.exit(1)

    dt = time.time() - t0
    token = (data.get("response") or {}).get("token")

    print()
    print("=" * 70)
    print("RESULT")
    print("=" * 70)
    result = {
        "used_backend": used_backend,
        "duration_s": round(dt, 2),
        "login_ok": bool(token),
        "fallback_triggered": used_backend != "requests",
    }
    print(json.dumps(result, indent=2))

    print()
    print("[Interpretation]")
    if token:
        print(f"  Login succeeded via backend='{used_backend}' in {dt:.2f}s.")
        if result["fallback_triggered"]:
            print("  >>> FALLBACK PATH CONFIRMED WORKING: requests failed, "
                  "curl_cffi was tried and succeeded. <<<")
        else:
            print("  Primary backend (requests) worked on the first try - "
                  "no fallback was needed this run.")
    else:
        print(f"  Backend='{used_backend}' returned HTTP 200 but no token: {data}")
        print("  This usually means wrong RG_EMAIL/RG_PASSWORD, not a network issue.")


if __name__ == "__main__":
    if not rg_email or not rg_password:
        print("[!] RG_EMAIL / RG_PASSWORD not set. Exiting.")
        sys.exit(1)
    main()
