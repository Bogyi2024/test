#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_login_v3.py - Full Rapidgator API chain test (login -> file info ->
premium download URL), using the SAME dual-backend rg_get() logic as
rpgx_fixed.py, driven by a real RG_LINK.

Does NOT download the actual file with aria2 (these .rar parts are
~900MB+, no point burning runner bandwidth/time for a logic test) and
does NOT touch Hugging Face. Instead, after generating the premium
download URL, it does a single lightweight HEAD request against it to
confirm the URL is actually live and reachable (status code + reported
file size), which is the real proof that the whole chain works end to end
short of transferring the bytes.

Steps tested, in order, each via the dual-backend fallback:
  1. extract_file_id(RG_LINK)
  2. POST/GET /user/login            (same as test_login_v2.py)
  3. GET /file/info                  (NEW - confirms file exists/is online)
  4. GET /file/download               (NEW - generates the premium URL)
  5. HEAD <premium_url>                (NEW - confirms URL is actually live)
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
rg_link = os.environ.get("RG_LINK")
# Optional: force a specific backend to fail on purpose, to prove fallback.
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
    """requests first, curl_cffi fallback - identical logic to rpgx_fixed.py."""
    backends = ["requests"]
    if _HAVE_CURL_CFFI:
        backends.append("curl_cffi")

    last = None
    for backend in backends:
        session = new_session(backend)
        for i in range(1, tries_per_backend + 1):
            try:
                res, data = _do_get(session, path, params, backend)
                return res, data, backend
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


def extract_file_id(url):
    match = re.search(r"/file/([a-zA-Z0-9]{32})", url or "")
    if match:
        return match.group(1)
    try:
        session = new_session("requests")
        res = session.head(url, allow_redirects=True, timeout=30)
        match = re.search(r"/file/([a-zA-Z0-9]{32})", res.url or "")
        return match.group(1) if match else None
    except Exception:
        return None


def head_check(url):
    """Lightweight check that the premium URL is actually live, no full download."""
    try:
        session = new_session("requests")
        res = session.head(url, allow_redirects=True, timeout=30,
                            headers={"User-Agent": BROWSER_UA,
                                     "Referer": "https://rapidgator.net/"})
        size = res.headers.get("Content-Length")
        return {
            "attempted": True,
            "status_code": res.status_code,
            "ok": res.status_code in (200, 206),
            "content_length_bytes": int(size) if size and size.isdigit() else None,
            "final_url_host": re.sub(r"^https?://([^/]+).*$", r"\1", res.url or ""),
        }
    except Exception as exc:
        return {"attempted": True, "status_code": None, "ok": False,
                "error": f"{type(exc).__name__}: {exc}"}


def main():
    print("=" * 70)
    print("TEST: full chain (login -> file info -> download URL -> HEAD check)")
    print("=" * 70)
    if FORCE_FAIL_BACKEND:
        print(f"[*] FORCE_FAIL_BACKEND={FORCE_FAIL_BACKEND!r} - simulating that "
              "backend being blocked on EVERY call below, to test fallback.")
    print(f"[*] RG_LINK: {rg_link}")
    print()

    result = {}
    t0 = time.time()

    # 1. Extract file ID
    file_id = extract_file_id(rg_link)
    result["file_id"] = file_id
    if not file_id:
        print("[x] Could not extract a 32-char file ID from RG_LINK. Stopping.")
        print(json.dumps(result, indent=2))
        sys.exit(2)
    print(f"[*] Extracted file_id: {file_id}")

    # 2. Login
    print("\n--- Step: /user/login ---")
    try:
        _, data, backend = rg_get("/user/login", {"login": rg_email, "password": rg_password})
        token = (data.get("response") or {}).get("token")
        result["login"] = {"ok": bool(token), "backend": backend}
        if not token:
            print(f"[x] Login rejected: {data}")
            print(json.dumps(result, indent=2))
            sys.exit(2)
        print(f"[*] Login OK via backend='{backend}'.")
    except Exception as exc:
        result["login"] = {"ok": False, "error": str(exc)}
        print(f"[x] Login failed on all backends: {exc}")
        print(json.dumps(result, indent=2))
        sys.exit(1)

    # 3. File info
    print("\n--- Step: /file/info ---")
    try:
        _, data, backend = rg_get("/file/info", {"file_id": file_id, "token": token})
        info = (data.get("response") or {}).get("file") or {}
        name = info.get("name")
        size = info.get("size")
        result["file_info"] = {"ok": bool(name), "backend": backend,
                                "name": name, "size_bytes": size}
        if not name:
            print(f"[x] File info failed / file offline: {data}")
            print(json.dumps(result, indent=2))
            sys.exit(2)
        print(f"[*] File: {name}  size={size}  (via backend='{backend}')")
    except Exception as exc:
        result["file_info"] = {"ok": False, "error": str(exc)}
        print(f"[x] file_info failed on all backends: {exc}")
        print(json.dumps(result, indent=2))
        sys.exit(1)

    # 4. Download URL
    print("\n--- Step: /file/download ---")
    try:
        _, data, backend = rg_get("/file/download", {"file_id": file_id, "token": token})
        download_url = (data.get("response") or {}).get("download_url")
        result["download_url"] = {"ok": bool(download_url), "backend": backend,
                                   "url_present": bool(download_url)}
        if not download_url:
            print(f"[x] Rapidgator refused the download URL: {data}")
            print(json.dumps(result, indent=2))
            sys.exit(2)
        print(f"[*] Premium download URL generated (via backend='{backend}').")
    except Exception as exc:
        result["download_url"] = {"ok": False, "error": str(exc)}
        print(f"[x] file_download_url failed on all backends: {exc}")
        print(json.dumps(result, indent=2))
        sys.exit(1)

    # 5. HEAD check the premium URL (no full download)
    print("\n--- Step: HEAD check on premium URL (no download) ---")
    head_result = head_check(download_url)
    result["head_check"] = head_result
    if head_result.get("ok"):
        mb = (head_result.get("content_length_bytes") or 0) / 1048576
        print(f"[*] Premium URL is LIVE: HTTP {head_result['status_code']}, "
              f"reports {mb:.1f} MB, host={head_result.get('final_url_host')}")
    else:
        print(f"[!] Premium URL HEAD check did not confirm liveness: {head_result}")

    dt = time.time() - t0
    result["total_duration_s"] = round(dt, 2)

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(json.dumps(result, indent=2))

    print()
    print("[Interpretation]")
    all_ok = (result["login"]["ok"] and result["file_info"]["ok"]
              and result["download_url"]["ok"] and head_result.get("ok"))
    if all_ok:
        print("  Full chain confirmed working end-to-end (login -> file info ->")
        print("  download URL -> URL is live). The real aria2 download/HF upload")
        print("  in rpgx_fixed.py should succeed for this link.")
    else:
        print("  One or more steps did not fully succeed - see which step above")
        print("  has ok=false. That is the step to investigate before deploying.")
    print(f"  Total time: {dt:.2f}s. No file bytes were downloaded; no HF upload was attempted.")


if __name__ == "__main__":
    if not rg_email or not rg_password:
        print("[!] RG_EMAIL / RG_PASSWORD not set. Exiting.")
        sys.exit(1)
    if not rg_link:
        print("[!] RG_LINK not set. Exiting.")
        sys.exit(1)
    main()
