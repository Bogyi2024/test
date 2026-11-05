#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_login_v4.py - Same chain as test_login_v3.py (login -> file info ->
download URL), but this time ACTUALLY downloads the file with aria2c,
using the identical aria2_download() logic from rpgx_fixed.py.

Does NOT touch Hugging Face - stops right after a successful, size-verified
download and deletes the file afterward to avoid filling runner disk.

This is the last check before trusting rpgx_fixed.py end-to-end: if this
step also reports ok, the only untested part of the real pipeline is the
HF upload call itself (which is unchanged from the original script and
was never implicated in the Rapidgator blocking issue).
"""

import os
import re
import sys
import time
import json
import subprocess

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
OUTPUT_PATH = "download"
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

rg_email = os.environ.get("RG_EMAIL")
rg_password = os.environ.get("RG_PASSWORD")
rg_link = os.environ.get("RG_LINK")
FORCE_FAIL_BACKEND = os.environ.get("FORCE_FAIL_BACKEND", "").strip()
# Safety cap so a bad test run can't fill the runner's disk unexpectedly.
MAX_TEST_MB = int(os.environ.get("MAX_TEST_MB", "2000") or 2000)


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


def aria2_download(url, outdir, filename):
    """Identical command/flags to rpgx_fixed.py's aria2_download()."""
    path = os.path.join(outdir, filename)
    cmd = [
        "aria2c", url,
        "-x", "16", "-s", "16", "-k", "1M",
        "-d", outdir, "-o", filename,
        "--allow-overwrite=true",
        "--auto-file-renaming=false",
        "--file-allocation=none",
        "--max-tries=5", "--retry-wait=10",
        "--timeout=60", "--connect-timeout=30",
        f"--user-agent={BROWSER_UA}",
        "--referer=https://rapidgator.net/",
        "--summary-interval=10",
        "--console-log-level=warn",
    ]
    print("[*] Downloading with aria2c (16 connections)...")
    print(f"[*] Command: {' '.join(cmd)}")
    rc = subprocess.run(cmd).returncode
    if rc != 0:
        raise RetryableError(f"aria2c exited with code {rc} (download link likely expired)")
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        raise RetryableError(f"aria2c produced no usable file: {filename}")
    return path


def main():
    print("=" * 70)
    print("TEST: real aria2c download (no HF upload)")
    print("=" * 70)
    if FORCE_FAIL_BACKEND:
        print(f"[*] FORCE_FAIL_BACKEND={FORCE_FAIL_BACKEND!r} - simulating that "
              "backend being blocked on every API call below.")
    print(f"[*] RG_LINK: {rg_link}")
    print()

    result = {}
    t0 = time.time()

    file_id = extract_file_id(rg_link)
    result["file_id"] = file_id
    if not file_id:
        print("[x] Could not extract file ID. Stopping.")
        print(json.dumps(result, indent=2)); sys.exit(2)
    print(f"[*] Extracted file_id: {file_id}")

    print("\n--- Step: /user/login ---")
    _, data, backend = rg_get("/user/login", {"login": rg_email, "password": rg_password})
    token = (data.get("response") or {}).get("token")
    result["login"] = {"ok": bool(token), "backend": backend}
    if not token:
        print(f"[x] Login rejected: {data}")
        print(json.dumps(result, indent=2)); sys.exit(2)
    print(f"[*] Login OK via backend='{backend}'.")

    print("\n--- Step: /file/info ---")
    _, data, backend = rg_get("/file/info", {"file_id": file_id, "token": token})
    info = (data.get("response") or {}).get("file") or {}
    name = info.get("name")
    reported_size = info.get("size")
    result["file_info"] = {"ok": bool(name), "backend": backend,
                            "name": name, "reported_size_bytes": reported_size}
    if not name:
        print(f"[x] File info failed: {data}")
        print(json.dumps(result, indent=2)); sys.exit(2)
    print(f"[*] File: {name}  reported_size={reported_size}")

    # Safety cap check
    if reported_size and int(reported_size) > MAX_TEST_MB * 1048576:
        print(f"[!] File is {int(reported_size)/1048576:.1f} MB, over the "
              f"MAX_TEST_MB={MAX_TEST_MB} safety cap for this test run.")
        print("[!] Refusing to download. Pick a smaller part, or raise MAX_TEST_MB input.")
        result["download"] = {"ok": False, "skipped_reason": "over MAX_TEST_MB cap"}
        print(json.dumps(result, indent=2)); sys.exit(1)

    print("\n--- Step: /file/download ---")
    _, data, backend = rg_get("/file/download", {"file_id": file_id, "token": token})
    download_url = (data.get("response") or {}).get("download_url")
    result["download_url"] = {"ok": bool(download_url), "backend": backend}
    if not download_url:
        print(f"[x] No download URL: {data}")
        print(json.dumps(result, indent=2)); sys.exit(2)
    print(f"[*] Premium download URL generated (via backend='{backend}').")

    print("\n--- Step: aria2c real download ---")
    os.makedirs(OUTPUT_PATH, exist_ok=True)
    dl_t0 = time.time()
    try:
        local_path = aria2_download(download_url, OUTPUT_PATH, name)
    except Exception as exc:
        result["download"] = {"ok": False, "error": str(exc)}
        print(f"[x] aria2c download failed: {exc}")
        print(json.dumps(result, indent=2)); sys.exit(1)
    dl_dt = time.time() - dl_t0

    actual_size = os.path.getsize(local_path)
    size_matches = (reported_size is None) or (int(reported_size) == actual_size)
    speed_mbps = (actual_size / 1048576) / dl_dt if dl_dt > 0 else 0

    result["download"] = {
        "ok": True,
        "actual_size_bytes": actual_size,
        "reported_size_bytes": reported_size,
        "size_matches": size_matches,
        "duration_s": round(dl_dt, 2),
        "avg_speed_mbps": round(speed_mbps, 2),
    }
    print(f"[*] Downloaded {actual_size/1048576:.1f} MB in {dl_dt:.1f}s "
          f"({speed_mbps:.1f} MB/s). size_matches={size_matches}")

    # Clean up - this is a test, not a real transfer.
    try:
        os.remove(local_path)
        print(f"[*] Cleaned up test file ({local_path}) - not uploading anywhere.")
    except Exception as exc:
        print(f"[!] Could not remove test file: {exc}")

    dt = time.time() - t0
    result["total_duration_s"] = round(dt, 2)

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(json.dumps(result, indent=2))

    print()
    print("[Interpretation]")
    if result["download"]["ok"] and size_matches:
        print("  Real aria2c download succeeded and the byte size matches what")
        print("  Rapidgator reported. The full pipeline (minus HF upload, which")
        print("  is unchanged original code) is now verified end-to-end.")
    elif result["download"]["ok"] and not size_matches:
        print("  Download completed but the size does NOT match the API's")
        print("  reported size - investigate before trusting this link.")
    print(f"  No file was uploaded to Hugging Face. Total time: {dt:.2f}s.")


if __name__ == "__main__":
    if not rg_email or not rg_password:
        print("[!] RG_EMAIL / RG_PASSWORD not set. Exiting.")
        sys.exit(1)
    if not rg_link:
        print("[!] RG_LINK not set. Exiting.")
        sys.exit(1)
    main()
