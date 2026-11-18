#!/usr/bin/env python3
"""Deliver a private callback file to an SDK loopback or Android intent.

The URL/code is never printed. Do not use shell tracing around this command.
This helper never exchanges tokens or reads the fixture password.
"""
import argparse
from pathlib import Path
import shlex
import subprocess
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--callback-file", type=Path, required=True)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--loopback", action="store_true")
    destination.add_argument("--adb-serial")
    args = parser.parse_args()
    assert args.callback_file.stat().st_mode & 0o077 == 0
    callback = args.callback_file.read_text().strip()
    url = urllib.parse.urlsplit(callback)
    query = urllib.parse.parse_qs(url.query, strict_parsing=True)
    assert not url.fragment and "error" not in query
    assert len(query.get("code", [])) == 1 and len(query.get("state", [])) == 1
    base = urllib.parse.urlunsplit((url.scheme, url.netloc, url.path, "", ""))
    if args.loopback:
        assert base == "http://127.0.0.1:18765/callback"
        with urllib.request.build_opener(NoRedirect()).open(callback, timeout=20) as response:
            assert response.status == 200
    else:
        assert base == "cyberbus://auth/callback"
        # adb shell concatenates arguments into a remote shell command. Quote the
        # complete URI there so query ampersands cannot become shell operators.
        result = subprocess.run(["adb", "-s", args.adb_serial, "shell", "am", "start", "-W",
                                 "-a", "android.intent.action.VIEW", "-d", shlex.quote(callback)],
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0 and "Error:" not in result.stdout + result.stderr
    print("PASS: callback delivered; SDK owns completion")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("FAIL: callback delivery (" + type(error).__name__ + ")")
        raise SystemExit(1)
