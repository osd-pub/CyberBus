#!/usr/bin/env python3
"""Reject local data, private deployment identifiers, keys, and build artifacts."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", "target", ".gradle", "build", ".worktrees", "node_modules"}
ALLOW = "https://cyberbus.x.aixgg.com/easytier/credentials/v1"
TEXT_SCAN_SKIP = {"scripts/check-public-tree.py"}
SECRET_CONFIG_SUFFIXES = {
    ".conf",
    ".env",
    ".ini",
    ".json",
    ".properties",
    ".toml",
    ".yaml",
    ".yml",
}

patterns = [
    ("local absolute path", re.compile(r"/(?:Users|home)/[A-Za-z0-9_.-]+/")),
    ("private deployment domain", re.compile(r"\.x\.aixgg\.com\b")),
    ("private host", re.compile(r"\bcath-w\b")),
    ("private relay", re.compile(r"\b43\.155\.169\.102\b")),
    ("device serial", re.compile(r"\bSM_G9500\b")),
    ("private key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("secret placeholder", re.compile(r"\{\{SECRET_[A-Za-z0-9_]+\}\}")),
    (
        "secret token",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b"
        ),
    ),
]
secret_assignment = re.compile(
    r"(?i)\b(?:access_token|refresh_token|client_secret|account_seed_secret_hex|network_secret|app_psk)"
    r"\s*[:=]\s*[\"']?[^\s\"',}]{12,}"
)
file_pattern = re.compile(
    r"(^|/)(?:\.env(?:\..*)?|.*\.(?:pem|key|p12|pfx|jks|keystore|apk|aab|dylib|so|dll|exe|log|jsonl))$",
    re.I,
)

issues = []
for path in ROOT.rglob("*"):
    if not path.is_file():
        continue
    relative = path.relative_to(ROOT)
    if any(part in SKIP for part in relative.parts):
        continue
    name = relative.as_posix()
    if file_pattern.search(name) and not name.startswith("vendor/"):
        issues.append((name, 0, "private/build filename"))
    if name in TEXT_SCAN_SKIP:
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    for line_number, line in enumerate(text.splitlines(), 1):
        checked = line.replace(ALLOW, "")
        for label, pattern in patterns:
            if pattern.search(checked):
                issues.append((name, line_number, label))
        if path.suffix.lower() in SECRET_CONFIG_SUFFIXES and secret_assignment.search(line):
            issues.append((name, line_number, "credential assignment"))

if issues:
    for name, line_number, label in issues:
        print(f"{name}:{line_number}: {label}")
    print(f"public tree check: FAIL ({len(issues)} finding(s))")
    sys.exit(1)
print("public tree check: PASS")
