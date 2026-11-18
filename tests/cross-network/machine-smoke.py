#!/usr/bin/env python3
"""Check the machine client's JSONL boundary without login or ADB."""

import argparse
import base64
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.state_dir.stat().st_mode & 0o077:
        parser.error("private state directory required")
    command_id = base64.b64encode(os.urandom(16)).decode()
    requests = [
        {
            "id": "auth",
            "op": "execute",
            "command": {"commandId": command_id, "getAuthState": {}},
        },
        {"id": "resume", "op": "on_resume"},
        {"id": "exit", "op": "shutdown"},
    ]
    report = {"schema": 1, "suite": "machine-stdio", "status": "failed"}
    try:
        result = subprocess.run(
            [
                str(args.binary),
                "--config",
                str(args.config),
                "--state-dir",
                str(args.state_dir),
            ],
            input="".join(json.dumps(row) + "\n" for row in requests),
            capture_output=True,
            text=True,
            timeout=40,
        )
        assert result.returncode == 0, "machine process exit was nonzero"
        messages = [json.loads(line) for line in result.stdout.splitlines()]
        assert any(message.get("ready") for message in messages)
        responses = {
            message["id"]: message for message in messages if "id" in message
        }
        assert all(
            responses[key].get("ok") is True for key in ("auth", "resume", "exit")
        ), "machine request rejected"
        auth = responses["auth"]["result"]
        assert "error" not in auth, "SDK getAuthState failed"
        assert (
            auth["commandId"] == command_id
            and auth["authState"]["phase"] == "LOGGED_OUT"
        )
        resume = responses["resume"]["result"]
        assert isinstance(resume, dict) and "error" not in resume
        shutdown = responses["exit"]["result"]
        assert isinstance(shutdown, dict) and "error" not in shutdown
        closed = shutdown.get("sdkClosed", {})
        assert (
            closed.get("closed") is True and "cleanupError" not in closed
        ), "SDK cleanup not confirmed"
        assert not any(
            message.get("sdkValid") is False for message in messages
        ), "SDK strict validation failed"
        assert any(
            message.get("eventsClosed") is True for message in messages
        ), "SDK event EOF not confirmed"
        report.update(
            status="passed",
            ready=True,
            jsonl=True,
            correlation=True,
            logged_out=True,
            on_resume=True,
            shutdown=True,
            exit_code=0,
        )
    except Exception as error:
        report["error_type"] = type(error).__name__
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
