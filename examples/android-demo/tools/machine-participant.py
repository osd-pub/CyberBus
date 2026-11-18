#!/usr/bin/env python3
"""JSONL machine adapter for the real Android sample's private instrumentation bridge.

Requires Python protobuf. --machine-binary is used only for --describe reflection,
never for SDK creation. stdout is protocol only; diagnostics are fixed strings.
"""
import argparse
import base64
import fcntl
import json
import importlib.util
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from google.protobuf import descriptor_pb2, descriptor_pool, json_format, message_factory

PRIVATE = "no_backup/multiclient/"
spec = importlib.util.spec_from_file_location("android_sample_diagnostics",
    Path(__file__).resolve().parents[3] / "tests/cross-network/android-sample.py")
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


def output(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


class Adapter:
    def __init__(self, args):
        self.args = args
        self.adb = [args.adb, "-s", args.serial]
        described = subprocess.run([str(args.machine_binary), "--describe"], check=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
        self.description = json.loads(described.stdout)
        self.description["clientApi"] = ["execute", "execute_bytes", "on_resume", "take_event_receiver"]
        self.description["androidBridge"] = dict(
            commands=["getDevices", "refreshDevices", "networkStart", "networkStop", "send", "getAuthState"],
            externalAuth=True, preconfigured=True, autoCompleteData=True,
            validation="protobuf decoding and command correlation; no Rust strict-codec marker")
        descriptor = descriptor_pb2.FileDescriptorSet.FromString(
            base64.b64decode(self.description["descriptorSet"], validate=True))
        pool = descriptor_pool.DescriptorPool()
        remaining = list(descriptor.file)
        while remaining:
            next_files = []
            for file in remaining:
                try:
                    pool.Add(file)
                except Exception:
                    next_files.append(file)
            if len(next_files) == len(remaining):
                raise RuntimeError("descriptor_dependency_failed")
            remaining = next_files
        self.pool = pool
        self.types = {name: message_factory.GetMessageClass(
            pool.FindMessageTypeByName("cyberbus.easytier.v1." + name))
            for name in ("SdkCommand", "SdkResult", "SdkEvent")}
        self.offset = 0
        self.partial = b""
        self.closed = False
        self.lock = None
        self.completion_enabled = False
        self.completion_offset = 0
        self.completion_partial = b""
        self.completion_rows = 0
        self.completion_invalid = False
        self.completion_error_codes = set(pool.FindEnumTypeByName("cyberbus.easytier.v1.ErrorCode").values_by_name)

    def run_adb(self, *args, data=None, optional=False):
        result = subprocess.run(self.adb + list(args), input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=15)
        if result.returncode and not optional:
            raise RuntimeError("private_adb_io_failed")
        return result.stdout if result.returncode == 0 else None

    def read(self, name, optional=False):
        # shell v2 carries the remote exit status; exec-out can return zero and
        # merge a missing-file diagnostic into stdout on older Android devices.
        return self.run_adb("shell", "-T", "run-as", "io.cyberbus.demo", "cat", PRIVATE + name,
                            optional=optional)

    def decode(self, kind, encoded):
        message = self.types[kind].FromString(base64.b64decode(encoded, validate=True))
        if not message.WhichOneof("body"):
            raise RuntimeError("missing_sdk_body")
        return json_format.MessageToDict(message, descriptor_pool=self.pool)

    def events(self):
        raw = self.run_adb("exec-out", "run-as", "io.cyberbus.demo", "tail", "-c",
                           "+" + str(self.offset + 1), PRIVATE + "events.ndjson")
        self.offset += len(raw)
        self.partial += raw
        if len(self.partial) > 32 * 1024 * 1024:
            raise RuntimeError("event_transport_overflow")
        rows = self.partial.split(b"\n")
        self.partial = rows.pop()
        for row in rows:
            event = self.decode("SdkEvent", json.loads(row)["event_base64"])
            # Sequence/runtime/correlation come unchanged from the native SDK.
            output({"event": event})
        self.completion_events()

    def completion_events(self):
        if not self.completion_enabled:
            return
        try:
            raw = self.run_adb("exec-out", "run-as", "io.cyberbus.demo", "tail", "-c",
                "+" + str(self.completion_offset + 1), PRIVATE + "completions.ndjson")
            self.completion_offset += len(raw)
            if self.completion_offset > 512 * 1024:
                self.completion_invalid = True
                self.completion_partial = b""
                return
            self.completion_partial += raw
            rows = self.completion_partial.split(b"\n")
            self.completion_partial = rows.pop()
            if len(self.completion_partial) > 2048:
                self.completion_invalid = True
                self.completion_partial = b""
            for row in rows:
                try:
                    if len(row) > 2048:
                        raise ValueError("diagnostic_line_bound")
                    value = diagnostics.completion_diagnostic(json.loads(row), self.completion_error_codes)
                    if value["sequence"] != self.completion_rows + 1:
                        raise ValueError("diagnostic_sequence")
                    self.completion_rows += 1
                    output({"appCompletionDiagnostic": value})
                except Exception:
                    self.completion_invalid = True
        except Exception:
            self.completion_invalid = True

    def completion_closed(self):
        if not self.completion_enabled:
            return
        # SdkClose has settled the existing worker before this final journal read.
        self.completion_events()
        try:
            raw = self.read("completions-closed.json")
            if len(raw) > 1024:
                raise ValueError("diagnostic_summary_bound")
            value = json.loads(raw)
            if not isinstance(value, dict) or "transportInvalid" in value:
                raise ValueError("diagnostic_summary_fields")
            value["transportInvalid"] = self.completion_invalid or bool(self.completion_partial)
            summary = diagnostics.completion_summary(value)
            if summary["rows"] != self.completion_rows or summary["bytes"] != self.completion_offset:
                summary["transportInvalid"] = True
        except Exception:
            summary = dict(rows=self.completion_rows, bytes=min(self.completion_offset, 512 * 1024),
                dropped=False, writeFailed=False, closed=False, transportInvalid=True)
        output({"appCompletionDiagnosticsClosed": summary})

    def exchange(self, op, command=None):
        rid = uuid.uuid4().hex
        request = dict(request_id=rid, op=op)
        if command is not None:
            request["command_base64"] = base64.b64encode(command).decode()
        data = json.dumps(request).encode()
        if len(data) > 2 * 1024 * 1024:
            raise RuntimeError("request_too_large")
        # Only static shell text is passed here. Protocol bytes enter through stdin.
        self.run_adb("shell", "-T", "run-as", "io.cyberbus.demo", "sh", "-c",
                     "'umask 077; cat > no_backup/multiclient/request.tmp; "
                     "mv no_backup/multiclient/request.tmp no_backup/multiclient/request.json'",
                     data=data)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            self.events()
            raw = self.read("reply.json", optional=True)
            if raw:
                reply = json.loads(raw)
                if reply.get("request_id") == rid:
                    if reply.get("error"):
                        raise RuntimeError("app_transport_rejected")
                    return reply
            time.sleep(0.1)
        raise RuntimeError("app_reply_timeout")

    def request(self, request):
        op = request.get("op")
        if op == "describe":
            return self.description
        if op in ("execute", "execute_bytes"):
            if op == "execute":
                command = self.types["SdkCommand"]()
                json_format.ParseDict(request["command"], command, ignore_unknown_fields=False, descriptor_pool=self.pool)
                raw = command.SerializeToString()
            else:
                raw = base64.b64decode(request["bytes"], validate=True)
            reply = self.exchange("execute", raw)
            result = self.decode("SdkResult", reply["result_base64"])
            return result if op == "execute" else dict(bytes=reply["result_base64"], result=result)
        if op == "on_resume":
            reply = self.exchange("on_resume")
            return {} if reply.get("resumed") else {"error": {"code": "UNAVAILABLE"}}
        if op == "take_event_receiver":
            return {"taken": False}  # The actual App owns its one native receiver.
        if op == "shutdown":
            try:
                reply = self.exchange("shutdown")
                result = self.decode("SdkResult", reply["result_base64"])
                closed = result.get("sdkClosed", {})
                if not closed.get("closed") or "cleanupError" in closed:
                    raise RuntimeError("sdk_cleanup_unconfirmed")
                self.events()
                if not json.loads(self.read("closed.json")).get("eventsClosed"):
                    raise RuntimeError("events_closure_unconfirmed")
                self.closed = True
                return result
            finally:
                # Observation finalization must also run when real SDK cleanup fails.
                # This never supplies successful SDK shutdown or event-EOF evidence.
                self.completion_closed()
        raise RuntimeError("operation_not_supported")

    def run(self):
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", self.args.serial):
            raise RuntimeError("invalid_device_serial")
        path = Path(tempfile.gettempdir()) / ("cyberbus-android-participant-" + self.args.serial + ".lock")
        self.lock = path.open("a+")
        os.chmod(path, 0o600)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        deadline = time.monotonic() + self.args.ready_timeout
        ready = None
        while time.monotonic() < deadline:
            raw = self.read("ready.json", optional=True)
            if raw:
                ready = json.loads(raw)
                break
            time.sleep(0.25)
        if not ready or not ready.get("ready"):
            raise RuntimeError("app_not_ready")
        self.completion_enabled = ready.get("completionDiagnostics") is True
        output(dict(ready, events="receiver"))
        requests = queue.Queue(maxsize=32)

        def input_loop():
            pending = b""
            while True:
                # A daemon blocked in buffered stdin can abort Python at shutdown.
                # Raw fd reads leave no interpreter buffered-reader lock held.
                chunk = os.read(sys.stdin.fileno(), 65536)
                if not chunk:
                    if pending:
                        requests.put(pending)
                    requests.put(b"")
                    return
                pending += chunk
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    requests.put(line + b"\n")
                if len(pending) > 2 * 1024 * 1024:
                    requests.put(pending)
                    return

        threading.Thread(target=input_loop, daemon=True).start()
        while not self.closed:
            self.events()
            try:
                line = requests.get(timeout=0.1)
            except queue.Empty:
                continue
            if not line:
                self.request({"op": "shutdown"})
                break
            rid = None
            request = None
            try:
                if len(line) > 2 * 1024 * 1024:
                    raise RuntimeError("request_too_large")
                request = json.loads(line)
                rid = request.get("id")
                result = self.request(request)
                output(dict(id=rid, ok=True, result=result))
            except Exception as error:
                # No exception text, command JSON, URL or callback reaches stderr/stdout.
                output(dict(id=rid, ok=False, error="android_machine_request_rejected", errorType=type(error).__name__))
                if isinstance(request, dict) and request.get("op") == "shutdown":
                    raise RuntimeError("sdk_shutdown_failed")
        output({"eventsClosed": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial", required=True)
    parser.add_argument("--machine-binary", type=Path, required=True)
    parser.add_argument("--ready-timeout", type=float, default=30)
    parser.add_argument("--describe", action="store_true")
    args = parser.parse_args()
    try:
        adapter = Adapter(args)
        if args.describe:
            output(adapter.description)
        else:
            adapter.run()
    except Exception as error:
        print("android-machine: private transport failed (" + type(error).__name__ + ")", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
