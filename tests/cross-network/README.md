# Cross-network smoke fixtures

This directory contains small, explicitly parameterized transport and machine
smoke tools. They do not contain default hosts, account credentials, device
serials, or deployment paths. Build the probe first and pass every endpoint,
binary, state directory, and output directory on the command line.

- `machine-smoke.py` checks the machine client's JSONL boundary, authenticated
  state query, resume hook, shutdown result, and event EOF without logging in.
- `scripts/diagnose-easytier.py` exercises raw or Noise transport between two
  explicitly selected peers.
- `scripts/diagnose-cloudflare.py` owns a local WebSocket relay and optional
  official anonymous cloudflared connector during the probe.

These tools validate transport or SDK lifecycle slices. They do not establish
hosted OIDC login, application ACK delivery, cross-network recovery, or platform
runtime acceptance.
