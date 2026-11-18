# Contributing

Read [docs/INTEGRATION.md](docs/INTEGRATION.md) before changing public commands, events,
storage, or native ownership. Keep generated artifacts, local state, credentials, and
machine-specific reports out of commits.

Before opening a pull request, run `cargo fmt --all -- --check`, the workspace tests,
`python3 scripts/check-public-tree.py`, and `git diff --check`. Describe platform and
toolchain coverage, and label live integration checks separately from offline fixtures.
