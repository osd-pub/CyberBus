#!/usr/bin/env bash
# Start a host-native JSONL client. The caller owns stdin/stdout and redaction.
set -euo pipefail
umask 077
[[ $# == 3 || $# == 4 ]] || { echo 'Usage: run-client.sh BINARY PUBLIC_CONFIG PRIVATE_STATE_DIR [open|provision|migrate]' >&2; exit 2; }
binary="$1"; config="$2"; state="$3"
mode="${4:-open}"
case "$mode" in open|provision|migrate) ;; *) echo 'Invalid development store mode' >&2; exit 2 ;; esac
if [[ "$mode" == provision ]]; then
  mkdir -p "$state"
  chmod 700 "$state"
fi
exec "$binary" --config "$config" --state-dir "$state" --store-mode "$mode"
