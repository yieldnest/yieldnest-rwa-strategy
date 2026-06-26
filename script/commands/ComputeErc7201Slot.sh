#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <namespace>"
  echo "Example: $0 yieldnest.storage.flow_handler"
  exit 1
fi

if ! command -v cast >/dev/null 2>&1; then
  echo "Error: 'cast' is required but not found in PATH." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: 'python3' is required but not found in PATH." >&2
  exit 1
fi

namespace="$1"
raw="$(cast keccak "$namespace")"

RAW_HEX="$raw" NAMESPACE="$namespace" python3 - <<'PY'
import os
import subprocess

raw_hex = os.environ["RAW_HEX"]
raw = int(raw_hex, 16)
minus1 = "0x" + format((raw - 1) % (1 << 256), "064x")
rehash = subprocess.check_output(["cast", "keccak", minus1], text=True).strip()
slot = int(rehash, 16) & ~0xff

print(f"namespace: {os.environ.get('NAMESPACE', '')}".rstrip())
print(f"raw keccak: 0x{raw:064x}")
print(f"minus one:  {minus1}")
print(f"rehash:     {rehash}")
print(f"erc7201:    0x{slot:064x}")
PY
