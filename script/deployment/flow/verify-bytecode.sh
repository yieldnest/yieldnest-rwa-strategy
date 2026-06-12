#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DEPLOYMENTS_DIR="$ROOT_DIR/deployments"

VALIDATOR_JSON="$DEPLOYMENTS_DIR/flow-validator-deployment.json"
HANDLER_JSON="$DEPLOYMENTS_DIR/flow-handler-deployment.json"
KEEPER_JSON="$DEPLOYMENTS_DIR/flow-keeper-deployment.json"

RPC_URL="${1:-${RPC_URL:-}}"

if [[ -z "$RPC_URL" ]]; then
  echo "usage: $0 <rpc-url>"
  echo "or set RPC_URL in the environment"
  exit 1
fi

for cmd in jq cast forge python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 1
  fi
done

for file in "$VALIDATOR_JSON" "$HANDLER_JSON" "$KEEPER_JSON"; do
  if [[ ! -f "$file" ]]; then
    echo "missing deployment artifact: $file"
    exit 1
  fi
done

EIP1967_IMPLEMENTATION_SLOT="0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN_SLOT="0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"

normalize_hex() {
  local value="${1:-}"
  value="${value#0x}"
  printf '%s' "${value,,}"
}

trim_slot_to_address() {
  python3 - "$1" <<'PY'
import sys
slot = sys.argv[1].lower().replace("0x", "").rjust(64, "0")
print("0x" + slot[-40:])
PY
}

compare_runtime_bytecode() {
  local label="$1"
  local address="$2"
  local artifact="$3"

  local chain_code expected_code
  chain_code="$(normalize_hex "$(cast code "$address" --rpc-url "$RPC_URL")")"
  expected_code="$(normalize_hex "$(forge inspect "$artifact" deployedBytecode)")"

  if [[ -z "$chain_code" ]]; then
    echo "FAIL $label: no code at $address"
    return 1
  fi

  if [[ "$chain_code" != "$expected_code" ]]; then
    echo "FAIL $label: runtime bytecode mismatch at $address"
    echo "  onchain length : ${#chain_code}"
    echo "  local length   : ${#expected_code}"
    echo "  onchain prefix : ${chain_code:0:32}"
    echo "  local prefix   : ${expected_code:0:32}"
    return 1
  fi

  echo "OK   $label: $address"
}

compare_runtime_bytecode_from_artifact_json() {
  local label="$1"
  local address="$2"
  local artifact_json="$3"

  if [[ ! -f "$artifact_json" ]]; then
    echo "FAIL $label: missing local artifact $artifact_json"
    return 1
  fi

  local chain_code expected_code
  chain_code="$(normalize_hex "$(cast code "$address" --rpc-url "$RPC_URL")")"
  expected_code="$(normalize_hex "$(jq -r '.deployedBytecode.object // .deployedBytecode' "$artifact_json")")"

  if [[ -z "$chain_code" ]]; then
    echo "FAIL $label: no code at $address"
    return 1
  fi

  if [[ "$chain_code" != "$expected_code" ]]; then
    echo "FAIL $label: runtime bytecode mismatch at $address"
    echo "  onchain length : ${#chain_code}"
    echo "  local length   : ${#expected_code}"
    echo "  onchain prefix : ${chain_code:0:32}"
    echo "  local prefix   : ${expected_code:0:32}"
    return 1
  fi

  echo "OK   $label: $address"
}

check_proxy_slots() {
  local proxy="$1"
  local expected_impl="$2"
  local expected_admin="$3"

  local impl_slot admin_slot impl_addr admin_addr
  impl_slot="$(cast storage "$proxy" "$EIP1967_IMPLEMENTATION_SLOT" --rpc-url "$RPC_URL")"
  admin_slot="$(cast storage "$proxy" "$EIP1967_ADMIN_SLOT" --rpc-url "$RPC_URL")"
  impl_addr="$(trim_slot_to_address "$impl_slot")"
  admin_addr="$(trim_slot_to_address "$admin_slot")"

  local ok=0

  if [[ "${impl_addr,,}" != "${expected_impl,,}" ]]; then
    echo "FAIL FlowHandler proxy implementation slot mismatch"
    echo "  expected: $expected_impl"
    echo "  actual  : $impl_addr"
    ok=1
  else
    echo "OK   FlowHandler proxy implementation slot: $impl_addr"
  fi

  if [[ "${admin_addr,,}" != "${expected_admin,,}" ]]; then
    echo "FAIL FlowHandler proxy admin slot mismatch"
    echo "  expected: $expected_admin"
    echo "  actual  : $admin_addr"
    ok=1
  else
    echo "OK   FlowHandler proxy admin slot: $admin_addr"
  fi

  return "$ok"
}

VALIDATOR_ADDR="$(jq -r '.validator' "$VALIDATOR_JSON")"
HANDLER_IMPL_ADDR="$(jq -r '.implementation' "$HANDLER_JSON")"
HANDLER_PROXY_ADDR="$(jq -r '.proxy' "$HANDLER_JSON")"
HANDLER_PROXY_ADMIN="$(jq -r '.proxyAdmin' "$HANDLER_JSON")"
KEEPER_ADDR="$(jq -r '.keeper' "$KEEPER_JSON")"

FAILURES=0

compare_runtime_bytecode \
  "FlowValidator" \
  "$VALIDATOR_ADDR" \
  "src/validators/FlowValidator.sol:FlowValidator" || FAILURES=1

compare_runtime_bytecode \
  "FlowHandler implementation" \
  "$HANDLER_IMPL_ADDR" \
  "src/FlowHandler.sol:FlowHandler" || FAILURES=1

compare_runtime_bytecode_from_artifact_json \
  "FlowHandler proxy" \
  "$HANDLER_PROXY_ADDR" \
  "$ROOT_DIR/out/TransparentUpgradeableProxy.sol/TransparentUpgradeableProxy.json" || FAILURES=1

check_proxy_slots \
  "$HANDLER_PROXY_ADDR" \
  "$HANDLER_IMPL_ADDR" \
  "$HANDLER_PROXY_ADMIN" || FAILURES=1

compare_runtime_bytecode \
  "FlowStrategyKeeper" \
  "$KEEPER_ADDR" \
  "src/FlowStrategyKeeper.sol:FlowStrategyKeeper" || FAILURES=1

if [[ "$FAILURES" -ne 0 ]]; then
  echo
  echo "Bytecode verification failed."
  exit 1
fi

echo
echo "All flow deployment bytecode checks passed."
