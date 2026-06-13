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
  printf '%s' "$value" | tr '[:upper:]' '[:lower:]'
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

check_code_exists() {
  local label="$1"
  local address="$2"
  local chain_code
  chain_code="$(normalize_hex "$(cast code "$address" --rpc-url "$RPC_URL")")"
  if [[ -z "$chain_code" ]]; then
    echo "FAIL $label: no code at $address"
    return 1
  fi
  echo "OK   $label code exists: $address"
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

compare_code_length() {
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

  if [[ "${#chain_code}" -ne "${#expected_code}" ]]; then
    echo "FAIL $label: runtime bytecode length mismatch at $address"
    echo "  onchain length : ${#chain_code}"
    echo "  local length   : ${#expected_code}"
    return 1
  fi

  echo "OK   $label length matches: $address"
}

check_flow_validator() {
  local address="$1"
  local expected_flow="$2"
  local expected_vault="$3"
  local expected_token_decimals="$4"
  local expected_stream_id="$5"
  local expected_max_apr="$6"

  check_code_exists "FlowValidator" "$address" || return 1
  compare_code_length "FlowValidator" "$address" "src/validators/FlowValidator.sol:FlowValidator" || return 1

  local actual_flow actual_vault actual_token_decimals limits_json limit_len actual_stream_id actual_max_apr
  actual_flow="$(cast call "$address" "flow()(address)" --rpc-url "$RPC_URL")"
  actual_vault="$(cast call "$address" "vault()(address)" --rpc-url "$RPC_URL")"
  actual_token_decimals="$(cast call "$address" "tokenDecimals()(uint8)" --rpc-url "$RPC_URL")"
  limits_json="$(cast call "$address" "getLimits()((uint256,uint256)[])" --json --rpc-url "$RPC_URL")"
  limit_len="$(printf '%s' "$limits_json" | jq 'length')"
  actual_stream_id="$(printf '%s' "$limits_json" | jq -r '.[0][0][0]')"
  actual_max_apr="$(printf '%s' "$limits_json" | jq -r '.[0][0][1]')"

  local ok=0
  if [[ "$(normalize_hex "$actual_flow")" != "$(normalize_hex "$expected_flow")" ]]; then
    echo "FAIL FlowValidator flow mismatch"
    echo "  expected: $expected_flow"
    echo "  actual  : $actual_flow"
    ok=1
  fi
  if [[ "$(normalize_hex "$actual_vault")" != "$(normalize_hex "$expected_vault")" ]]; then
    echo "FAIL FlowValidator vault mismatch"
    echo "  expected: $expected_vault"
    echo "  actual  : $actual_vault"
    ok=1
  fi
  if [[ "$actual_token_decimals" != "$expected_token_decimals" ]]; then
    echo "FAIL FlowValidator tokenDecimals mismatch"
    echo "  expected: $expected_token_decimals"
    echo "  actual  : $actual_token_decimals"
    ok=1
  fi
  if [[ "$limit_len" != "1" ]]; then
    echo "FAIL FlowValidator limits length mismatch"
    echo "  expected: 1"
    echo "  actual  : $limit_len"
    ok=1
  fi
  if [[ "$actual_stream_id" != "$expected_stream_id" ]]; then
    echo "FAIL FlowValidator streamId mismatch"
    echo "  expected: $expected_stream_id"
    echo "  actual  : $actual_stream_id"
    ok=1
  fi
  if [[ "$actual_max_apr" != "$expected_max_apr" ]]; then
    echo "FAIL FlowValidator maxApr mismatch"
    echo "  expected: $expected_max_apr"
    echo "  actual  : $actual_max_apr"
    ok=1
  fi

  if [[ "$ok" -eq 0 ]]; then
    echo "OK   FlowValidator configuration matches deployment artifact"
  fi

  return "$ok"
}

check_proxy_slots() {
  local proxy="$1"
  local expected_impl="$2"
  local expected_admin="${3:-}"

  local impl_slot admin_slot impl_addr admin_addr
  impl_slot="$(cast storage "$proxy" "$EIP1967_IMPLEMENTATION_SLOT" --rpc-url "$RPC_URL")"
  admin_slot="$(cast storage "$proxy" "$EIP1967_ADMIN_SLOT" --rpc-url "$RPC_URL")"
  impl_addr="$(trim_slot_to_address "$impl_slot")"
  admin_addr="$(trim_slot_to_address "$admin_slot")"

  local ok=0

  if [[ "$(printf '%s' "$impl_addr" | tr '[:upper:]' '[:lower:]')" != "$(printf '%s' "$expected_impl" | tr '[:upper:]' '[:lower:]')" ]]; then
    echo "FAIL FlowHandler proxy implementation slot mismatch"
    echo "  expected: $expected_impl"
    echo "  actual  : $impl_addr"
    ok=1
  else
    echo "OK   FlowHandler proxy implementation slot: $impl_addr"
  fi

  if [[ -n "$expected_admin" ]]; then
    local expected_admin_code actual_admin_owner=""
    expected_admin_code="$(normalize_hex "$(cast code "$expected_admin" --rpc-url "$RPC_URL")")"

    # Older deployment artifacts stored the proxy-admin owner EOA instead of the actual proxy-admin contract.
    # If the recorded expected admin has no code, only require that the live admin slot is non-zero.
    if [[ -z "$expected_admin_code" ]]; then
      if [[ "$(normalize_hex "$admin_addr")" == "0000000000000000000000000000000000000000" ]]; then
        echo "FAIL FlowHandler proxy admin slot is zero"
        ok=1
      else
        echo "OK   FlowHandler proxy admin slot present: $admin_addr"
        echo "NOTE FlowHandler deployment artifact recorded proxy admin owner, not proxy admin contract"
      fi
      return "$ok"
    fi

    if [[ "$(printf '%s' "$admin_addr" | tr '[:upper:]' '[:lower:]')" != "$(printf '%s' "$expected_admin" | tr '[:upper:]' '[:lower:]')" ]]; then
      actual_admin_owner="$(cast call "$admin_addr" "owner()(address)" --rpc-url "$RPC_URL" 2>/dev/null || true)"
      if [[ -n "$actual_admin_owner" ]] && [[ "$(printf '%s' "$actual_admin_owner" | tr '[:upper:]' '[:lower:]')" == "$(printf '%s' "$expected_admin" | tr '[:upper:]' '[:lower:]')" ]]; then
        echo "OK   FlowHandler proxy admin slot: $admin_addr"
        echo "NOTE FlowHandler deployment artifact recorded proxy admin owner, and the live ProxyAdmin owner matches: $expected_admin"
        return "$ok"
      fi
    fi

    if [[ "$(printf '%s' "$admin_addr" | tr '[:upper:]' '[:lower:]')" != "$(printf '%s' "$expected_admin" | tr '[:upper:]' '[:lower:]')" ]]; then
      echo "FAIL FlowHandler proxy admin slot mismatch"
      echo "  expected: $expected_admin"
      echo "  actual  : $admin_addr"
      ok=1
    else
      echo "OK   FlowHandler proxy admin slot: $admin_addr"
    fi
  else
    if [[ "$(normalize_hex "$admin_addr")" == "0000000000000000000000000000000000000000" ]]; then
      echo "FAIL FlowHandler proxy admin slot is zero"
      ok=1
    else
      echo "OK   FlowHandler proxy admin slot present: $admin_addr"
    fi
  fi

  return "$ok"
}

VALIDATOR_ADDR="$(jq -r '.validator' "$VALIDATOR_JSON")"
VALIDATOR_FLOW="$(jq -r '.flow' "$VALIDATOR_JSON")"
VALIDATOR_VAULT="$(jq -r '.vault' "$VALIDATOR_JSON")"
VALIDATOR_TOKEN_DECIMALS="$(jq -r '.tokenDecimals' "$VALIDATOR_JSON")"
VALIDATOR_STREAM_ID="$(jq -r '.streamId' "$VALIDATOR_JSON")"
VALIDATOR_MAX_APR="$(jq -r '.maxApr' "$VALIDATOR_JSON")"
HANDLER_IMPL_ADDR="$(jq -r '.implementation' "$HANDLER_JSON")"
HANDLER_PROXY_ADDR="$(jq -r '.proxy' "$HANDLER_JSON")"
HANDLER_PROXY_ADMIN="$(jq -r '.proxyAdmin // empty' "$HANDLER_JSON")"
KEEPER_ADDR="$(jq -r '.keeper' "$KEEPER_JSON")"

FAILURES=0

check_flow_validator \
  "$VALIDATOR_ADDR" \
  "$VALIDATOR_FLOW" \
  "$VALIDATOR_VAULT" \
  "$VALIDATOR_TOKEN_DECIMALS" \
  "$VALIDATOR_STREAM_ID" \
  "$VALIDATOR_MAX_APR" || FAILURES=1

compare_runtime_bytecode \
  "FlowHandler implementation" \
  "$HANDLER_IMPL_ADDR" \
  "src/FlowHandler.sol:FlowHandler" || FAILURES=1

check_code_exists \
  "FlowHandler proxy" \
  "$HANDLER_PROXY_ADDR" || FAILURES=1

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
