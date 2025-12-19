#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -x "${SCRIPT_DIR}/query_blob_sidecar.sh" ]]; then
  exec bash "${SCRIPT_DIR}/query_blob_sidecar.sh" "$@"
fi

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Load auto-generated endpoints config, if available
if [[ -f "${SCRIPT_DIR}/rpc_config.sh" ]]; then
  source "${SCRIPT_DIR}/rpc_config.sh"
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DEFAULT_BACK_SLOTS=8192 # ~27 hours on 12s/slot; adjust as needed

show_usage() {
  echo -e "${BLUE}Blob Sidecar Query by Hash${NC}"
  echo "Usage: $0 [--hash <0x01..>] [--tx <0x...>|--block <0x...>|--block-number <N>] [options]"
  echo ""
  echo "Required:"
  echo "  --hash <0xhash>         Blob versioned hash (32 bytes, 0x01-prefixed). Optional if --tx/--block/--block-number given"
  echo ""
  echo "Endpoint options:"
  echo "  -e, --endpoint <URL>    Beacon HTTP URL (overrides auto-detection)"
  echo "  --rpc-endpoint <URL>    Execution-layer RPC URL (for tx/block → slot derivation)"
  echo "  --no-color              Disable ANSI colors in log output"
  echo ""
  echo "Search window options (one of):"
  echo "  --back <N>              Search backward N slots from head (default: ${DEFAULT_BACK_SLOTS})"
  echo "  --from-slot <S>         Start slot (inclusive)"
  echo "  --to-slot <S>           End slot (inclusive)"
  echo "  --asc                   Scan from low slot to high (default: desc from head)"
  echo ""
  echo "Slot derivation options (mutually exclusive):"
  echo "  --tx <0xhash>           Derive slot from transaction hash (uses EL RPC)"
  echo "  --block <0xhash>        Derive slot from block hash (uses EL RPC)"
  echo "  --block-number <N>      Derive slot from block number (uses EL RPC)"
  echo ""
  echo "Filtering options:"
  echo "  --only-tx               With --tx, keep only blobs from that tx"
  echo ""
  echo "Output options:"
  echo "  -o, --output <file>     Save JSON result to file"
  echo "  -p, --pretty            Pretty-print JSON with jq"
  echo "  --no-blob               Remove 'blob' payloads to reduce size"
  echo "  --summary               Output compact summary instead of full data"
  echo "  -h, --help              Show this help information"
  echo ""
  echo "Examples:"
  echo "  $0 --hash 0x... -p"
  echo "  $0 --hash 0x... --endpoint http://172.16.0.12:5052 -p"
  echo "  $0 --hash 0x... --from-slot 123450 --to-slot 123500 -p"
  echo "  $0 --tx 0x<txhash> --endpoint http://172.16.0.12:5052 -p  # derive slot then fetch sidecars/match hash if provided"
  echo "  $0 --tx 0x<txhash> --only-tx --no-blob -p -o out.json       # only blobs from the tx, stripped blob payloads"
  echo "  $0 --block 0x<blockhash> -e http://172.16.0.12:5052 -p"
}

require_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo -e "${RED}Error: jq is required for this script. Please install jq.${NC}" >&2
    exit 1
  fi
}

require_hash_tools() {
  if ! command -v openssl >/dev/null 2>&1 && ! command -v sha256sum >/dev/null 2>&1; then
    echo -e "${RED}Error: Need either openssl or coreutils sha256sum to compute versioned hashes.${NC}" >&2
    exit 1
  fi
  if ! command -v xxd >/dev/null 2>&1; then
    echo -e "${RED}Error: xxd is required to convert hex to bytes. Please install xxd (often in vim-common).${NC}" >&2
    exit 1
  fi
}

test_beacon_connection() {
  local url="$1"
  local resp
  resp=$(curl -s --connect-timeout 3 --max-time 5 "$url/eth/v1/node/identity" 2>/dev/null || true)
  if [[ -n "$resp" ]] && echo "$resp" | grep -q '"data"'; then
    return 0
  else
    return 1
  fi
}

test_rpc_connection() {
  local url="$1"
  local resp
  resp=$(curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    --connect-timeout 3 --max-time 5 "$url" 2>/dev/null || true)
  if [[ -n "$resp" ]] && echo "$resp" | grep -q '"result"'; then
    return 0
  else
    return 1
  fi
}

select_beacon_url_from_config() {
  local chosen=""
  # Prefer IP-based URLs
  if declare -p BEACON_HTTP_URLS_IP >/dev/null 2>&1; then
    for cand in "${BEACON_HTTP_URLS_IP[@]}"; do
      [[ -z "$cand" ]] && continue
      if test_beacon_connection "$cand"; then
        echo "$cand"; return 0
      fi
      [[ -z "$chosen" ]] && chosen="$cand"
    done
  fi
  # Fallback to service hostnames
  if [[ -z "$chosen" ]] && declare -p BEACON_HTTP_URLS_SERVICE >/dev/null 2>&1; then
    for cand in "${BEACON_HTTP_URLS_SERVICE[@]}"; do
      [[ -z "$cand" ]] && continue
      if test_beacon_connection "$cand"; then
        echo "$cand"; return 0
      fi
      [[ -z "$chosen" ]] && chosen="$cand"
    done
  fi
  echo "$chosen"
}

select_rpc_url_from_config() {
  local chosen=""
  if declare -p RPC_ENDPOINTS_IP >/dev/null 2>&1; then
    for cand in "${RPC_ENDPOINTS_IP[@]}"; do
      [[ -z "$cand" ]] && continue
      if test_rpc_connection "$cand"; then echo "$cand"; return 0; fi
      [[ -z "$chosen" ]] && chosen="$cand"
    done
  fi
  if [[ -z "$chosen" ]] && declare -p RPC_ENDPOINTS_SERVICE >/dev/null 2>&1; then
    for cand in "${RPC_ENDPOINTS_SERVICE[@]}"; do
      [[ -z "$cand" ]] && continue
      if test_rpc_connection "$cand"; then echo "$cand"; return 0; fi
      [[ -z "$chosen" ]] && chosen="$cand"
    done
  fi
  echo "$chosen"
}

get_head_slot() {
  local url="$1"
  local resp slot
  resp=$(curl -sS "$url/eth/v2/beacon/blocks/head" 2>/dev/null || true)
  if [[ -z "$resp" ]]; then
    # Fallback to headers endpoint
    resp=$(curl -sS "$url/eth/v1/beacon/headers/head" 2>/dev/null || true)
    slot=$(echo "$resp" | jq -r '.data.header.message.slot // empty')
  else
    slot=$(echo "$resp" | jq -r '.data.message.slot // .data.slot // empty')
  fi
  if [[ -z "$slot" || "$slot" == "null" ]]; then
    echo -e "${RED}Error: Unable to determine head slot from beacon: $url${NC}" >&2
    return 1
  fi
  echo "$slot"
}

# Compute blob versioned hash (0x01 ++ sha256(commitment)) from a kzg commitment hex (0x...)
compute_versioned_hash_from_commitment() {
  local commitment_hex="$1"
  local hex_no_prefix
  hex_no_prefix="${commitment_hex#0x}"
  if [[ -z "$hex_no_prefix" ]]; then
    echo ""; return 1
  fi
  local digest_hex=""
  if command -v openssl >/dev/null 2>&1; then
    digest_hex=$(printf "%s" "$hex_no_prefix" | xxd -r -p | openssl dgst -sha256 -binary | xxd -p -c 256)
  else
    # sha256sum fallback (outputs hex + whitespace + dash)
    digest_hex=$(printf "%s" "$hex_no_prefix" | xxd -r -p | sha256sum | awk '{print $1}')
  fi
  # EIP-4844 versioned hash is 32 bytes: 0x01 || first 31 bytes of sha256(commitment)
  # Truncate digest to 31 bytes (62 hex chars)
  local digest_trunc="${digest_hex:0:62}"
  echo "0x01${digest_trunc}"
}

find_slot_and_index_by_hash() {
  local url="$1"; local hash="$2"; local from_slot="$3"; local to_slot="$4"; local order="$5"
  local s resp lines idx commitment vhash
  if [[ "$order" == "desc" ]]; then
    for (( s=from_slot; s>=to_slot; s-- )); do
      resp=$(curl -sS "$url/eth/v1/beacon/blob_sidecars/$s" 2>/dev/null || true)
      [[ -z "$resp" ]] && continue
      # iterate sidecars
      while IFS= read -r line; do
        idx=$(awk '{print $1}' <<< "$line")
        commitment=$(awk '{print $2}' <<< "$line")
        vhash=$(compute_versioned_hash_from_commitment "$commitment")
        if [[ -n "$vhash" ]] && [[ "${vhash,,}" == "${hash,,}" ]]; then
          echo "$s:$idx"; return 0
        fi
      done < <(echo "$resp" | jq -r '.data[]? | "\(.index) \(.kzg_commitment)"')
    done
  else
    for (( s=from_slot; s<=to_slot; s++ )); do
      resp=$(curl -sS "$url/eth/v1/beacon/blob_sidecars/$s" 2>/dev/null || true)
      [[ -z "$resp" ]] && continue
      while IFS= read -r line; do
        idx=$(awk '{print $1}' <<< "$line")
        commitment=$(awk '{print $2}' <<< "$line")
        vhash=$(compute_versioned_hash_from_commitment "$commitment")
        if [[ -n "$vhash" ]] && [[ "${vhash,,}" == "${hash,,}" ]]; then
          echo "$s:$idx"; return 0
        fi
      done < <(echo "$resp" | jq -r '.data[]? | "\(.index) \(.kzg_commitment)"')
    done
  fi
  return 1
}

query_sidecar_by_slot_index() {
  local url="$1"; local slot="$2"; local index="$3"
  curl -sS "$url/eth/v1/beacon/blob_sidecars/$slot?indices=$index"
}

# Fetch all sidecars for a slot
query_sidecars_by_slot() {
  local url="$1"; local slot="$2"
  curl -sS "$url/eth/v1/beacon/blob_sidecars/$slot"
}

# Get blobVersionedHashes from a transaction receipt (EIP-4844)
get_tx_blob_versioned_hashes() {
  local rpc_url="$1"; local tx_hash="$2"
  local resp
  resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["'$tx_hash'"],"id":1}' "$rpc_url")
  echo "$resp" | jq -r '.result.blobVersionedHashes[]? // empty'
}

# From sidecars response, collect indexes whose commitment-derived versioned hash matches any provided hashes
collect_matching_indexes_by_hashes() {
  local resp_json="$1"; local hashes_str="$2"
  local keep="" idx commitment vhash
  while IFS= read -r line; do
    idx=$(awk '{print $1}' <<< "$line")
    commitment=$(awk '{print $2}' <<< "$line")
    vhash=$(compute_versioned_hash_from_commitment "$commitment")
    if grep -Fxq "$vhash" <<< "$hashes_str"; then
      keep+=" $idx"
    fi
  done < <(echo "$resp_json" | jq -r '.data[]? | "\(.index) \(.kzg_commitment)"')
  echo "$keep"
}

filter_resp_by_indexes() {
  local resp_json="$1"; local indexes_str="$2"
  local expr="" i
  for i in $indexes_str; do
    [[ -z "$i" ]] && continue
    if [[ -n "$expr" ]]; then expr+=" or "; fi
    expr+="(.index == $i)"
  done
  if [[ -z "$expr" ]]; then
    echo "$resp_json"; return 0
  fi
  echo "$resp_json" | jq '{data: [.data[] | select('"$expr"') ]}'
}

strip_blob_payload() {
  local resp_json="$1"
  echo "$resp_json" | jq '{data: [.data[] | del(.blob)]}'
}

make_summary() {
  local resp_json="$1"; local slot="$2"
  echo "$resp_json" | jq --argjson s "$slot" '{slot: $s, sidecar_count: (.data|length), indexes: [.data[].index], kzg_commitments: [.data[].kzg_commitment]}'
}

# Get genesis time and seconds per slot from beacon
get_slotting_params() {
  local url="$1"; local genesis seconds
  genesis=$(curl -sS "$url/eth/v1/beacon/genesis" | jq -r '.data.genesis_time // empty')
  seconds=$(curl -sS "$url/eth/v1/config/spec" | jq -r '.data.SECONDS_PER_SLOT // empty')
  if [[ -z "$genesis" || -z "$seconds" || "$genesis" == "null" || "$seconds" == "null" ]]; then
    echo ""; return 1
  fi
  echo "$genesis $seconds"
}

# Derive slot from EL block timestamp and beacon genesis/spec
derive_slot_from_timestamp() {
  local beacon_url="$1"; local ts="$2"
  local params genesis seconds
  params=$(get_slotting_params "$beacon_url") || { echo ""; return 1; }
  genesis=$(awk '{print $1}' <<< "$params")
  seconds=$(awk '{print $2}' <<< "$params")
  if ! [[ "$ts" =~ ^[0-9]+$ && "$genesis" =~ ^[0-9]+$ && "$seconds" =~ ^[0-9]+$ ]]; then
    echo ""; return 1
  fi
  local diff=$(( ts - genesis ))
  if (( diff < 0 )); then diff=0; fi
  echo $(( diff / seconds ))
}

# Probe ±2 slots to match execution block number
probe_slot_match_block_number() {
  local beacon_url="$1"; local base_slot="$2"; local block_num_dec="$3"
  local s payload_bn
  for s in $base_slot $((base_slot-1)) $((base_slot+1)) $((base_slot-2)) $((base_slot+2)); do
    (( s < 0 )) && continue
    payload_bn=$(curl -sS "$beacon_url/eth/v2/beacon/blocks/$s" | jq -r '.data.message.body.execution_payload.block_number // empty')
    if [[ -n "$payload_bn" && "$payload_bn" != "null" ]]; then
      if [[ "$payload_bn" =~ ^[0-9]+$ ]]; then
        if (( payload_bn == block_num_dec )); then echo "$s"; return 0; fi
      else
        # payload_bn may be hex; handle hex to dec
        local bn_dec=$((16#${payload_bn#0x}))
        if (( bn_dec == block_num_dec )); then echo "$s"; return 0; fi
      fi
    fi
  done
  echo ""; return 1
}

# Derive slot from tx hash / block hash / block number using EL RPC
derive_slot_from_el() {
  local rpc_url="$1"; local beacon_url="$2"; local tx_hash="$3"; local block_hash="$4"; local block_number_in="$5"
  local block_ts=""; local block_num_dec=""; local resp
  if [[ -n "$tx_hash" ]]; then
    resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["'$tx_hash'"],"id":1}' "$rpc_url")
    local block_num_hex=$(echo "$resp" | jq -r '.result.blockNumber // empty')
    if [[ -z "$block_num_hex" || "$block_num_hex" == "null" ]]; then
      resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getTransactionByHash","params":["'$tx_hash'"],"id":1}' "$rpc_url")
      block_num_hex=$(echo "$resp" | jq -r '.result.blockNumber // empty')
    fi
    [[ -z "$block_num_hex" || "$block_num_hex" == "null" ]] && { echo ""; return 1; }
    block_num_dec=$((16#${block_num_hex#0x}))
    resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["'$block_num_hex'", false],"id":1}' "$rpc_url")
    block_ts=$(echo "$resp" | jq -r '.result.timestamp // empty')
    block_ts=$((16#${block_ts#0x}))
  elif [[ -n "$block_hash" ]]; then
    resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getBlockByHash","params":["'$block_hash'", false],"id":1}' "$rpc_url")
    local bn_hex=$(echo "$resp" | jq -r '.result.number // empty')
    [[ -z "$bn_hex" || "$bn_hex" == "null" ]] && { echo ""; return 1; }
    block_num_dec=$((16#${bn_hex#0x}))
    local ts_hex=$(echo "$resp" | jq -r '.result.timestamp // empty')
    [[ -z "$ts_hex" || "$ts_hex" == "null" ]] && { echo ""; return 1; }
    block_ts=$((16#${ts_hex#0x}))
  elif [[ -n "$block_number_in" ]]; then
    local bn_hex
    if [[ "$block_number_in" =~ ^0x[0-9a-fA-F]+$ ]]; then
      bn_hex="$block_number_in"
      block_num_dec=$((16#${bn_hex#0x}))
    else
      # decimal → hex
      bn_hex=$(printf '0x%x' "$block_number_in")
      block_num_dec="$block_number_in"
    fi
    resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["'$bn_hex'", false],"id":1}' "$rpc_url")
    local ts_hex=$(echo "$resp" | jq -r '.result.timestamp // empty')
    [[ -z "$ts_hex" || "$ts_hex" == "null" ]] && { echo ""; return 1; }
    block_ts=$((16#${ts_hex#0x}))
  else
    echo ""; return 1
  fi
  local slot_est
  slot_est=$(derive_slot_from_timestamp "$beacon_url" "$block_ts") || { echo ""; return 1; }
  local slot_match
  slot_match=$(probe_slot_match_block_number "$beacon_url" "$slot_est" "$block_num_dec") || true
  if [[ -n "$slot_match" ]]; then echo "$slot_match"; return 0; fi
  echo "$slot_est"; return 0
}

format_json() {
  local data="$1"; local pretty="${2:-false}"
  if [[ "$pretty" == "true" ]]; then
    echo "$data" | jq '.'
  else
    echo "$data"
  fi
}

main() {
  local beacon_url=""; local rpc_url=""; local blob_hash=""; local back_slots="$DEFAULT_BACK_SLOTS"; local from_slot=""; local to_slot=""; local asc="false"; local output_file=""; local pretty="false"; local tx_hash=""; local block_hash=""; local block_number=""; local no_color="false"; local only_tx="false"; local no_blob="false"; local summary="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --hash)
        blob_hash="$2"; shift 2;;
      -e|--endpoint)
        beacon_url="$2"; shift 2;;
      --rpc-endpoint)
        rpc_url="$2"; shift 2;;
      --no-color)
        no_color="true"; shift;;
      --only-tx)
        only_tx="true"; shift;;
      --back)
        back_slots="$2"; shift 2;;
      --from-slot)
        from_slot="$2"; shift 2;;
      --to-slot)
        to_slot="$2"; shift 2;;
      --asc)
        asc="true"; shift;;
      -o|--output)
        output_file="$2"; shift 2;;
      -p|--pretty)
        pretty="true"; shift;;
      --no-blob)
        no_blob="true"; shift;;
      --summary)
        summary="true"; shift;;
      --tx)
        tx_hash="$2"; shift 2;;
      --block)
        block_hash="$2"; shift 2;;
      --block-number)
        block_number="$2"; shift 2;;
      -h|--help)
        show_usage; exit 0;;
      *)
        echo -e "${RED}Error: Unknown parameter $1${NC}" >&2
        show_usage; exit 1;;
    esac
  done

  # Handle color disabling early
  if [[ "$no_color" == "true" ]]; then
    RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
  fi

  # If neither hash nor tx/block info provided, require hash
  if [[ -z "$blob_hash" && -z "$tx_hash" && -z "$block_hash" && -z "$block_number" ]]; then
    echo -e "${RED}Error: provide --hash or one of (--tx, --block, --block-number)${NC}" >&2
    show_usage; exit 1
  fi

  # sanity check for blob hash (only when provided)
  if [[ -n "$blob_hash" ]]; then
    if ! echo "$blob_hash" | grep -Eq '^0x[0-9a-fA-F]{64}$'; then
      echo -e "${RED}Error: hash must be 0x-prefixed 32-byte hex (bytes32). Given: $blob_hash${NC}" >&2
      exit 1
    fi
    # Versioned hash should start with 0x01 (KZG commitment version)
    if ! echo "$blob_hash" | grep -Eq '^0x01[0-9a-fA-F]{62}$'; then
      echo -e "${YELLOW}Warning: provided hash does not start with 0x01.\nIt may be a raw blob data hash or other identifier, not a versioned hash.\nThe consensus layer stores versioned hashes (0x01 || sha256(commitment)[0:31]).${NC}" >&2
    fi
  fi

  require_jq
  require_hash_tools

  # Endpoint resolution (Beacon)
  if [[ -z "$beacon_url" ]]; then
    if [[ -n "${BEACON_HTTP_URL:-}" ]]; then
      beacon_url="$BEACON_HTTP_URL"
    fi
  fi
  if [[ -z "$beacon_url" ]]; then
    beacon_url=$(select_beacon_url_from_config)
  fi
  if [[ -z "$beacon_url" ]]; then
    echo -e "${RED}Error: Beacon HTTP URL not found. Provide via --endpoint or set BEACON_HTTP_URL, or ensure scripts/rpc_config.sh defines BEACON_HTTP_URLS_IP/BEACON_HTTP_URLS_SERVICE.${NC}" >&2
    exit 1
  fi
  if ! echo "$beacon_url" | grep -Eq '^https?://'; then
    echo -e "${YELLOW}Warning: Beacon URL '$beacon_url' may be missing http/https scheme${NC}" >&2
  fi

  echo -e "${BLUE}Beacon endpoint:${NC} $beacon_url" >&2
  echo -e "${BLUE}Target blob hash:${NC} $blob_hash" >&2

  # Endpoint resolution (RPC) if slot derivation requested
  if [[ -n "$tx_hash" || -n "$block_hash" || -n "$block_number" ]]; then
    if [[ -z "$rpc_url" ]]; then
      if [[ -n "${EL_RPC_URL:-}" ]]; then rpc_url="$EL_RPC_URL"; fi
    fi
    if [[ -z "$rpc_url" ]]; then rpc_url=$(select_rpc_url_from_config); fi
    if [[ -z "$rpc_url" ]]; then
      echo -e "${RED}Error: RPC URL not found. Provide via --rpc-endpoint or set EL_RPC_URL, or ensure scripts/rpc_config.sh defines RPC_ENDPOINTS_IP/SERVICE.${NC}" >&2
      exit 1
    fi
    if ! test_rpc_connection "$rpc_url"; then
      echo -e "${RED}Error: RPC endpoint not responding: $rpc_url${NC}" >&2
      exit 1
    fi
    echo -e "${BLUE}RPC endpoint:${NC} $rpc_url" >&2
  fi

  # Determine search window
  local start end order="desc"
  if [[ -n "$from_slot" || -n "$to_slot" ]]; then
    if [[ -z "$from_slot" || -z "$to_slot" ]]; then
      echo -e "${RED}Error: both --from-slot and --to-slot must be provided together${NC}" >&2
      exit 1
    fi
    start="$from_slot"; end="$to_slot"
  elif [[ -n "$tx_hash" || -n "$block_hash" || -n "$block_number" ]]; then
    local derived_slot
    derived_slot=$(derive_slot_from_el "$rpc_url" "$beacon_url" "$tx_hash" "$block_hash" "$block_number") || {
      echo -e "${RED}Error: failed to derive slot from provided tx/block information${NC}" >&2
      exit 1
    }
    start="$derived_slot"; end="$derived_slot"
    echo -e "${BLUE}Derived slot:${NC} $derived_slot (from tx/block info)" >&2
  else
    local head_slot
    head_slot=$(get_head_slot "$beacon_url")
    start="$head_slot"
    local tmp=$(( head_slot - back_slots ))
    if (( tmp < 0 )); then tmp=0; fi
    end="$tmp"
  fi

  if [[ "$asc" == "true" ]]; then order="asc"; fi
  echo -e "${BLUE}Search window:${NC} ${start} -> ${end} (${order})" >&2

  # If hash provided, match index by commitment-derived versioned hash.
  local resp
  if [[ -n "$blob_hash" ]]; then
    local found
    if ! found=$(find_slot_and_index_by_hash "$beacon_url" "$blob_hash" "$start" "$end" "$order"); then
      echo -e "${RED}Not found: blob hash not present in scanned slots${NC}" >&2
      exit 2
    fi
    local slot idx
    slot="${found%%:*}"; idx="${found##*:}"
    echo -e "${GREEN}Found at slot:${NC} $slot  ${GREEN}index:${NC} $idx" >&2
    resp=$(query_sidecar_by_slot_index "$beacon_url" "$slot" "$idx") || {
      echo -e "${RED}Error: Failed to fetch sidecar for slot $slot index $idx${NC}" >&2
      exit 1
    }
  else
    # No hash: just fetch all sidecars for the derived or chosen window (single slot expected)
    if [[ "$start" != "$end" ]]; then
      echo -e "${YELLOW}Warning: without --hash, only single-slot fetch is supported. Consider providing --tx/--block or set --from/to to same slot.${NC}" >&2
    fi
    resp=$(query_sidecars_by_slot "$beacon_url" "$start") || {
      echo -e "${RED}Error: Failed to fetch sidecars for slot $start${NC}" >&2
      exit 1
    }
    echo -e "${GREEN}Fetched sidecars at slot:${NC} $start" >&2
  fi

  # Optional: keep only blobs from the given tx
  if [[ "$only_tx" == "true" ]]; then
    if [[ -z "$tx_hash" ]]; then
      echo -e "${YELLOW}Warning: --only-tx provided without --tx; skipping tx-side filtering${NC}" >&2
    else
      local tx_hashes
      tx_hashes=$(get_tx_blob_versioned_hashes "$rpc_url" "$tx_hash")
      if [[ -z "$tx_hashes" ]]; then
        echo -e "${YELLOW}Warning: tx has no blobVersionedHashes or receipt unavailable; skipping tx-side filtering${NC}" >&2
      else
        local keep_indexes
        keep_indexes=$(collect_matching_indexes_by_hashes "$resp" "$tx_hashes")
        resp=$(filter_resp_by_indexes "$resp" "$keep_indexes")
      fi
    fi
  fi

  # Optional: strip heavy blob payload
  if [[ "$no_blob" == "true" ]]; then
    resp=$(strip_blob_payload "$resp")
  fi

  # Optional: summary output
  if [[ "$summary" == "true" ]]; then
    resp=$(make_summary "$resp" "$start")
  fi
  
  # Output
  if [[ -n "$output_file" ]]; then
    format_json "$resp" "$pretty" > "$output_file"
    echo -e "${GREEN}Result saved to: $output_file${NC}" >&2
  else
    echo -e "${YELLOW}=== Blob Sidecar ===${NC}" >&2
    format_json "$resp" "$pretty"
  fi
}

main "$@"
