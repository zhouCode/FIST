#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/rpc_config.sh" ]]; then
  source "${SCRIPT_DIR}/rpc_config.sh"
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DEFAULT_BLOCK_ID="head"

show_usage() {
  echo -e "${BLUE}Beacon Blob Sidecar Query Tool${NC}"
  echo "Usage: $0 [options]"
  echo ""
  echo "Endpoint:"
  echo "  -e, --endpoint <URL>         Beacon HTTP URL"
  echo "  --rpc-endpoint <URL>         Execution RPC URL"
  echo ""
  echo "Query by block/slot:"
  echo "  -b, --block <id>             Block id (head/finalized/justified/<slot>/<root>)"
  echo "  -s, --slot <slot>            Slot number"
  echo "  -i, --indices <csv>          Indices filter (e.g., 0,1)"
  echo ""
  echo "Query by blob:"
  echo "  --hash <0x...>               Blob versioned hash"
  echo "  --tx <0x...>                 Derive slot from tx hash"
  echo "  --block <0x...>              Derive slot from block hash"
  echo "  --block-number <N>           Derive slot from block number"
  echo "  --only-tx                    Keep only blobs from the tx"
  echo "  --receipt                    Find tx by hash and output its receipt"
  echo ""
  echo "Search window:"
  echo "  --back <N>                   Scan back N slots from head"
  echo "  --from-slot <S>              Start slot"
  echo "  --to-slot <S>                End slot"
  echo "  --asc                        Scan ascending"
  echo ""
  echo "Output:"
  echo "  -o, --output <file>          Save JSON"
  echo "  -p, --pretty                 Pretty-print JSON"
  echo "  --no-blob                    Strip blob payload"
  echo "  --summary                    Output compact summary"
  echo "  --no-color                   Disable ANSI colors"
  echo "  -h, --help                   Show help"
  echo ""
  echo "Examples:"
  echo "  $0 -b head -p"
  echo "  $0 --hash 0x01.. -p"
  echo "  $0 --tx 0x<txhash> --only-tx --no-blob -p"
}

 
select_beacon_url_from_config() {
  local chosen=""
  if declare -p BEACON_HTTP_URLS_IP >/dev/null 2>&1; then
    for cand in "${BEACON_HTTP_URLS_IP[@]}"; do
      [[ -z "$cand" ]] && continue
      if test_beacon_connection "$cand"; then
        echo "$cand"; return 0
      fi
      [[ -z "$chosen" ]] && chosen="$cand"
    done
  fi
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
  resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' --connect-timeout 3 --max-time 5 "$url" 2>/dev/null || true)
  if [[ -n "$resp" ]] && echo "$resp" | grep -q '"result"'; then
    return 0
  else
    return 1
  fi
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

format_json() {
  local data="$1"; local pretty="${2:-false}"
  if [[ "$pretty" == "true" ]] && command -v jq >/dev/null 2>&1; then
    echo "$data" | jq '.'
  else
    echo "$data"
  fi
}

query_blob_sidecars() {
  local beacon_url="$1"; local block_id="$2"; local indices_csv="${3:-}"
  local url_path="/eth/v1/beacon/blob_sidecars/${block_id}"
  local full_url="$beacon_url$url_path"
  if [[ -n "$indices_csv" ]]; then
    full_url="$full_url?indices=$indices_csv"
  fi
  local response
  response=$(curl -sS -X GET "$full_url") || { echo -e "${RED}Error: Failed to query Beacon API${NC}" >&2; return 1; }
  if echo "$response" | grep -q '"data"'; then
    echo "$response"; return 0
  else
    echo -e "${RED}Error: Unexpected response from Beacon API${NC}" >&2
    echo "$response"; return 1
  fi
}

get_head_slot() {
  local url="$1"; local resp slot
  resp=$(curl -sS "$url/eth/v2/beacon/blocks/head" 2>/dev/null || true)
  if [[ -z "$resp" ]]; then
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

compute_versioned_hash_from_commitment() {
  local commitment_hex="$1"; local hex_no_prefix; hex_no_prefix="${commitment_hex#0x}"; [[ -z "$hex_no_prefix" ]] && { echo ""; return 1; }
  local digest_hex=""
  if command -v openssl >/dev/null 2>&1; then
    digest_hex=$(printf "%s" "$hex_no_prefix" | xxd -r -p | openssl dgst -sha256 -binary | xxd -p -c 256)
  else
    digest_hex=$(printf "%s" "$hex_no_prefix" | xxd -r -p | sha256sum | awk '{print $1}')
  fi
  local digest_trunc="${digest_hex:0:62}"
  echo "0x01${digest_trunc}"
}

find_slot_and_index_by_hash() {
  local url="$1"; local hash="$2"; local from_slot="$3"; local to_slot="$4"; local order="$5"
  local s resp idx commitment vhash
  if [[ "$order" == "desc" ]]; then
    for (( s=from_slot; s>=to_slot; s-- )); do
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

query_sidecars_by_slot() {
  local url="$1"; local slot="$2"
  curl -sS "$url/eth/v1/beacon/blob_sidecars/$slot"
}

get_tx_blob_versioned_hashes() {
  local rpc_url="$1"; local tx_hash="$2"; local resp
  resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["'"$tx_hash"'"],"id":1}' "$rpc_url")
  echo "$resp" | jq -r '.result.blobVersionedHashes[]? // empty'
}

collect_matching_indexes_by_hashes() {
  local resp_json="$1"; local hashes_str="$2"; local keep="" idx commitment vhash
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
  local resp_json="$1"; local indexes_str="$2"; local expr="" i
  for i in $indexes_str; do
    [[ -z "$i" ]] && continue
    [[ -n "$expr" ]] && expr+=" or "
    expr+="(.index == $i)"
  done
  [[ -z "$expr" ]] && { echo "$resp_json"; return 0; }
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

derive_versioned_hashes_from_sidecars_json() {
  local resp_json="$1"; local line vhash out=""
  while IFS= read -r line; do
    vhash=$(compute_versioned_hash_from_commitment "$line")
    [[ -n "$vhash" ]] && out+="$vhash\n"
  done < <(echo "$resp_json" | jq -r '.data[]? | .kzg_commitment // empty')
  printf "%b" "$out"
}

json_array_from_lines() {
  jq -R -s 'split("\n") | map(select(length>0))'
}

get_slotting_params() {
  local url="$1"; local genesis seconds
  genesis=$(curl -sS "$url/eth/v1/beacon/genesis" | jq -r '.data.genesis_time // empty')
  seconds=$(curl -sS "$url/eth/v1/config/spec" | jq -r '.data.SECONDS_PER_SLOT // empty')
  [[ -z "$genesis" || -z "$seconds" || "$genesis" == "null" || "$seconds" == "null" ]] && { echo ""; return 1; }
  echo "$genesis $seconds"
}

derive_slot_from_timestamp() {
  local beacon_url="$1"; local ts="$2"; local params genesis seconds
  params=$(get_slotting_params "$beacon_url") || { echo ""; return 1; }
  genesis=$(awk '{print $1}' <<< "$params")
  seconds=$(awk '{print $2}' <<< "$params")
  if ! [[ "$ts" =~ ^[0-9]+$ && "$genesis" =~ ^[0-9]+$ && "$seconds" =~ ^[0-9]+$ ]]; then
    echo ""; return 1
  fi
  local diff=$(( ts - genesis )); (( diff < 0 )) && diff=0
  echo $(( diff / seconds ))
}

probe_slot_match_block_number() {
  local beacon_url="$1"; local base_slot="$2"; local block_num_dec="$3"; local s payload_bn
  for s in $base_slot $((base_slot-1)) $((base_slot+1)) $((base_slot-2)) $((base_slot+2)); do
    (( s < 0 )) && continue
    payload_bn=$(curl -sS "$beacon_url/eth/v2/beacon/blocks/$s" | jq -r '.data.message.body.execution_payload.block_number // empty')
    if [[ -n "$payload_bn" && "$payload_bn" != "null" ]]; then
      if [[ "$payload_bn" =~ ^[0-9]+$ ]]; then
        (( payload_bn == block_num_dec )) && { echo "$s"; return 0; }
      else
        local bn_dec=$((16#${payload_bn#0x}))
        (( bn_dec == block_num_dec )) && { echo "$s"; return 0; }
      fi
    fi
  done
  echo ""; return 1
}

derive_slot_from_el() {
  local rpc_url="$1"; local beacon_url="$2"; local tx_hash="$3"; local block_hash="$4"; local block_number_in="$5"; local block_ts=""; local block_num_dec=""; local resp
  if [[ -n "$tx_hash" ]]; then
    resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["'"$tx_hash"'"],"id":1}' "$rpc_url")
    local block_num_hex=$(echo "$resp" | jq -r '.result.blockNumber // empty')
    if [[ -z "$block_num_hex" || "$block_num_hex" == "null" ]]; then
      resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getTransactionByHash","params":["'"$tx_hash"'"],"id":1}' "$rpc_url")
      block_num_hex=$(echo "$resp" | jq -r '.result.blockNumber // empty')
    fi
    [[ -z "$block_num_hex" || "$block_num_hex" == "null" ]] && { echo ""; return 1; }
    block_num_dec=$((16#${block_num_hex#0x}))
    resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["'"$block_num_hex"'", false],"id":1}' "$rpc_url")
    block_ts=$(echo "$resp" | jq -r '.result.timestamp // empty'); block_ts=$((16#${block_ts#0x}))
  elif [[ -n "$block_hash" ]]; then
    resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getBlockByHash","params":["'"$block_hash"'", false],"id":1}' "$rpc_url")
    local bn_hex=$(echo "$resp" | jq -r '.result.number // empty'); [[ -z "$bn_hex" || "$bn_hex" == "null" ]] && { echo ""; return 1; }
    block_num_dec=$((16#${bn_hex#0x}))
    local ts_hex=$(echo "$resp" | jq -r '.result.timestamp // empty'); [[ -z "$ts_hex" || "$ts_hex" == "null" ]] && { echo ""; return 1; }
    block_ts=$((16#${ts_hex#0x}))
  elif [[ -n "$block_number_in" ]]; then
    local bn_hex
    if [[ "$block_number_in" =~ ^0x[0-9a-fA-F]+$ ]]; then
      bn_hex="$block_number_in"; block_num_dec=$((16#${bn_hex#0x}))
    else
      bn_hex=$(printf '0x%x' "$block_number_in"); block_num_dec="$block_number_in"
    fi
    resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["'"$bn_hex"'", false],"id":1}' "$rpc_url")
    local ts_hex=$(echo "$resp" | jq -r '.result.timestamp // empty'); [[ -z "$ts_hex" || "$ts_hex" == "null" ]] && { echo ""; return 1; }
    block_ts=$((16#${ts_hex#0x}))
  else
    echo ""; return 1
  fi
  local slot_est; slot_est=$(derive_slot_from_timestamp "$beacon_url" "$block_ts") || { echo ""; return 1; }
  local slot_match; slot_match=$(probe_slot_match_block_number "$beacon_url" "$slot_est" "$block_num_dec") || true
  if [[ -n "$slot_match" ]]; then echo "$slot_match"; return 0; fi
  echo "$slot_est"; return 0
}

require_jq() { if ! command -v jq >/dev/null 2>&1; then echo -e "${RED}Error: jq is required${NC}" >&2; exit 1; fi }
require_hash_tools() {
  if ! command -v openssl >/dev/null 2>&1 && ! command -v sha256sum >/dev/null 2>&1; then echo -e "${RED}Error: openssl or sha256sum required${NC}" >&2; exit 1; fi
  if ! command -v xxd >/dev/null 2>&1; then echo -e "${RED}Error: xxd required${NC}" >&2; exit 1; fi
}

main() {
  local beacon_url="" rpc_url="" blob_hash="" back_slots=8192 from_slot="" to_slot="" asc="false" output_file="" pretty="false" tx_hash="" block_hash_in="" block_number="" no_color="false" only_tx="false" no_blob="false" summary="false" receipt="false" block_id="$DEFAULT_BLOCK_ID" slot="" indices=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -e|--endpoint) beacon_url="$2"; shift 2;;
      --rpc-endpoint) rpc_url="$2"; shift 2;;
      -b|--block) block_id="$2"; shift 2;;
      -s|--slot) slot="$2"; shift 2;;
      -i|--indices) indices="$2"; shift 2;;
      --hash) blob_hash="$2"; shift 2;;
      --tx) tx_hash="$2"; shift 2;;
      --block) block_hash_in="$2"; shift 2;;
      --block-number) block_number="$2"; shift 2;;
      --only-tx) only_tx="true"; shift;;
      --back) back_slots="$2"; shift 2;;
      --from-slot) from_slot="$2"; shift 2;;
      --to-slot) to_slot="$2"; shift 2;;
      --asc) asc="true"; shift;;
      -o|--output) output_file="$2"; shift 2;;
      -p|--pretty) pretty="true"; shift;;
      --no-blob) no_blob="true"; shift;;
      --summary) summary="true"; shift;;
      --receipt) receipt="true"; shift;;
      --no-color) no_color="true"; shift;;
      -h|--help) show_usage; exit 0;;
      *) echo -e "${RED}Error: Unknown parameter $1${NC}" >&2; show_usage; exit 1;;
    esac
  done
  if [[ "$no_color" == "true" ]]; then RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''; fi
  if [[ -n "$slot" ]]; then block_id="$slot"; fi
  if [[ -z "$beacon_url" ]]; then if [[ -n "${BEACON_HTTP_URL:-}" ]]; then beacon_url="$BEACON_HTTP_URL"; fi; fi
  if [[ -z "$beacon_url" ]]; then beacon_url=$(select_beacon_url_from_config); fi
  if [[ -z "$beacon_url" ]]; then echo -e "${RED}Error: Beacon HTTP URL not found${NC}" >&2; exit 1; fi
  if ! echo "$beacon_url" | grep -Eq '^https?://'; then echo -e "${YELLOW}Warning: Beacon URL '$beacon_url' may be missing http/https scheme${NC}"; fi
  echo -e "${BLUE}Beacon endpoint:${NC} $beacon_url"

  if [[ -n "$blob_hash" || -n "$tx_hash" || -n "$block_hash_in" || -n "$block_number" || -n "$from_slot" || -n "$to_slot" ]]; then
    if [[ -n "$tx_hash" || -n "$block_hash_in" || -n "$block_number" ]]; then
      if [[ -z "$rpc_url" ]]; then if [[ -n "${EL_RPC_URL:-}" ]]; then rpc_url="$EL_RPC_URL"; fi; fi
      if [[ -z "$rpc_url" ]]; then rpc_url=$(select_rpc_url_from_config); fi
      if [[ -z "$rpc_url" ]]; then echo -e "${RED}Error: RPC URL not found${NC}" >&2; exit 1; fi
      if ! test_rpc_connection "$rpc_url"; then echo -e "${RED}Error: RPC endpoint not responding: $rpc_url${NC}" >&2; exit 1; fi
      echo -e "${BLUE}RPC endpoint:${NC} $rpc_url"
    fi
    local start end order="desc"
    if [[ -n "$from_slot" || -n "$to_slot" ]]; then
      if [[ -z "$from_slot" || -z "$to_slot" ]]; then echo -e "${RED}Error: both --from-slot and --to-slot must be provided${NC}" >&2; exit 1; fi
      start="$from_slot"; end="$to_slot"
    elif [[ -n "$tx_hash" || -n "$block_hash_in" || -n "$block_number" ]]; then
      local derived_slot; derived_slot=$(derive_slot_from_el "$rpc_url" "$beacon_url" "$tx_hash" "$block_hash_in" "$block_number") || { echo -e "${RED}Error: failed to derive slot${NC}" >&2; exit 1; }
      start="$derived_slot"; end="$derived_slot"; echo -e "${BLUE}Derived slot:${NC} $derived_slot" >&2
    else
      local head_slot; head_slot=$(get_head_slot "$beacon_url")
      start="$head_slot"; local tmp=$(( head_slot - back_slots )); (( tmp < 0 )) && tmp=0; end="$tmp"
    fi
    [[ "$asc" == "true" ]] && order="asc"
    echo -e "${BLUE}Search window:${NC} ${start} -> ${end} (${order})" >&2
    local resp
    if [[ -n "$blob_hash" ]]; then
      require_jq; require_hash_tools
      local found; if ! found=$(find_slot_and_index_by_hash "$beacon_url" "$blob_hash" "$start" "$end" "$order"); then echo -e "${RED}Not found: blob hash not present${NC}" >&2; exit 2; fi
      local slot_found idx; slot_found="${found%%:*}"; idx="${found##*:}"
      echo -e "${GREEN}Found at slot:${NC} $slot_found  ${GREEN}index:${NC} $idx" >&2
      resp=$(query_sidecar_by_slot_index "$beacon_url" "$slot_found" "$idx") || { echo -e "${RED}Error: fetch failed${NC}" >&2; exit 1; }
      start="$slot_found"

      if [[ "$receipt" == "true" ]]; then
        if [[ -z "$rpc_url" ]]; then if [[ -n "${EL_RPC_URL:-}" ]]; then rpc_url="$EL_RPC_URL"; fi; fi
        if [[ -z "$rpc_url" ]]; then rpc_url=$(select_rpc_url_from_config); fi
        if [[ -z "$rpc_url" ]]; then echo -e "${RED}Error: RPC URL not found${NC}" >&2; exit 1; fi
        if ! test_rpc_connection "$rpc_url"; then echo -e "${RED}Error: RPC endpoint not responding: $rpc_url${NC}" >&2; exit 1; fi
        echo -e "${BLUE}RPC endpoint:${NC} $rpc_url" >&2
        local payload_bn bn_hex
        payload_bn=$(curl -sS "$beacon_url/eth/v2/beacon/blocks/$slot_found" | jq -r '.data.message.body.execution_payload.block_number // empty')
        if [[ -z "$payload_bn" || "$payload_bn" == "null" ]]; then echo -e "${RED}Error: unable to get execution block number${NC}" >&2; exit 1; fi
        if [[ "$payload_bn" =~ ^0x[0-9a-fA-F]+$ ]]; then bn_hex="$payload_bn"; else bn_hex=$(printf '0x%x' "$payload_bn"); fi
        local block_resp; block_resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["'"$bn_hex"'", true],"id":1}' "$rpc_url")
        local matched_tx=""; while IFS= read -r th; do
          [[ -z "$th" ]] && continue
          local hv; hv=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getTransactionByHash","params":["'"$th"'"],"id":1}' "$rpc_url" | jq -r '.result.blobVersionedHashes[]? // empty')
          if grep -Fxq "$blob_hash" <<< "$hv"; then matched_tx="$th"; break; fi
        done < <(echo "$block_resp" | jq -r '.result.transactions[]? | if type=="string" then . else .hash end')
        if [[ -z "$matched_tx" ]]; then echo -e "${YELLOW}Warning: no matching transaction found in block ${bn_hex}${NC}" >&2; else
          local receipt_resp; receipt_resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["'"$matched_tx"'"],"id":1}' "$rpc_url")
          echo -e "${YELLOW}=== Matching Transaction Receipt ===${NC}" >&2
          format_json "$receipt_resp" "$pretty"
        fi
      fi
    else
      resp=$(query_sidecars_by_slot "$beacon_url" "$start") || { echo -e "${RED}Error: fetch failed${NC}" >&2; exit 1; }
      echo -e "${GREEN}Fetched sidecars at slot:${NC} $start" >&2
      if [[ -n "$tx_hash" && "$receipt" == "true" ]]; then
        if [[ -z "$rpc_url" ]]; then if [[ -n "${EL_RPC_URL:-}" ]]; then rpc_url="$EL_RPC_URL"; fi; fi
        if [[ -z "$rpc_url" ]]; then rpc_url=$(select_rpc_url_from_config); fi
        if [[ -z "$rpc_url" ]]; then echo -e "${RED}Error: RPC URL not found${NC}" >&2; exit 1; fi
        if ! test_rpc_connection "$rpc_url"; then echo -e "${RED}Error: RPC endpoint not responding: $rpc_url${NC}" >&2; exit 1; fi
        echo -e "${BLUE}RPC endpoint:${NC} $rpc_url" >&2
        local payload_bn bn_hex
        payload_bn=$(curl -sS "$beacon_url/eth/v2/beacon/blocks/$start" | jq -r '.data.message.body.execution_payload.block_number // empty')
        if [[ -z "$payload_bn" || "$payload_bn" == "null" ]]; then echo -e "${RED}Error: unable to get execution block number${NC}" >&2; exit 1; fi
        if [[ "$payload_bn" =~ ^0x[0-9a-fA-F]+$ ]]; then bn_hex="$payload_bn"; else bn_hex=$(printf '0x%x' "$payload_bn"); fi
        local block_resp; block_resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["'"$bn_hex"'", true],"id":1}' "$rpc_url")
        echo -e "${YELLOW}=== All Transaction Receipts in Block ${bn_hex} ===${NC}" >&2
        while IFS= read -r th; do
          [[ -z "$th" ]] && continue
          local receipt_resp; receipt_resp=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["'"$th"'"],"id":1}' "$rpc_url")
          format_json "$receipt_resp" "$pretty"
        done < <(echo "$block_resp" | jq -r '.result.transactions[]? | if type=="string" then . else .hash end')
      fi
    fi
    if [[ "$only_tx" == "true" ]]; then
      if [[ -z "$tx_hash" ]]; then echo -e "${YELLOW}Warning: --only-tx without --tx; skipping${NC}" >&2; else
        require_jq; require_hash_tools
        local tx_hashes; tx_hashes=$(get_tx_blob_versioned_hashes "$rpc_url" "$tx_hash")
        if [[ -z "$tx_hashes" ]]; then echo -e "${YELLOW}Warning: tx has no blobVersionedHashes; skipping${NC}" >&2; else
          local keep_indexes; keep_indexes=$(collect_matching_indexes_by_hashes "$resp" "$tx_hashes")
          resp=$(filter_resp_by_indexes "$resp" "$keep_indexes")
        fi
      fi
    fi
    if [[ "$no_blob" == "true" ]]; then require_jq; resp=$(strip_blob_payload "$resp"); fi
    if [[ "$summary" == "true" ]]; then require_jq; resp=$(make_summary "$resp" "$start"); fi
    if [[ -n "$output_file" ]]; then
      format_json "$resp" "$pretty" > "$output_file"
      local vhashes; vhashes=$(derive_versioned_hashes_from_sidecars_json "$resp" | json_array_from_lines)
      echo -e "${YELLOW}=== Derived Blob Versioned Hashes ===${NC}" >&2
      echo "$vhashes" | jq '.' 2>/dev/null || echo "$vhashes"
      echo -e "${GREEN}Result saved to: $output_file${NC}" >&2
    else
      echo -e "${YELLOW}=== Blob Sidecar ===${NC}" >&2
      format_json "$resp" "$pretty"
      local vhashes; vhashes=$(derive_versioned_hashes_from_sidecars_json "$resp" | json_array_from_lines)
      echo -e "${YELLOW}=== Derived Blob Versioned Hashes ===${NC}" >&2
      echo "$vhashes" | jq '.' 2>/dev/null || echo "$vhashes"
    fi
  else
    echo -e "${BLUE}Query target:${NC} block_id=$block_id${indices:+, indices=$indices}"
    local resp
    if ! resp=$(query_blob_sidecars "$beacon_url" "$block_id" "$indices"); then exit 1; fi
    if [[ -n "$output_file" ]]; then
      format_json "$resp" "$pretty" > "$output_file"
      local vhashes; vhashes=$(derive_versioned_hashes_from_sidecars_json "$resp" | json_array_from_lines)
      echo -e "${YELLOW}=== Derived Blob Versioned Hashes ===${NC}" >&2
      echo "$vhashes" | jq '.' 2>/dev/null || echo "$vhashes"
      echo -e "${GREEN}Result saved to: $output_file${NC}"
    else
      echo -e "${YELLOW}=== Blob Sidecars ===${NC}"
      format_json "$resp" "$pretty"
      local vhashes; vhashes=$(derive_versioned_hashes_from_sidecars_json "$resp" | json_array_from_lines)
      echo -e "${YELLOW}=== Derived Blob Versioned Hashes ===${NC}" >&2
      echo "$vhashes" | jq '.' 2>/dev/null || echo "$vhashes"
    fi
  fi
}

main "$@"
