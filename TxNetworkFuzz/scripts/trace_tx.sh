#!/bin/bash

# Transaction Tracing Script
# Used to trace detailed information of Ethereum transaction execution

# Set character encoding to UTF-8
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Load RPC configuration from external file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/rpc_config.sh"

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
DEFAULT_TRACER="callTracer"
DEFAULT_NODE="geth"
DEFAULT_REEXEC=0
DEFAULT_TIMEOUT="60s"

# Show usage information
show_usage() {
    echo -e "${BLUE}Ethereum Transaction Tracing Tool${NC}"
    echo "Usage: $0 [options] <transaction_hash>"
    echo ""
    echo "Options:"
    echo "  -t, --tracer <type>     Tracer type (default: callTracer)"
    echo "                          Available: callTracer, prestateTracer, 4byteTracer, opcodeLogger"
    echo "  -n, --node <node>       Specify node type (default: geth)"
    # Dynamically list configured nodes, and supported aliases
    local available_nodes=$(printf '%s ' ${!NODE_RPC_MAP[@]})
    echo "                          Configured: ${available_nodes}"
    echo "                          Aliases: geth, nethermind, besu"
    echo "  -e, --endpoint <URL>    Custom RPC endpoint"
    echo "  --reexec <N>            Recompute recent N blocks state if needed"
    echo "  --timeout <dur>         Tracer timeout (e.g., 60s, 120s)"
    echo "  -o, --output <file>     Output result to file"
    echo "  -p, --pretty            Pretty print JSON output"
    echo "  -h, --help              Show this help information"
    echo ""
    echo "Tracer descriptions:"
    echo "  callTracer      - Trace all contract calls (recommended)"
    echo "  prestateTracer  - Trace state changes"
    echo "  4byteTracer     - Trace function call statistics"
    echo "  opcodeLogger    - Detailed opcode logs"
    echo ""
    echo "Examples:"
    echo "  $0 0x1234...                                    # Trace transaction with default settings"
    echo "  $0 -t prestateTracer 0x1234...                 # Use state tracer"
    echo "  $0 -n reth -t callTracer 0x1234...             # Use reth node for tracing"
    echo "  $0 -o trace_result.json 0x1234...              # Output to file"
    echo "  $0 -p 0x1234...                                # Pretty print output"
}

# Resolve user-friendly node alias to configured NODE_RPC_MAP key
resolve_node_alias() {
    local name="$1"
    # If exact key exists, use it directly
    if [[ -n "${NODE_RPC_MAP[$name]}" ]]; then
        echo "$name"
        return 0
    fi

    case "$name" in
        "geth")
            if [[ -n "${NODE_RPC_MAP["geth-lighthouse"]}" ]]; then
                echo "geth-lighthouse"; return 0
            elif [[ -n "${NODE_RPC_MAP["geth-nimbus"]}" ]]; then
                echo "geth-nimbus"; return 0
            else
                # Fallback: first key starting with geth
                for key in "${!NODE_RPC_MAP[@]}"; do
                    if [[ "$key" == geth* ]]; then echo "$key"; return 0; fi
                done
            fi
            ;;
        "nethermind")
            if [[ -n "${NODE_RPC_MAP["nethermind-teku"]}" ]]; then
                echo "nethermind-teku"; return 0
            else
                for key in "${!NODE_RPC_MAP[@]}"; do
                    if [[ "$key" == nethermind* ]]; then echo "$key"; return 0; fi
                done
            fi
            ;;
        "besu")
            if [[ -n "${NODE_RPC_MAP["besu-lodestar"]}" ]]; then
                echo "besu-lodestar"; return 0
            elif [[ -n "${NODE_RPC_MAP["besu-prysm"]}" ]]; then
                echo "besu-prysm"; return 0
            else
                for key in "${!NODE_RPC_MAP[@]}"; do
                    if [[ "$key" == besu* ]]; then echo "$key"; return 0; fi
                done
            fi
            ;;
        *)
            # Unknown alias, return as-is (will be validated later)
            echo "$name"; return 0
            ;;
    esac
}

# Test RPC connection
test_rpc_connection() {
    local endpoint=$1
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
    
    if [[ $? -eq 0 ]] && echo "$response" | grep -q '"result"'; then
        return 0
    else
        return 1
    fi
}

# Validate transaction hash
validate_tx_hash() {
    local tx_hash=$1
    if [[ ! "$tx_hash" =~ ^0x[a-fA-F0-9]{64}$ ]]; then
        echo -e "${RED}Error: Invalid transaction hash format${NC}"
        echo "Transaction hash should be a 64-character hexadecimal string starting with 0x"
        return 1
    fi
    return 0
}

# Format JSON output
format_json() {
    local json_data=$1
    local pretty=$2
    
    if [[ "$pretty" == "true" ]] && command -v jq >/dev/null 2>&1; then
        echo "$json_data" | jq '.'
    else
        echo "$json_data"
    fi
}

# Fetch transaction details via RPC
get_transaction_details() {
    local tx_hash=$1
    local endpoint=$2
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$tx_hash\"],\"id\":1}" \
        --connect-timeout 10 --max-time 15 "$endpoint" 2>/dev/null)

    if echo "$response" | grep -q '"result":null'; then
        echo ""
        return 1
    fi
    local tx_json
    if command -v jq >/dev/null 2>&1; then
        tx_json=$(echo "$response" | jq -c '.result')
    else
        # Fallback: crude extraction of result JSON object
        tx_json=$(echo "$response" | grep -o '"result":{.*}' | sed 's/^"result"://')
    fi
    if [[ -z "$tx_json" ]]; then
        echo ""
        return 1
    fi
    echo "$tx_json"
    return 0
}

# Try to get transaction object from txpool_content by hash
get_tx_from_txpool() {
    local tx_hash="$1"
    local endpoint="$2"
    local txpool_response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}' \
        --connect-timeout 10 --max-time 15 "$endpoint" 2>/dev/null)
    if ! echo "$txpool_response" | grep -q '"result"'; then
        echo ""
        return 1
    fi
    if command -v jq >/dev/null 2>&1; then
        local found=$(echo "$txpool_response" | jq -c --arg h "$tx_hash" '.result.pending | to_entries[] | .value | to_entries[] | .value | select(.hash==$h)')
        if [[ -z "$found" ]]; then
            found=$(echo "$txpool_response" | jq -c --arg h "$tx_hash" '.result.queued  | to_entries[] | .value | to_entries[] | .value | select(.hash==$h)')
        fi
        echo "$found"
        [[ -n "$found" ]]
        return $?
    else
        # Fallback: not robust without jq; bail out
        echo ""
        return 1
    fi
}

# Build call object from tx details for debug_traceCall
build_call_object() {
    local tx_json=$1
    local from to gas gasPrice maxFeePerGas value input
    if command -v jq >/dev/null 2>&1; then
        from=$(echo "$tx_json" | jq -r '.from // "0x0000000000000000000000000000000000000000"')
        to=$(echo "$tx_json" | jq -r '.to // empty')
        gas=$(echo "$tx_json" | jq -r '.gas // "0x5208"')
        gasPrice=$(echo "$tx_json" | jq -r '.gasPrice // empty')
        maxFeePerGas=$(echo "$tx_json" | jq -r '.maxFeePerGas // empty')
        value=$(echo "$tx_json" | jq -r '.value // "0x0"')
        input=$(echo "$tx_json" | jq -r '.input // "0x"')
    else
        # Minimal fallback if jq is unavailable
        from=$(echo "$tx_json" | grep -o '"from":"[^"]*"' | cut -d'"' -f4)
        to=$(echo "$tx_json" | grep -o '"to":"[^"]*"' | cut -d'"' -f4)
        gas=$(echo "$tx_json" | grep -o '"gas":"[^"]*"' | cut -d'"' -f4)
        gasPrice=$(echo "$tx_json" | grep -o '"gasPrice":"[^"]*"' | cut -d'"' -f4)
        maxFeePerGas=$(echo "$tx_json" | grep -o '"maxFeePerGas":"[^"]*"' | cut -d'"' -f4)
        value=$(echo "$tx_json" | grep -o '"value":"[^"]*"' | cut -d'"' -f4)
        input=$(echo "$tx_json" | grep -o '"input":"[^"]*"' | cut -d'"' -f4)
        [[ -z "$gas" ]] && gas="0x5208"
        [[ -z "$value" ]] && value="0x0"
        [[ -z "$input" ]] && input="0x"
    fi

    # Assemble call object JSON; omit gasPrice if EIP-1559 fields are present
    local call_obj="{\"from\":\"$from\"," 
    if [[ -n "$to" ]]; then
        call_obj+="\"to\":\"$to\"," 
    fi
    call_obj+="\"gas\":\"$gas\"," 
    if [[ -n "$gasPrice" ]]; then
        call_obj+="\"gasPrice\":\"$gasPrice\"," 
    fi
    call_obj+="\"value\":\"$value\",\"data\":\"$input\"}"

    echo "$call_obj"
}

# Trace transaction
trace_transaction() {
    local tx_hash=$1
    local tracer=$2
    local endpoint=$3
    local output_file=$4
    local pretty=$5
    local reexec=${6:-$DEFAULT_REEXEC}
    local timeout=${7:-$DEFAULT_TIMEOUT}
    
    echo -e "${CYAN}Tracing transaction: $tx_hash${NC}"
    echo -e "${CYAN}Using tracer: $tracer${NC}"
    echo -e "${CYAN}RPC endpoint: $endpoint${NC}"
    echo ""
    
    # Prepare tracer configuration
    local tracer_config=""
    case "$tracer" in
        "callTracer")
            tracer_config='{"tracer": "callTracer"}'
            ;;
        "prestateTracer")
            tracer_config='{"tracer": "prestateTracer"}'
            ;;
        "4byteTracer")
            tracer_config='{"tracer": "4byteTracer"}'
            ;;
        "opcodeLogger")
            tracer_config='{"tracer": "opcodeLogger"}'
            ;;
        *)
            tracer_config="{\"tracer\": \"$tracer\"}"
            ;;
    esac

    # Add optional reexec/timeout to config if set
    if [[ -n "$timeout" ]]; then
        tracer_config=$(echo "$tracer_config" | sed 's/}$/,"timeout":"'$timeout'"}/')
    fi
    if [[ "$reexec" -gt 0 ]]; then
        tracer_config=$(echo "$tracer_config" | sed 's/}$/,"reexec":'$reexec'}/')
    fi
    
    # Decide tracing mode based on transaction status
    local tx_details=$(get_transaction_details "$tx_hash" "$endpoint")
    local tx_is_pending=0
    local choose_call_trace=0
    if [[ -n "$tx_details" ]]; then
        # Determine if blockNumber is null using jq if available
        local block_number=""
        if command -v jq >/dev/null 2>&1; then
            block_number=$(echo "$tx_details" | jq -r '.blockNumber')
        else
            block_number=$(echo "$tx_details" | grep -o '"blockNumber":"[^"]*"' | cut -d'"' -f4)
        fi
        if [[ -z "$block_number" || "$block_number" == "null" ]]; then
            tx_is_pending=1
            choose_call_trace=1
        fi
    else
        # Not found via eth_getTransactionByHash; try mempool existence via txpool_content
        local txpool_response=$(curl -s -X POST -H "Content-Type: application/json" \
            --data '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}' \
            --connect-timeout 10 --max-time 15 "$endpoint" 2>/dev/null)
        if echo "$txpool_response" | grep -q '"result"'; then
            if command -v jq >/dev/null 2>&1; then
                if echo "$txpool_response" | jq -r '.result.pending' 2>/dev/null | grep -q "$tx_hash"; then
                    tx_is_pending=1
                    choose_call_trace=1
                fi
            else
                if echo "$txpool_response" | grep -q "$tx_hash"; then
                    tx_is_pending=1
                    choose_call_trace=1
                fi
            fi
        fi
    fi

    if [[ $choose_call_trace -eq 1 ]]; then
        echo -e "${YELLOW}Transaction is pending; using debug_traceCall on latest state${NC}"
        local call_obj=$(build_call_object "${tx_details:-}" )
        if [[ -z "$call_obj" ]]; then
            echo -e "${RED}Error: Unable to build call object for pending transaction${NC}"
            return 1
        fi
        local trace_response=$(curl -s -X POST -H "Content-Type: application/json" \
            --data "{\"jsonrpc\":\"2.0\",\"method\":\"debug_traceCall\",\"params\":[${call_obj}, \"latest\", ${tracer_config}],\"id\":1}" \
            --connect-timeout 30 --max-time 60 "$endpoint" 2>/dev/null)
    else
        # Execute trace on mined transaction
        local trace_response=$(curl -s -X POST -H "Content-Type: application/json" \
            --data "{\"jsonrpc\":\"2.0\",\"method\":\"debug_traceTransaction\",\"params\":[\"$tx_hash\", ${tracer_config}],\"id\":1}" \
            --connect-timeout 30 --max-time 60 "$endpoint" 2>/dev/null)
    fi

    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Error: RPC call failed${NC}"
        return 1
    fi
    
    # Check for errors in response
    if echo "$trace_response" | grep -q '"error"'; then
        # If we attempted debug_traceTransaction and got 'transaction not found', fallback to debug_traceCall
        if echo "$trace_response" | grep -q 'transaction not found' && [[ $choose_call_trace -eq 0 ]]; then
            echo -e "${YELLOW}debug_traceTransaction reported 'transaction not found'; falling back to debug_traceCall${NC}"
            # Attempt to construct call object from details or txpool
            local call_source="$tx_details"
            if [[ -z "$call_source" ]]; then
                call_source=$(get_tx_from_txpool "$tx_hash" "$endpoint")
            fi
            local call_obj=""
            if [[ -n "$call_source" ]]; then
                call_obj=$(build_call_object "$call_source")
            fi
            if [[ -z "$call_obj" ]]; then
                echo -e "${RED}Error: Unable to construct call object for fallback tracing${NC}"
                echo "$trace_response" | grep -o '"error":[^}]*}' | sed 's/^"error"://'
                return 1
            fi
            trace_response=$(curl -s -X POST -H "Content-Type: application/json" \
                --data "{\"jsonrpc\":\"2.0\",\"method\":\"debug_traceCall\",\"params\":[${call_obj}, \"latest\", ${tracer_config}],\"id\":1}" \
                --connect-timeout 30 --max-time 60 "$endpoint" 2>/dev/null)
            if echo "$trace_response" | grep -q '"error"'; then
                echo -e "${RED}Tracing failed:${NC}"
                echo "$trace_response" | grep -o '"error":[^}]*}' | sed 's/^"error"://'
                return 1
            fi
        elif echo "$trace_response" | grep -q 'historical state is not available' && [[ $choose_call_trace -eq 0 ]]; then
            # Auto retry with incremental reexec values
            local try_reexecs=(512 2048 8192)
            for r in "${try_reexecs[@]}"; do
                echo -e "${YELLOW}Historical state unavailable; retrying with reexec=${r}${NC}"
                local cfg_with_reexec=$(echo "$tracer_config" | sed 's/}$/,"reexec":'$r'}/')
                trace_response=$(curl -s -X POST -H "Content-Type: application/json" \
                    --data "{\"jsonrpc\":\"2.0\",\"method\":\"debug_traceTransaction\",\"params\":[\"$tx_hash\", ${cfg_with_reexec}],\"id\":1}" \
                    --connect-timeout 30 --max-time 60 "$endpoint" 2>/dev/null)
                if echo "$trace_response" | grep -q '"result"'; then
                    break
                fi
            done
            if ! echo "$trace_response" | grep -q '"result"'; then
                echo -e "${YELLOW}Retrying failed; falling back to debug_traceCall on latest state${NC}"
                local call_source="$tx_details"
                if [[ -z "$call_source" ]]; then
                    call_source=$(get_tx_from_txpool "$tx_hash" "$endpoint")
                fi
                local call_obj=""
                if [[ -n "$call_source" ]]; then
                    call_obj=$(build_call_object "$call_source")
                fi
                if [[ -z "$call_obj" ]]; then
                    echo -e "${RED}Error: Unable to construct call object for fallback tracing${NC}"
                    echo "$trace_response" | grep -o '"error":[^}]*}' | sed 's/^"error"://'
                    return 1
                fi
                trace_response=$(curl -s -X POST -H "Content-Type: application/json" \
                    --data "{\"jsonrpc\":\"2.0\",\"method\":\"debug_traceCall\",\"params\":[${call_obj}, \"latest\", ${tracer_config}],\"id\":1}" \
                    --connect-timeout 30 --max-time 60 "$endpoint" 2>/dev/null)
                if echo "$trace_response" | grep -q '"error"'; then
                    echo -e "${RED}Tracing failed:${NC}"
                    echo "$trace_response" | grep -o '"error":[^}]*}' | sed 's/^"error"://'
                    return 1
                fi
            fi
        else
            echo -e "${RED}Tracing failed:${NC}"
            echo "$trace_response" | grep -o '"error":[^}]*}' | sed 's/^"error"://'
            return 1
        fi
    fi
    
    # Check if result exists
    if echo "$trace_response" | grep -q '"result"'; then
        echo -e "${GREEN}✓ Tracing successful${NC}"
        echo ""
        
        # Extract and format result
        local result
        if command -v jq >/dev/null 2>&1; then
            result=$(echo "$trace_response" | jq -c '.result')
        else
            result=$(echo "$trace_response" | grep -o '"result":{.*}' | sed 's/^"result"://' | sed 's/}$/}/')
            if [[ -z "$result" ]]; then
                result=$(echo "$trace_response" | grep -o '"result":\[.*\]' | sed 's/^"result"://')
            fi
        fi
        
        # Format and output result
        local formatted_result=$(format_json "$result" "$pretty")
        
        if [[ -n "$output_file" ]]; then
            echo "$formatted_result" > "$output_file"
            echo -e "${GREEN}Result saved to: $output_file${NC}"
        else
            echo -e "${YELLOW}=== Trace Result ===${NC}"
            echo "$formatted_result"
        fi
        
        return 0
    else
        echo -e "${RED}Error: Abnormal response format${NC}"
        echo "$trace_response"
        return 1
    fi
}

# Main function
main() {
    local tx_hash=""
    local tracer="$DEFAULT_TRACER"
    local node="$DEFAULT_NODE"
    local endpoint=""
    local output_file=""
    local pretty="false"
    local reexec="$DEFAULT_REEXEC"
    local timeout="$DEFAULT_TIMEOUT"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--tracer)
                tracer="$2"
                shift 2
                ;;
            -n|--node)
                node="$2"
                shift 2
                ;;
            -e|--endpoint)
                endpoint="$2"
                shift 2
                ;;
            --reexec)
                reexec="$2"
                shift 2
                ;;
            --reexec=*)
                reexec="${1#*=}"
                shift
                ;;
            --timeout)
                timeout="$2"
                shift 2
                ;;
            --timeout=*)
                timeout="${1#*=}"
                shift
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -p|--pretty)
                pretty="true"
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            0x*)
                tx_hash="$1"
                shift
                ;;
            *)
                echo -e "${RED}Error: Unknown parameter $1${NC}"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Check if transaction hash is provided
    if [[ -z "$tx_hash" ]]; then
        echo -e "${RED}Error: Please provide transaction hash${NC}"
        show_usage
        exit 1
    fi
    
    # Validate transaction hash
    if ! validate_tx_hash "$tx_hash"; then
        exit 1
    fi
    
    # Determine endpoint
    if [[ -z "$endpoint" ]]; then
        local node_key=$(resolve_node_alias "$node")
        if [[ -n "${NODE_RPC_MAP[$node_key]}" ]]; then
            if [[ "$node" != "$node_key" ]]; then
                echo -e "${CYAN}Node alias '${node}' resolved to '${node_key}'${NC}"
            fi
            endpoint="${NODE_RPC_MAP[$node_key]}"
        else
            echo -e "${RED}Error: Unknown node type '$node'${NC}"
            echo -n "Available nodes: "
            printf '%s ' ${!NODE_RPC_MAP[@]}
            echo ""
            exit 1
        fi
    fi
    
    # Test connection
    echo -e "${CYAN}Testing RPC connection...${NC}"
    if ! test_rpc_connection "$endpoint"; then
        echo -e "${RED}Error: Unable to connect to RPC endpoint $endpoint${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Connection successful${NC}"
    echo ""
    
    # Execute trace
    # Validate reexec as a non-negative integer
    if ! [[ "$reexec" =~ ^[0-9]+$ ]]; then
        echo -e "${YELLOW}Warning: --reexec value '$reexec' is not a non-negative integer; using default ${DEFAULT_REEXEC}${NC}"
        reexec="$DEFAULT_REEXEC"
    fi
    # timeout is passed as-is (e.g., 60s); basic sanity check
    if [[ -z "$timeout" ]]; then
        timeout="$DEFAULT_TIMEOUT"
    fi
    trace_transaction "$tx_hash" "$tracer" "$endpoint" "$output_file" "$pretty" "$reexec" "$timeout"
}

# Run main function
main "$@"
