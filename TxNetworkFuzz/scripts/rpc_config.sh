#!/bin/bash

# 本文件由 run_ethereum_network.sh 自动生成：Fri Dec 19 11:10:50 UTC 2025
# 请勿手动编辑，该文件会在每次运行后被覆盖

# RPC Endpoints (service hostnames)
RPC_ENDPOINTS_SERVICE=(
    "http://el-1-geth-lighthouse:8545"
    "http://el-2-nethermind-lighthouse:8545"
    "http://el-3-reth-lighthouse:8545"
    "http://el-4-erigon-lighthouse:8545"
    "http://el-5-besu-lighthouse:8545"
    "http://el-6-ethrex-lighthouse:8545"
)

# RPC Endpoints (IP-based)
RPC_ENDPOINTS_IP=(
    "http://172.16.0.10:8545"
    "http://172.16.0.11:8545"
    "http://172.16.0.12:8545"
    "http://172.16.0.13:8545"
    "http://172.16.0.14:8545"
    "http://198.18.0.39:8545"
)

# Legacy: RPC_ENDPOINTS（兼容旧脚本，默认使用 IP 版）
RPC_ENDPOINTS=(
    "http://172.16.0.10:8545"
    "http://172.16.0.11:8545"
    "http://172.16.0.12:8545"
    "http://172.16.0.13:8545"
    "http://172.16.0.14:8545"
    "http://198.18.0.39:8545"
)

# Beacon HTTP URLs (service hostnames)
BEACON_HTTP_URLS_SERVICE=(
    "http://cl-1-lighthouse-geth:4000"
)

# Beacon HTTP URLs (IP-based)
BEACON_HTTP_URLS_IP=(
    "http://172.16.0.16:4000"
)

# 服务名到 RPC 的映射（服务域名版）
declare -A SERVICE_TO_RPC_SERVICE=(
  ["el-1-geth-lighthouse"]="http://el-1-geth-lighthouse:8545"
  ["el-2-nethermind-lighthouse"]="http://el-2-nethermind-lighthouse:8545"
  ["el-3-reth-lighthouse"]="http://el-3-reth-lighthouse:8545"
  ["el-4-erigon-lighthouse"]="http://el-4-erigon-lighthouse:8545"
  ["el-5-besu-lighthouse"]="http://el-5-besu-lighthouse:8545"
  ["el-6-ethrex-lighthouse"]="http://el-6-ethrex-lighthouse:8545"
)

# 服务名到 RPC 的映射（IP 版）
declare -A SERVICE_TO_RPC_IP=(
  ["el-1-geth-lighthouse"]="http://172.16.0.10:8545"
  ["el-2-nethermind-lighthouse"]="http://172.16.0.12:8545"
  ["el-3-reth-lighthouse"]="http://172.16.0.13:8545"
  ["el-4-erigon-lighthouse"]="http://172.16.0.14:8545"
  ["el-5-besu-lighthouse"]="http://198.18.0.39:8545"
  ["el-6-ethrex-lighthouse"]="http://172.16.0.11:8545"
)

# Legacy: 节点对到 RPC 的映射（兼容旧脚本）
declare -A NODE_RPC_MAP=(
)

get_rpc_endpoint() { local node="$1"; echo "${NODE_RPC_MAP[$node]}"; }
get_all_rpc_endpoints() { printf '%s\n' "${RPC_ENDPOINTS[@]}"; }
get_node_type_from_endpoint() {
  local endpoint="$1"
  for k in "${!NODE_RPC_MAP[@]}"; do
    if [[ "${NODE_RPC_MAP[$k]}" == "$endpoint" ]]; then echo "$k"; return 0; fi
  done
  echo ""
}

get_rpc_service_endpoint() { local service="$1"; echo "${SERVICE_TO_RPC_SERVICE[$service]}"; }
get_rpc_ip_endpoint() { local service="$1"; echo "${SERVICE_TO_RPC_IP[$service]}"; }
get_all_rpc_endpoints_service() { printf '%s\n' "${RPC_ENDPOINTS_SERVICE[@]}"; }
get_all_rpc_endpoints_ip() { printf '%s\n' "${RPC_ENDPOINTS_IP[@]}"; }
get_all_beacon_http_urls_service() { printf '%s\n' "${BEACON_HTTP_URLS_SERVICE[@]}"; }
get_all_beacon_http_urls_ip() { printf '%s\n' "${BEACON_HTTP_URLS_IP[@]}"; }

export -f get_rpc_endpoint get_all_rpc_endpoints get_node_type_from_endpoint get_rpc_service_endpoint get_rpc_ip_endpoint get_all_rpc_endpoints_service get_all_rpc_endpoints_ip get_all_beacon_http_urls_service get_all_beacon_http_urls_ip
