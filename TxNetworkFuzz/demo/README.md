# Blob Transaction Demo

这个目录包含两个 blob 交易发送的演示程序：

## 1. blob_rpc.go - RPC 方式发送 Blob 交易

使用标准的 RPC 连接方式发送 blob 交易：
- 通过 `ethclient.Dial()` 连接到以太坊节点
- 使用 `ethclient.SendTransaction()` 发送交易
- 简单直接的 RPC 调用方式

运行方式：
```bash
cd /home/kkk/workspaces/FIST/TxNetworkFuzz/demo/blob_rpc
RPC_URL=http://127.0.0.1:8545 FROM_PRIVKEY_HEX=... go run .
```

## 2. devp2p/blob_devp2p.go - DevP2P 方式发送 Blob 交易

使用 DevP2P 协议直接发送 blob 交易：
- 通过 enode 地址解析节点信息
- 使用 JWT 认证创建 `ethtest.Suite`
- 通过 P2P 协议直接发送交易，而不是 RPC
- 保留了完整的 blob 交易构建逻辑

运行方式：
```bash
cd /home/kkk/workspaces/FIST/TxNetworkFuzz/demo/blob_devp2p
ENODE_URL=enode://... JWT_SECRET_HEX=... FROM_PRIVKEY_HEX=... go run .
```

## 主要区别

| 特性 | blob_rpc.go | blob_devp2p.go |
|------|-------------|-----------------|
| 连接方式 | HTTP RPC | DevP2P 协议 |
| 认证方式 | 无需认证 | JWT 认证 |
| 发送方式 | `ethclient.SendTransaction()` | `transaction.SendTxsWithoutRecv()` |
| 网络层 | HTTP | TCP P2P |
| 适用场景 | 标准客户端交互 | 节点间直接通信 |

## 配置说明

两个程序都通过环境变量读取必要配置（避免把敏感信息写进代码仓库）：
- `FROM_PRIVKEY_HEX`: 发送账户私钥（hex，去掉 `0x` 或带 `0x` 均可）
- `TO_ADDRESS`: 目标地址（可选，默认 `0x0000000000000000000000000000000000000000`）

RPC 版本额外需要：
- `RPC_URL`: 节点 RPC 地址

DevP2P 版本额外需要：
- `ENODE_URL`: 目标节点的 enode
- `JWT_SECRET_HEX`: Engine API JWT secret（hex）
- `RPC_ADDR`: RPC 地址（可选，默认 `http://127.0.0.1:8545`）
- `ENGINE_ADDR`: Engine API 地址（可选，默认 `127.0.0.1:8551`）
- `NODE_NAME`: 节点名称（可选）
