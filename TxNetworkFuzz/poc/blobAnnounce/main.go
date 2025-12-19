package main

import (
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/AgnopraxLab/D2PFuzz/blob"
	"github.com/AgnopraxLab/D2PFuzz/config"
	ethtest "github.com/AgnopraxLab/D2PFuzz/devp2p/protocol/eth"
	"github.com/AgnopraxLab/D2PFuzz/ethclient"
	"github.com/AgnopraxLab/D2PFuzz/transaction"
	"github.com/AgnopraxLab/D2PFuzz/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
)

// ============================================================================
// TEST CONFIGURATION AND PARAMETERS
// ============================================================================

// ZeroAddress is the target address for all transactions
var ZeroAddress = common.HexToAddress("0x0000000000000000000000000000000000000000")

// BlobFeeCap is the max fee per blob gas (1 Gwei)
var BlobFeeCap = big.NewInt(1000000000)

// AnnounceParams holds the parameters for the NewPooledTransactionHashesPacket
type AnnounceParams struct {
	Types  []byte
	Sizes  []uint32
	Hashes []common.Hash
}

// TestCases defines the scenarios to run
var TestCases = []struct {
	Name   string
	Params AnnounceParams
}{
	{
		Name: "abnormal type (0x09, Actual Size)",
		Params: AnnounceParams{
			Types: []byte{0x09},
			Sizes: []uint32{0},
		},
	},
	// {
	// 	Name: "Standard (0x00, Actual Size)",
	// 	Params: AnnounceParams{
	// 		Types: []byte{types.LegacyTxType},
	// 		Sizes: []uint32{0},
	// 	},
	// },
	// {
	// 	Name: "Standard (0x01, Actual Size)",
	// 	Params: AnnounceParams{
	// 		Types: []byte{types.AccessListTxType},
	// 		Sizes: []uint32{0}, // Will be updated with actual size
	// 	},
	// },
	// {
	// 	Name: "Standard (0x02, Actual Size)",
	// 	Params: AnnounceParams{
	// 		Types: []byte{types.DynamicFeeTxType},
	// 		Sizes: []uint32{0},
	// 	},
	// },
	// {
	// 	Name: "Standard (0x03, Actual Size)",
	// 	Params: AnnounceParams{
	// 		Types: []byte{types.BlobTxType},
	// 		Sizes: []uint32{0},
	// 	},
	// },
	// {
	// 	Name: "Standard (0x04, Actual Size)",
	// 	Params: AnnounceParams{
	// 		Types: []byte{types.SetCodeTxType},
	// 		Sizes: []uint32{0},
	// 	},
	// },
}

// SendBlobViaGossipCustom 发送 blob 交易，同时支持自定义子交易并在公告中携带多哈希
func SendBlobViaGossipCustom(s *ethclient.Client, tx *types.Transaction, params AnnounceParams, subTxs []*types.Transaction) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if tx.Type() != types.BlobTxType {
		return fmt.Errorf("transaction type %d is not blob", tx.Type())
	}

	suite := s.GetSuite()
	if suite == nil {
		return fmt.Errorf("devp2p suite is nil")
	}

	conn, err := suite.Dial()
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()
	if err := conn.Peer(nil); err != nil {
		return fmt.Errorf("peering failed: %w", err)
	}

	// 构建哈希到交易的映射（含 blob 与子交易）
	hashToTx := make(map[common.Hash]*types.Transaction)
	hashToTx[tx.Hash()] = tx
	for _, stx := range subTxs {
		if stx != nil {
			hashToTx[stx.Hash()] = stx
		}
	}

	// 1) 宣告哈希（NewPooledTransactionHashesMsg）
	hashes := params.Hashes
	if len(hashes) == 0 {
		hashes = make([]common.Hash, 0, 1+len(subTxs))
		hashes = append(hashes, tx.Hash())
		for _, stx := range subTxs {
			hashes = append(hashes, stx.Hash())
		}
	}
	ann := eth.NewPooledTransactionHashesPacket{
		Types:  params.Types,
		Sizes:  []uint32{uint32(tx.Size())},
		Hashes: hashes,
	}

	fmt.Printf("   📢 Announcing: Types=%x, Sizes=%v, Hash=%s\n", ann.Types, ann.Sizes, tx.Hash().Hex())

	if err := conn.Write(ethtest.EthProto(), eth.NewPooledTransactionHashesMsg, ann); err != nil {
		return fmt.Errorf("announcement write failed: %w", err)
	}

	// 2) 等待对方的 GetPooledTransactions 请求
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set read deadline failed: %w", err)
	}

	// 同步读取请求并响应（不使用协程）
	req := new(eth.GetPooledTransactionsPacket)
	if err := conn.ReadMsg(ethtest.EthProto(), eth.GetPooledTransactionsMsg, req); err != nil {
		return fmt.Errorf("read pooled tx request failed: %w", err)
	}

	if len(req.GetPooledTransactionsRequest) == 0 {
		return fmt.Errorf("unexpected pooled tx request: empty hashes")
	}

	var respTxs types.Transactions
	for _, h := range req.GetPooledTransactionsRequest {
		if t, ok := hashToTx[h]; ok {
			respTxs = append(respTxs, t)
		}
	}
	if len(respTxs) == 0 {
		return fmt.Errorf("no matching transactions for requested hashes")
	}

	resp := eth.PooledTransactionsPacket{
		RequestId:                  req.RequestId,
		PooledTransactionsResponse: eth.PooledTransactionsResponse(respTxs),
	}
	if err := conn.Write(ethtest.EthProto(), eth.PooledTransactionsMsg, resp); err != nil {
		return fmt.Errorf("pooled tx response write failed: %w", err)
	}

	fmt.Printf("   📤 Sent PooledTransactions response\n")
	return nil
}

// 构造 EIP-1559 动态费交易
func BuildDynamicFeeTx(chainID *big.Int, fromAcc config.Account, to common.Address, nonce uint64, value, gasTipCap, gasFeeCap *big.Int, gasLimit uint64) (*types.Transaction, error) {
	prik, err := ethclient.PrivateKeyFromHex(fromAcc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	txdata := &types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit,
		To:        &to,
		Value:     value,
	}
	innertx := types.NewTx(txdata)
	tx, err := types.SignTx(innertx, types.NewCancunSigner(chainID), prik)
	if err != nil {
		return nil, fmt.Errorf("sign tx failed: %w", err)
	}
	return tx, nil
}

// 构造若干子交易，参数与 maxNonce 示例一致（100 wei, 21000 gas, 3/30 Gwei）
func BuildSubTxs(chainID *big.Int, fromAcc config.Account, to common.Address, startNonce uint64, count int) ([]*types.Transaction, error) {
	res := make([]*types.Transaction, 0, count)
	for i := 0; i < count; i++ {
		nonce := startNonce + uint64(i)
		tx, err := BuildDynamicFeeTx(chainID, fromAcc, to, nonce, big.NewInt(100), big.NewInt(3000000000), big.NewInt(30000000000), 21000)
		if err != nil {
			return nil, err
		}
		res = append(res, tx)
	}
	return res, nil
}

// 计算公告参数，填入 blob 及子交易的类型、尺寸与哈希
func ComputeAnnouncementFor(blobTx *types.Transaction, subTxs []*types.Transaction, base AnnounceParams) AnnounceParams {
	hashes := make([]common.Hash, 0, 1+len(subTxs))
	hashes = append(hashes, blobTx.Hash())
	for _, stx := range subTxs {
		hashes = append(hashes, stx.Hash())
	}
	typesArr := make([]byte, 0, 1+len(subTxs))
	typesArr = append(typesArr, types.BlobTxType)
	for range subTxs {
		typesArr = append(typesArr, 0x02)
	}
	sizesArr := make([]uint32, 0, 1+len(subTxs))
	sizesArr = append(sizesArr, uint32(blobTx.Size()))
	for _, stx := range subTxs {
		sizesArr = append(sizesArr, uint32(stx.Size()))
	}
	return AnnounceParams{Types: typesArr, Sizes: sizesArr, Hashes: hashes}
}

func main() {
	// Initialize KZG
	if err := blob.InitKZG(); err != nil {
		fmt.Printf("Failed to initialize KZG: %v\n", err)
		os.Exit(1)
	}
	cfg, err := config.LoadConfig("../../cmd/manual/config.yaml")
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Starting Blob Multi-Node (manual-aligned) test...")
	fmt.Printf("Total Target Nodes: %d\n", len(cfg.P2P.BootstrapNodes))
	fmt.Printf("Total Test Accounts: %d\n", len(cfg.Accounts))
	fmt.Printf("To Address: %s\n", ZeroAddress.Hex())
	fmt.Println("----------------------------------------")

	// 读取 blob_multi 或 blob_test 配置
	var blobCount int
	var totalBlobTxs int
	var sendInterval int
	var nodeNonces []string
	if cfg.Test.BlobMulti.BlobCount > 0 {
		blobCount = cfg.Test.BlobMulti.BlobCount
		totalBlobTxs = cfg.Test.BlobMulti.TotalTransactions
		sendInterval = cfg.Test.BlobMulti.SendIntervalMS
		nodeNonces = cfg.Test.BlobMulti.Nonces
	} else {
		blobCount = cfg.Test.BlobTest.BlobCount
		totalBlobTxs = cfg.Test.BlobTest.TotalBlobTxs
		sendInterval = cfg.Test.BlobTest.SendInterval
		nodeNonces = cfg.Test.BlobTest.MultiNodeNonces
		if blobCount == 0 {
			blobCount = 1
		}
	}

	// 顺序执行每个节点测试，并记录 blob 交易哈希
	hashFilePath := "./txhashes.txt"
	// 运行开始清空文件（覆盖记录而非追加）
	if err := utils.WriteStringToFile(hashFilePath, ""); err != nil {
		fmt.Printf("Failed to init hash file: %v\n", err)
	}

	// Iterate through each node and run tests sequentially
	for i := 0; i < len(cfg.P2P.BootstrapNodes); i++ {
		nodeIndex := i
		// Use corresponding account for this node
		accountIndex := i % len(cfg.Accounts)
		senderAccount := cfg.Accounts[accountIndex]

		fmt.Printf("\n[Node %d] Connecting to %s...\n", nodeIndex, cfg.P2P.BootstrapNodes[nodeIndex])

		// 在哈希文件追加节点名称（与 cmd/manual/txhashes.txt 格式一致）
		var nodeName string
		if nodeIndex < len(cfg.P2P.NodeNames) {
			nodeName = cfg.P2P.NodeNames[nodeIndex]
		} else {
			nodeName = fmt.Sprintf("node-%d", nodeIndex)
		}
		// 写入节点头（覆盖文件后从头开始写入）
		if err := utils.AppendToFile(hashFilePath, fmt.Sprintf("# %s\n", nodeName)); err != nil {
			fmt.Printf("[Node %d] Failed to write header to hash file: %v\n", nodeIndex, err)
		}

		// Create client for this specific node
		client, err := ethclient.NewClient(cfg, nodeIndex)
		if err != nil {
			fmt.Printf("[Node %d] Failed to create client: %v\n", nodeIndex, err)
			continue
		}

		if err := client.GetSuite().InitializeAndConnect(); err != nil {
			fmt.Printf("[Node %d] Suite initialize failed: %v\n", nodeIndex, err)
			continue
		}

		// Resolve nonce（支持通过配置覆盖）
		nonceStr := "auto"
		if nodeIndex < len(nodeNonces) && nodeNonces[nodeIndex] != "" {
			nonceStr = nodeNonces[nodeIndex]
		}
		nonce, err := utils.ResolveNonce(client, nonceStr, common.HexToAddress(senderAccount.Address))
		if err != nil {
			fmt.Printf("[Node %d] Failed to resolve nonce for %s: %v\n", nodeIndex, senderAccount.Address, err)
			continue
		}
		fmt.Printf("[Node %d] Account: %s, Start Nonce: %d\n", nodeIndex, senderAccount.Address, nonce)

		// 每个节点发送 totalBlobTxs/节点数 的 blob 交易
		totalTxs := totalBlobTxs / len(cfg.P2P.BootstrapNodes)
		if totalTxs == 0 {
			totalTxs = 1
		}
		for j := 0; j < totalTxs; j++ {
			// 构造 blob 交易（与 testing/blob_multi 一致）
			builder := transaction.NewBlobTxBuilder(cfg.ChainID).
				WithFrom(senderAccount).
				WithTo(config.Account{Address: ZeroAddress.Hex()}).
				WithNonce(nonce).
				WithCount(1).
				WithMaxFeePerBlobGas(BlobFeeCap)

			for k := 0; k < blobCount; k++ {
				if err := builder.AddRandomBlob(); err != nil {
					fmt.Printf("[Node %d] Failed to add blob: %v\n", nodeIndex, err)
					continue
				}
			}

			blobTx, err := builder.Build()
			if err != nil || len(blobTx) == 0 {
				fmt.Printf("[Node %d] Failed to build tx: %v\n", nodeIndex, err)
				continue
			}
			tx := blobTx[0]

			// 记录交易哈希
			if err := utils.AppendHashToFile(hashFilePath, tx.Hash()); err != nil {
				fmt.Printf("[Node %d] Failed to write tx hash: %v\n", nodeIndex, err)
			}

			// 使用标准 DevP2P Gossip 发送（宣告→拉取→回包）
			if err := transaction.SendBlobViaGossip(client.GetSuite(), tx); err != nil {
				fmt.Printf("[Node %d] ❌ Failed: %v\n", nodeIndex, err)
			} else {
				fmt.Printf("[Node %d] ✅ Success: blob tx sent\n", nodeIndex)
			}

			nonce++
			if j < totalTxs-1 && sendInterval > 0 {
				time.Sleep(time.Duration(sendInterval) * time.Millisecond)
			}
		}

		// 节点完成后稍作停顿，便于观察
		time.Sleep(1 * time.Second)
	}

	fmt.Println("\nAll Multi-Node Tests Completed.")
}
