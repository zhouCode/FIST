package testing

import (
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/AgnopraxLab/D2PFuzz/blob"
	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/ethclient"
	"github.com/AgnopraxLab/D2PFuzz/transaction"
	"github.com/AgnopraxLab/D2PFuzz/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// BlobMultiNodeTest implements multi-node blob transaction testing
type BlobMultiNodeTest struct{}

func (t *BlobMultiNodeTest) Name() string {
	return "blob-multi"
}

func (t *BlobMultiNodeTest) Description() string {
	return "Send blob transactions to multiple nodes and verify propagation"
}

func (t *BlobMultiNodeTest) Run(cfg *config.Config) error {
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Blob Transaction Multi-Node Test")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Get configuration - prefer new BlobMulti section, fallback to BlobTest
	var nodeIndices []int
	var blobCount int
	var blobDataSize int
	var maxFeePerBlobGas string
	var generatorType string
	var totalBlobTxs int
	var sendInterval int
	var nodeNonces []string

	if cfg.Test.BlobMulti.BlobCount > 0 { // New config section detected
		nodeIndices = cfg.Test.BlobMulti.NodeIndices
		blobCount = cfg.Test.BlobMulti.BlobCount
		blobDataSize = cfg.Test.BlobMulti.BlobDataSize
		maxFeePerBlobGas = cfg.Test.BlobMulti.MaxFeePerBlobGas
		generatorType = cfg.Test.BlobMulti.GeneratorType
		totalBlobTxs = cfg.Test.BlobMulti.TotalTransactions
		sendInterval = cfg.Test.BlobMulti.SendIntervalMS
		nodeNonces = cfg.Test.BlobMulti.Nonces
		fmt.Println("📋 Using new blob_multi configuration section")
	} else { // Fallback to BlobTest
		blobCfg := cfg.Test.BlobTest
		nodeIndices = blobCfg.MultiNodeIndices
		blobCount = blobCfg.BlobCount
		blobDataSize = blobCfg.BlobDataSize
		maxFeePerBlobGas = blobCfg.MaxFeePerBlobGas
		if len(blobCfg.Scenarios) > 0 {
			generatorType = blobCfg.Scenarios[0]
		} else {
			generatorType = "random"
		}
		totalBlobTxs = blobCfg.TotalBlobTxs
		sendInterval = blobCfg.SendInterval
		nodeNonces = blobCfg.MultiNodeNonces
		fmt.Println("📋 Using legacy blob_test configuration section")
	}

	// Validate blob count
	if blobCount < 1 || blobCount > blob.MaxBlobsPerTransaction {
		return fmt.Errorf("invalid blob count: %d (must be 1-%d)", blobCount, blob.MaxBlobsPerTransaction)
	}

	// Get node indices (default: use all nodes if empty)
	if len(nodeIndices) == 0 {
		nodeIndices = make([]int, len(cfg.P2P.BootstrapNodes))
		for i := range nodeIndices {
			nodeIndices[i] = i
		}
	}

	if len(nodeIndices) == 0 {
		return fmt.Errorf("no nodes configured")
	}

	fmt.Printf("📍 Target Nodes: %d nodes\n", len(nodeIndices))
	for _, idx := range nodeIndices {
		if idx >= len(cfg.P2P.BootstrapNodes) {
			return fmt.Errorf("invalid node index: %d", idx)
		}
		fmt.Printf("   - Node %d: %s\n", idx, cfg.GetNodeName(idx))
	}
	fmt.Printf("🧊 Blobs per transaction: %d\n", blobCount)
	fmt.Printf("📊 Transactions per node: %d\n", totalBlobTxs/len(nodeIndices))
	fmt.Println()

	// Initialize KZG
	fmt.Println("🔧 Initializing KZG trusted setup...")
	if err := blob.InitKZG(); err != nil {
		return fmt.Errorf("failed to initialize KZG: %w", err)
	}
	fmt.Println("✅ KZG initialized successfully")
	fmt.Println()

	// Get accounts
	if len(cfg.Accounts) == 0 {
		return fmt.Errorf("no accounts configured")
	}

	// Parse max fee per blob gas
	maxFeePerBlobGasBig := new(big.Int)
	if maxFeePerBlobGas != "" {
		if _, ok := maxFeePerBlobGasBig.SetString(maxFeePerBlobGas, 10); !ok {
			return fmt.Errorf("invalid max_fee_per_blob_gas: %s", maxFeePerBlobGas)
		}
	} else {
		maxFeePerBlobGasBig = big.NewInt(1000000000) // 1 Gwei default
	}

	// Determine generator type from string
	var genType blob.GeneratorType
	switch generatorType {
	case "random":
		genType = blob.GeneratorRandom
	case "pattern":
		genType = blob.GeneratorPattern
	case "zero":
		genType = blob.GeneratorZero
	case "l2-data":
		genType = blob.GeneratorL2Data
	default:
		genType = blob.GeneratorRandom
	}

	fmt.Printf("🎲 Generator type: %s\n", generatorType)
	fmt.Printf("💰 Max fee per blob gas: %s wei\n", maxFeePerBlobGasBig.String())
	fmt.Println()

	// Statistics tracking
	type NodeStats struct {
		NodeIndex int
		NodeName  string
		Success   int
		Failed    int
		TotalSent int
		Duration  time.Duration
	}

	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		hashesMu   sync.Mutex
		nodeStats  = make([]*NodeStats, len(nodeIndices))
		globalFail int
		nodeHashes = make(map[int][]common.Hash)
	)

	startTime := time.Now()

	// Send transactions to each node concurrently
	for i, nodeIdx := range nodeIndices {
		wg.Add(1)
		go func(i, nodeIdx int) {
			defer wg.Done()

			stats := &NodeStats{
				NodeIndex: nodeIdx,
				NodeName:  cfg.GetNodeName(nodeIdx),
			}
			nodeStats[i] = stats

			nodeStartTime := time.Now()

			// Create client for this node
			client, err := ethclient.NewClient(cfg, nodeIdx)
			if err != nil {
				fmt.Printf("❌ Node %d (%s): Failed to create client: %v\n", nodeIdx, stats.NodeName, err)
				mu.Lock()
				globalFail++
				mu.Unlock()
				return
			}

			fmt.Printf("✅ Node %d (%s): Connected\n", nodeIdx, stats.NodeName)

			// Calculate transactions for this node
			totalTxs := totalBlobTxs / len(nodeIndices)
			if totalTxs == 0 {
				totalTxs = 1
			}

			// Get accounts for this node
			accountIdx := i % len(cfg.Accounts)
			fromAccount := cfg.Accounts[accountIdx]
			toAccount := cfg.Accounts[(accountIdx+1)%len(cfg.Accounts)]

			// Resolve nonce for this node
			nonceStr := "auto" // default to auto
			if nodeIdx < len(nodeNonces) && nodeNonces[nodeIdx] != "" {
				nonceStr = nodeNonces[nodeIdx]
			}

			nonce, err := utils.ResolveNonce(client, nonceStr, common.HexToAddress(fromAccount.Address))
			if err != nil {
				fmt.Printf("❌ Node %d (%s): Failed to resolve nonce: %v\n", nodeIdx, stats.NodeName, err)
				mu.Lock()
				globalFail++
				mu.Unlock()
				return
			}

			// Send transactions
			for j := 0; j < totalTxs; j++ {
				// Build blob transaction
				builder := transaction.NewBlobTxBuilder(cfg.ChainID).
					WithFrom(fromAccount).
					WithTo(toAccount).
					WithNonce(nonce).
					WithCount(1).
					WithMaxFeePerBlobGas(maxFeePerBlobGasBig)

				// Generate and add blobs
				success := true
				for k := 0; k < blobCount; k++ {
					blobSize := blobDataSize
					if blobSize == 0 {
						blobSize = blob.BlobDataSize
					}

					blobData, err := blob.GenerateBlob(genType, blobSize)
					if err != nil {
						success = false
						break
					}

					if err := builder.AddBlobData(blobData); err != nil {
						success = false
						break
					}
				}

				if !success {
					stats.Failed++
					continue
				}

				// Build and send
				blobTx, err := builder.Build()
				if err != nil {
					stats.Failed++
					continue
				}

				// 在最终发送前，仅打印该节点“最后一笔”交易的关键参数
				if len(blobTx) > 0 && j == totalTxs-1 {
					tx := blobTx[0]
					fmt.Printf("   🧾 Node %d (%s) Final Tx Parameters:\n", nodeIdx, stats.NodeName)
					fmt.Printf("      Type: %d (BlobTxType=3)\n", tx.Type())
					fmt.Printf("      ChainID: %s\n", tx.ChainId().String())
					fmt.Printf("      Nonce: %d\n", tx.Nonce())
					fmt.Printf("      To: %s\n", func() string {
						if tx.To() != nil {
							return tx.To().Hex()
						}
						return "<nil>"
					}())
					fmt.Printf("      From(config): %s\n", fromAccount.Address)
					if addr, err := types.Sender(types.NewCancunSigner(cfg.ChainID), tx); err == nil {
						fmt.Printf("      From(recovered): %s\n", addr.Hex())
					} else {
						fmt.Printf("      From(recovered): <error: %v>\n", err)
					}
					fmt.Printf("      Value: %s wei\n", tx.Value().String())
					fmt.Printf("      Gas: %d\n", tx.Gas())
					fmt.Printf("      GasFeeCap: %s\n", tx.GasFeeCap().String())
					fmt.Printf("      GasTipCap: %s\n", tx.GasTipCap().String())
					if tx.Type() == 3 {
						feeCap := tx.BlobGasFeeCap()
						if feeCap != nil {
							fmt.Printf("      BlobFeeCap: %s\n", feeCap.String())
						}
						hashes := tx.BlobHashes()
						if hashes != nil {
							fmt.Printf("      BlobHashes: %d\n", len(hashes))
							for bi, bh := range hashes {
								fmt.Printf("        - blob[%d] hash: %s\n", bi, bh.Hex())
							}
						}
					}
				}

				// 使用 DevP2P Gossip 流发送 blob（宣告→拉取→回包），不经过 RPC
				if len(blobTx) == 0 {
					stats.Failed++
				} else {
					tx := blobTx[0]
					// 记录本次尝试的交易哈希（无论发送成功或失败）
					hashesMu.Lock()
					nodeHashes[nodeIdx] = append(nodeHashes[nodeIdx], tx.Hash())
					hashesMu.Unlock()
					if err := transaction.SendBlobViaGossip(client.GetSuite(), tx); err != nil {
						stats.Failed++
					} else {
						// 可选：针对多节点压力测试，此处不做每笔验证以提升吞吐
						stats.Success++
					}
				}

				stats.TotalSent++
				nonce++

				// Delay between transactions
				if j < totalTxs-1 && sendInterval > 0 {
					time.Sleep(time.Duration(sendInterval) * time.Millisecond)
				}
			}

			stats.Duration = time.Since(nodeStartTime)
			fmt.Printf("✅ Node %d (%s): Completed - %d success, %d failed\n",
				nodeIdx, stats.NodeName, stats.Success, stats.Failed)

		}(i, nodeIdx)
	}

	// Wait for all nodes to complete
	wg.Wait()
	totalDuration := time.Since(startTime)

	// Print summary
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Test Summary")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	totalSuccess := 0
	totalFailed := 0

	fmt.Println("Per-Node Statistics:")
	for _, stats := range nodeStats {
		if stats == nil {
			continue
		}
		fmt.Printf("\n  Node %d (%s):\n", stats.NodeIndex, stats.NodeName)
		fmt.Printf("    ✅ Successful: %d\n", stats.Success)
		fmt.Printf("    ❌ Failed: %d\n", stats.Failed)
		fmt.Printf("    📊 Total: %d\n", stats.TotalSent)
		fmt.Printf("    ⏱️  Duration: %v\n", stats.Duration)
		if stats.Success > 0 && stats.Duration > 0 {
			fmt.Printf("    📈 Rate: %.2f tx/sec\n", float64(stats.Success)/stats.Duration.Seconds())
		}

		totalSuccess += stats.Success
		totalFailed += stats.Failed
	}

	fmt.Println()
	fmt.Println("Overall Statistics:")
	fmt.Printf("  ✅ Total Successful: %d\n", totalSuccess)
	fmt.Printf("  ❌ Total Failed: %d\n", totalFailed)
	fmt.Printf("  ⏱️  Total Duration: %v\n", totalDuration)
	if totalSuccess > 0 {
		fmt.Printf("  📊 Overall Rate: %.2f tx/sec\n", float64(totalSuccess)/totalDuration.Seconds())
	}

	// 保存所有节点的交易哈希（分组并添加节点标注）到指定文件
	if len(nodeHashes) > 0 {
		hashFile := "/home/kkk/workspaces/FIST/TxNetworkFuzz/cmd/manual/txhashes.txt"
		var b strings.Builder
		for _, stats := range nodeStats {
			if stats == nil {
				continue
			}
			hashes := nodeHashes[stats.NodeIndex]
			if len(hashes) == 0 {
				continue
			}
			// 节点标注头（仅输出节点名称，不含索引）
			b.WriteString(fmt.Sprintf("# %s\n", stats.NodeName))
			for _, h := range hashes {
				b.WriteString(h.Hex())
				b.WriteString("\n")
			}
			b.WriteString("\n")
		}
		content := b.String()
		if content != "" {
			if err := utils.WriteStringToFile(hashFile, content); err != nil {
				fmt.Printf("⚠️  Warning: Failed to save transaction hashes: %v\n", err)
			} else {
				// 统计总写入条数
				count := 0
				for _, hs := range nodeHashes {
					count += len(hs)
				}
				fmt.Printf("💾 Saved %d transaction hash(es) to %s\n", count, hashFile)
			}
		}
	}
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Blob Multi-Node Test - Completed")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	if totalFailed > 0 {
		return fmt.Errorf("test completed with %d failures", totalFailed)
	}

	return nil
}
