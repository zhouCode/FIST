package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"

	ethtest "github.com/AgnopraxLab/D2PFuzz/devp2p/protocol/eth"
	"github.com/AgnopraxLab/D2PFuzz/transaction"
	"github.com/AgnopraxLab/D2PFuzz/utils"
)

func main() {
	enodeStr := mustEnv("ENODE_URL")
	jwtSecret := mustEnv("JWT_SECRET_HEX")
	privHex := mustEnv("FROM_PRIVKEY_HEX")
	to := common.HexToAddress(envOrDefault("TO_ADDRESS", "0x0000000000000000000000000000000000000000"))
	nodeName := envOrDefault("NODE_NAME", "node")

	fmt.Println("to:", to)
	ctx := context.Background()
	fmt.Println("ctx:", ctx)

	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	must(err)

	rpcAddr := envOrDefault("RPC_ADDR", "http://127.0.0.1:8545")
	cl, err := ethclient.Dial(rpcAddr)
	must(err)
	defer cl.Close()

	priv, err := crypto.HexToECDSA(privHex)
	must(err)
	from := crypto.PubkeyToAddress(priv.PublicKey)

	// 使用 pending nonce，避免已有待处理交易导致 nonce 过低/过高
	nonce, err := cl.PendingNonceAt(ctx, from)
	fmt.Println("pending nonce:", nonce)
	must(err)

	chainID, err := cl.ChainID(ctx)
	must(err)
	fmt.Println("chainID:", chainID)

	txInner, err := buildValidBlobTxDevP2P(ctx, cl, to, chainID, nonce)
	must(err)

	tx := types.NewTx(txInner)
	signer := types.LatestSignerForChainID(chainID)
	fmt.Println("signer:", signer)
	signed, err := types.SignTx(tx, signer, priv)
	must(err)

	jwtSecretBytes, err := utils.ParseJWTSecretFromHexString(jwtSecret)
	must(err)
	engineAddr := envOrDefault("ENGINE_ADDR", "127.0.0.1:8551")
	suite, err := ethtest.NewSuite(node, engineAddr, common.Bytes2Hex(jwtSecretBytes[:]), nodeName)
	must(err)
	err = suite.InitializeAndConnect()
	must(err)

	p2pAddr := fmt.Sprintf("%s:%d", node.IP().String(), node.TCP())
	target := p2pAddr
	if err := transaction.SendBlobViaGossip(suite, signed); err != nil {
		log.Printf("gossip send to %s failed: %v", target, err)
		return
	}
	fmt.Printf("gossip-sent tx to %s: %s\n", target, signed.Hash().Hex())

	// Verify acceptance via DevP2P (request pooled transaction by hash), with retries
	found := false
	for attempt := 1; attempt <= 3; attempt++ {
		vconn, err := suite.Dial()
		if err != nil {
			log.Printf("verification dial failed (attempt %d): %v", attempt, err)
			time.Sleep(3 * time.Second)
			continue
		}
		if err := vconn.Peer(nil); err != nil {
			log.Printf("verification peering failed (attempt %d): %v", attempt, err)
			vconn.Close()
			time.Sleep(3 * time.Second)
			continue
		}
		req := &eth.GetPooledTransactionsPacket{
			RequestId:                    999,
			GetPooledTransactionsRequest: []common.Hash{signed.Hash()},
		}
		if err := vconn.Write(ethtest.EthProto(), eth.GetPooledTransactionsMsg, req); err != nil {
			log.Printf("verification write failed (attempt %d): %v", attempt, err)
			vconn.Close()
			time.Sleep(3 * time.Second)
			continue
		}
		if err := vconn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			log.Printf("verification set deadline failed (attempt %d): %v", attempt, err)
			vconn.Close()
			time.Sleep(3 * time.Second)
			continue
		}
		resp := new(eth.PooledTransactionsPacket)
		if err := vconn.ReadMsg(ethtest.EthProto(), eth.PooledTransactionsMsg, resp); err != nil {
			log.Printf("verification read failed (attempt %d): %v", attempt, err)
			vconn.Close()
			time.Sleep(3 * time.Second)
			continue
		}
		vconn.Close()
		if resp.RequestId != req.RequestId {
			log.Printf("verification: unexpected request id: got %d, want %d", resp.RequestId, req.RequestId)
			time.Sleep(3 * time.Second)
			continue
		}
		if len(resp.PooledTransactionsResponse) > 0 {
			found = true
			break
		}
		time.Sleep(3 * time.Second)
	}
	fmt.Println("found:", found)
	// if !found {
	// 	log.Printf("verification: tx not found in pool after retries; using RPC fallback")
	// 	if err := cl.SendTransaction(ctx, signed); err != nil {
	// 		log.Printf("RPC eth_sendRawTransaction failed: %v", err)
	// 	} else {
	// 		log.Printf("RPC send succeeded: %s", signed.Hash().Hex())
	// 	}
	// 	return
	// }
	// fmt.Println("verification: tx present in pool")
}

func buildValidBlobTxDevP2P(ctx context.Context, cl *ethclient.Client, to common.Address, chainID *big.Int, nonce uint64) (*types.BlobTx, error) {
	tip, err := cl.SuggestGasTipCap(ctx)
	minTip := big.NewInt(1 * params.GWei)
	if err != nil || tip.Sign() == 0 {
		tip = new(big.Int).Set(minTip)
	} else if tip.Cmp(minTip) < 0 {
		tip = new(big.Int).Set(minTip)
	}
	header, err := cl.HeaderByNumber(ctx, nil)

	var feeCap *big.Int
	if err != nil || header == nil || header.BaseFee == nil {
		feeCap = big.NewInt(30 * params.GWei)
		feeCap.Add(feeCap, tip)
	} else {
		feeCap = new(big.Int).Mul(header.BaseFee, big.NewInt(2))
		feeCap.Add(feeCap, tip)
	}

	blobBaseFee, err := cl.BlobBaseFee(ctx)
	var blobFeeCap *big.Int
	if err != nil || blobBaseFee == nil || blobBaseFee.Sign() == 0 {
		blobFeeCap = big.NewInt(1 * params.GWei)
	} else {
		blobFeeCap = new(big.Int).Mul(blobBaseFee, big.NewInt(2))
	}

	if blobFeeCap.Cmp(minTip) < 0 {
		blobFeeCap = new(big.Int).Set(minTip)
	}

	blobs := make([]kzg4844.Blob, 0, 3)
	commitments := make([]kzg4844.Commitment, 0, 3)
	blobHashes := make([]common.Hash, 0, 3)
	proofs := make([]kzg4844.Proof, 0, 3)
	for i := 0; i < 3; i++ {
		var b kzg4844.Blob
		copy(b[:], []byte(fmt.Sprintf("blob %d: hello, PeerDAS cell proofs", i)))
		comm, err := kzg4844.BlobToCommitment(&b)
		if err != nil {
			return nil, err
		}
		proof, err := kzg4844.ComputeBlobProof(&b, comm)
		if err != nil {
			return nil, err
		}
		vh := kzg4844.CalcBlobHashV1(sha256.New(), &comm)
		blobs = append(blobs, b)
		commitments = append(commitments, comm)
		blobHashes = append(blobHashes, common.Hash(vh))
		proofs = append(proofs, proof)
	}

	sidecar := types.NewBlobTxSidecar(types.BlobSidecarVersion0, blobs, commitments, proofs)
	fmt.Println("tip:", tip)
	fmt.Println("feeCap:", feeCap)
	fmt.Println("blobFeeCap:", blobFeeCap)
	inner := &types.BlobTx{
		ChainID:    uint256.MustFromBig(chainID),
		Nonce:      nonce,
		GasTipCap:  uint256.MustFromBig(tip),
		GasFeeCap:  uint256.MustFromBig(feeCap),
		Gas:        uint64(21000),
		To:         to,
		Value:      uint256.NewInt(0),
		BlobFeeCap: uint256.MustFromBig(blobFeeCap),
		BlobHashes: blobHashes,
		Sidecar:    sidecar,
	}
	return inner, nil
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func mustEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("missing env %s", key)
	}
	return value
}

func envOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
