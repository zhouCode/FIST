package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func main() {
	rpcURL := mustEnv("RPC_URL")
	privHex := mustEnv("FROM_PRIVKEY_HEX")
	to := common.HexToAddress(envOrDefault("TO_ADDRESS", "0x0000000000000000000000000000000000000000"))
	fmt.Println("to:", to)
	ctx := context.Background()
	fmt.Println("ctx:", ctx)
	cl, err := ethclient.Dial(rpcURL)
	must(err)
	defer cl.Close()
	priv, err := crypto.HexToECDSA(privHex)
	must(err)
	from := crypto.PubkeyToAddress(priv.PublicKey)
	nonce, err := cl.NonceAt(ctx, from, nil)
	fmt.Println("nonce:", nonce)
	must(err)
	chainID, err := cl.ChainID(ctx)
	must(err)
	fmt.Println("chainID:", chainID)
	// 1. Build valid blob tx with 3 blobs
	txInner, err := buildValidBlobTx(ctx, cl, to, chainID, nonce)
	must(err)
	// 2. Sign the valid transaction
	tx := types.NewTx(txInner)
	signer := types.LatestSignerForChainID(chainID)
	signed, err := types.SignTx(tx, signer, priv)
	must(err)

	// 4. Broadcast the signed transaction to all provided RPCs
	if err := cl.SendTransaction(ctx, signed); err != nil {
		log.Printf("send transaction to %s failed: %v", rpcURL, err)
		return
	}
	fmt.Printf("sent tx to %s: %s\n", rpcURL, signed.Hash().Hex())

}

func buildValidBlobTx(ctx context.Context, cl *ethclient.Client, to common.Address, chainID *big.Int, nonce uint64) (*types.BlobTx, error) {
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
	// ... existing code ...
	inner := &types.BlobTx{
		ChainID:    uint256.MustFromBig(chainID),
		Nonce:      nonce,
		GasTipCap:  uint256.MustFromBig(tip),
		GasFeeCap:  uint256.MustFromBig(feeCap),
		Gas:        50_000,
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
