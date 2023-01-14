package main

import (
	"crypto/rand"
	"fmt"

	"crypto/bls" // any bls12381 module
)

const (
	// Number of shards
	nShards = 10
	// Number of signatures per shard
	nSignatures = 5
)

func main() {
	// Generate private keys for each signature
	privKeys := make([]*bls.SecretKey, nShards*nSignatures)
	for i := range privKeys {
		privKeys[i] = bls.NewSecretKey(rand.Reader)
	}

	// Generate public keys for each signature
	pubKeys := make([]*bls.PublicKey, nShards*nSignatures)
	for i, privKey := range privKeys {
		pubKeys[i] = privKey.PublicKey()
	}

	// Generate messages for each signature
	messages := make([][]byte, nShards*nSignatures)
	for i := range messages {
		messages[i] = make([]byte, 32)
		rand.Read(messages[i])
	}

	// Sign messages with corresponding private keys
	signatures := make([]*bls.Signature, nShards*nSignatures)
	for i, privKey := range privKeys {
		signatures[i] = privKey.Sign(messages[i])
	}

	// Create a map for counting signatures for each shard
	signatureCounts := make(map[int]int)
	for i := range signatures {
		shard := i % nShards
		signatureCounts[shard]++
	}

	// Randomly select shards for verification
	selectedShards := make(map[int]bool)
	for len(selectedShards) < nShards {
		shard := rand.Intn(nShards)
		selectedShards[shard] = true
	}

	// Aggregate signatures for selected shards
	aggregatedSig := bls.NewSignature()
	for shard := range selectedShards {
		start := shard * nSignatures
		end := start + signatureCounts[shard]
		for i := start; i < end; i++ {
			aggregatedSig.Aggregate(signatures[i])
		}
	}

	// Verify aggregated signature against public keys and messages of selected shards
	valid := true
	for shard := range selectedShards {
		start := shard * nSignatures
		end := start + signatureCounts[shard]
		for i := start; i < end; i++ {
			if !aggregatedSig.Verify(pubKeys[i], messages[i]) {
				valid = false
				break
			}
		}
	}

	if valid {
		fmt.Println("Aggregated signature is valid.")
	} else {
		fmt.Println("Invalid signature.")
	}
}
