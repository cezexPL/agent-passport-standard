package crypto

import (
	"strings"
	"encoding/hex"

	"golang.org/x/crypto/sha3"
)

// MerkleTree is a simple binary Merkle tree using keccak256.
type MerkleTree struct {
	leaves []string
	layers [][]string
}

// NewMerkleTree builds a Merkle tree from leaf hashes (hex strings with or without 0x prefix).
func NewMerkleTree(leaves []string) *MerkleTree {
	if len(leaves) == 0 {
		return &MerkleTree{}
	}

	normalized := make([]string, len(leaves))
	copy(normalized, leaves)

	// Pad to power of 2
	for len(normalized)&(len(normalized)-1) != 0 {
		normalized = append(normalized, normalized[len(normalized)-1])
	}

	mt := &MerkleTree{
		leaves: normalized,
		layers: [][]string{normalized},
	}

	current := normalized
	for len(current) > 1 {
		next := make([]string, len(current)/2)
		for i := 0; i < len(current); i += 2 {
			next[i/2] = hashPair(current[i], current[i+1])
		}
		mt.layers = append(mt.layers, next)
		current = next
	}

	return mt
}

// Root returns the Merkle root hash.
func (mt *MerkleTree) Root() string {
	if len(mt.layers) == 0 {
		return ""
	}
	top := mt.layers[len(mt.layers)-1]
	if len(top) == 0 {
		return ""
	}
	return top[0]
}

// Proof returns the Merkle proof (sibling hashes) for the leaf at the given index.
func (mt *MerkleTree) Proof(index int) []string {
	if index < 0 || index >= len(mt.leaves) {
		return nil
	}

	var proof []string
	idx := index
	for i := 0; i < len(mt.layers)-1; i++ {
		layer := mt.layers[i]
		if idx%2 == 0 {
			if idx+1 < len(layer) {
				proof = append(proof, layer[idx+1])
			}
		} else {
			proof = append(proof, layer[idx-1])
		}
		idx /= 2
	}
	return proof
}

// VerifyProof verifies a Merkle proof for a leaf against the expected root.
func VerifyProof(leaf, root string, proof []string, index int) bool {
	current := leaf
	idx := index
	for _, sibling := range proof {
		if idx%2 == 0 {
			current = hashPair(current, sibling)
		} else {
			current = hashPair(sibling, current)
		}
		idx /= 2
	}
	return current == root
}

func hashPair(a, b string) string {
	aBytes := hexToBytes(a)
	bBytes := hexToBytes(b)

	// Spec requires deterministic sorted-concat pairing before hashing.
	if len(aBytes) > 0 && len(bBytes) > 0 {
		if strings.Compare(encodeHexLower(aBytes), encodeHexLower(bBytes)) > 0 {
			aBytes, bBytes = bBytes, aBytes
		}
	}

	h := sha3.NewLegacyKeccak256()
	h.Write(aBytes)
	h.Write(bBytes)
	return "0x" + hex.EncodeToString(h.Sum(nil))
}

func encodeHexLower(data []byte) string {
	return hex.EncodeToString(data)
}

func hexToBytes(s string) []byte {
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	b, _ := hex.DecodeString(s)
	return b
}
