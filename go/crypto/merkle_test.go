package crypto

import (
	"fmt"
	"testing"
)

func TestMerkleTree_8Leaves(t *testing.T) {
	leaves := make([]string, 8)
	for i := range leaves {
		leaves[i] = Keccak256([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	tree := NewMerkleTree(leaves)
	root := tree.Root()
	if root == "" {
		t.Fatal("root should not be empty")
	}
	if len(root) != 66 {
		t.Errorf("root should be 66 chars, got %d", len(root))
	}
	for i, leaf := range leaves {
		proof := tree.Proof(i)
		if !VerifyProof(leaf, root, proof, i) {
			t.Errorf("proof verification failed for leaf %d", i)
		}
	}
}

func TestMerkleTree_SingleLeaf(t *testing.T) {
	leaf := Keccak256([]byte("only"))
	tree := NewMerkleTree([]string{leaf})
	if tree.Root() != leaf {
		t.Errorf("single leaf root should equal leaf")
	}
}

func TestMerkleTree_Empty(t *testing.T) {
	tree := NewMerkleTree(nil)
	if tree.Root() != "" {
		t.Error("empty tree root should be empty")
	}
}

func TestVerifyProof_WrongLeaf(t *testing.T) {
	leaves := []string{
		Keccak256([]byte("a")),
		Keccak256([]byte("b")),
		Keccak256([]byte("c")),
		Keccak256([]byte("d")),
	}
	tree := NewMerkleTree(leaves)
	proof := tree.Proof(0)
	if VerifyProof(Keccak256([]byte("wrong")), tree.Root(), proof, 0) {
		t.Error("should not verify with wrong leaf")
	}
}
