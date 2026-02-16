// Package identity implements key rotation and identity chain types from APS v1.1 §19.
package identity

import (
	"fmt"
	"time"
)

// KeyRotation represents a DID key rotation event.
type KeyRotation struct {
	Type      string    `json:"type"`
	OldDID    string    `json:"oldDid"`
	NewDID    string    `json:"newDid"`
	Reason    string    `json:"reason"`
	RotatedAt time.Time `json:"rotatedAt"`
	Proof     string    `json:"proof"`
}

// Validate checks required fields.
func (r *KeyRotation) Validate() error {
	if r.OldDID == "" {
		return fmt.Errorf("oldDid is required")
	}
	if r.NewDID == "" {
		return fmt.Errorf("newDid is required")
	}
	if r.OldDID == r.NewDID {
		return fmt.Errorf("oldDid and newDid must differ")
	}
	if r.Proof == "" {
		return fmt.Errorf("proof is required")
	}
	return nil
}

// IdentityChainNode is a single node in a linked list of DIDs.
type IdentityChainNode struct {
	DID      string             `json:"did"`
	ActiveAt time.Time          `json:"activeAt"`
	RevokedAt *time.Time        `json:"revokedAt,omitempty"`
	Next     *IdentityChainNode `json:"-"`
}

// IdentityChain is a linked list tracking DID history.
type IdentityChain struct {
	Head *IdentityChainNode
}

// Append adds a new DID to the chain, revoking the current head.
func (c *IdentityChain) Append(did string, at time.Time) {
	node := &IdentityChainNode{DID: did, ActiveAt: at}
	if c.Head == nil {
		c.Head = node
		return
	}
	// Find tail
	cur := c.Head
	for cur.Next != nil {
		cur = cur.Next
	}
	cur.RevokedAt = &at
	cur.Next = node
}

// Current returns the latest DID.
func (c *IdentityChain) Current() string {
	if c.Head == nil {
		return ""
	}
	cur := c.Head
	for cur.Next != nil {
		cur = cur.Next
	}
	return cur.DID
}

// Len returns the number of DIDs in the chain.
func (c *IdentityChain) Len() int {
	n := 0
	cur := c.Head
	for cur != nil {
		n++
		cur = cur.Next
	}
	return n
}

// RecoveryRequest represents a request to recover a lost identity.
type RecoveryRequest struct {
	Type          string   `json:"type"`
	LostDID       string   `json:"lostDid"`
	RecoveryDID   string   `json:"recoveryDid"`
	Evidence      []string `json:"evidence"`
	RequestedAt   time.Time `json:"requestedAt"`
	ApprovedBy    []string `json:"approvedBy,omitempty"`
}

// Validate checks required fields.
func (r *RecoveryRequest) Validate() error {
	if r.LostDID == "" {
		return fmt.Errorf("lostDid is required")
	}
	if r.RecoveryDID == "" {
		return fmt.Errorf("recoveryDid is required")
	}
	if len(r.Evidence) == 0 {
		return fmt.Errorf("evidence is required")
	}
	return nil
}
