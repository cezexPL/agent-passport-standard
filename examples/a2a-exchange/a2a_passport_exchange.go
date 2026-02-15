package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/agent-passport/standard-go/receipt"
	"github.com/agent-passport/standard-go/passport"
)

type AAMessage struct {
	Type         string          `json:"type"`
	ExchangeID   string          `json:"exchange_id"`
	AgentDid     string          `json:"agent_did"`
	PassportJSON json.RawMessage `json:"passport_json"`
	ReceiptJSON  json.RawMessage `json:"receipt_json"`
	Timestamp    string          `json:"timestamp"`
}

type A2AEnvelope struct {
	MessageType string   `json:"message_type"`
	Sender      string   `json:"sender"`
	Recipients  []string `json:"recipients"`
	Nonce       string   `json:"nonce"`
	Payload     AAMessage `json:"payload"`
}

func buildPassportForMessage() *passport.AgentPassport {
	p := &passport.AgentPassport{}
	p.Context = "https://agentpassport.org/v0.1"
	p.SpecVersion = "0.1.0"
	p.Type = "AgentPassport"
	p.ID = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	p.Keys.Signing = passport.SigningKey{
		Algorithm:  "Ed25519",
		PublicKey:  "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
	}
	p.Snapshot.Hash = "0x7a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5"
	p.Lineage.Kind = "single"
	p.Lineage.Generation = 1
	p.GenesisOwner.ID = p.ID
	p.CurrentOwner.ID = p.ID
	p.Keys.EVM = nil
	p.Context = "https://agentpassport.org/v0.1"
	p.Proof = &passport.Proof{
		Type:               "Ed25519Signature2020",
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod:  "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#key-1",
		ProofPurpose:       "assertionMethod",
		ProofValue:         "dummy",
	}
	return p
}

func buildReceiptForExchange(passportID string) *receipt.WorkReceipt {
	r, err := receipt.New(receipt.Config{
		ReceiptID: "550e8400-e29b-41d4-a716-446655440000",
		JobID:     "550e8400-e29b-41d4-a716-446655440001",
		AgentDID:  passportID,
		ClientDID: "did:key:z6MkpOwnerABCDEFGHIJKLMNOPQRSTUVWXYZ12345",
		AgentSnapshot: receipt.AgentSnapshot{
			Version: 1,
			Hash:    "0x7a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5",
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	err = r.AddEvent(receipt.ReceiptEvent{
		Type:        "claim",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		PayloadHash: "0xabc0000000000000000000000000000000000000000000000000000000000001",
		Signature:   "z2claim",
	})
	if err != nil {
		log.Fatal(err)
	}

	if hash, err := r.Hash(); err == nil {
		r.ReceiptHash = hash
	}
	return r
}

func main() {
	p := buildPassportForMessage()
	r := buildReceiptForExchange(p.ID)

	passportJSON, err := p.JSON()
	if err != nil {
		log.Fatal(err)
	}
	receiptJSON, err := json.Marshal(r)
	if err != nil {
		log.Fatal(err)
	}

	message := AAMessage{
		Type:         "passport_exchange.request",
		ExchangeID:   "ex-550e8400-e29b-41d4-a716-446655440099",
		AgentDid:     p.ID,
		PassportJSON: passportJSON,
		ReceiptJSON:  receiptJSON,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}
	envelope := A2AEnvelope{
		MessageType: "agent-passport-exchange-v1",
		Sender:      p.ID,
		Recipients:  []string{"did:key:z6MkpConsumer0000000000000000000000000000000000000000"},
		Nonce:       "nonce-001",
		Payload:     message,
	}

	wire, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("A2A payload:\n" + string(wire))
}
