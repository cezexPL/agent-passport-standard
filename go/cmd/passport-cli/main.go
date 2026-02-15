package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cezexPL/agent-passport-standard/go/crypto"
	"github.com/cezexPL/agent-passport-standard/go/envelope"
	"github.com/cezexPL/agent-passport-standard/go/passport"
	"github.com/cezexPL/agent-passport-standard/go/receipt"
)

const (
	commandVerify   = "verify"
	commandReceipt  = "receipt"
	commandEnvelope = "envelope"
	commandBundle   = "bundle"
)

type verificationResult struct {
	Artifact string            `json:"artifact"`
	Path     string            `json:"path"`
	Valid    bool              `json:"valid"`
	Checks   map[string]string `json:"checks"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	var code int
	switch os.Args[1] {
	case commandVerify:
		code = runPassportVerify(os.Args[2:])
	case commandReceipt:
		code = runReceiptCommand(os.Args[2:])
	case commandEnvelope:
		code = runEnvelopeCommand(os.Args[2:])
	case commandBundle:
		code = runBundleCommand(os.Args[2:])
	case "-h", "--help":
		printUsage()
		return
	default:
		printUsage()
		code = 2
	}

	os.Exit(code)
}

func runPassportVerify(args []string) int {
	fs := flag.NewFlagSet(commandVerify, flag.ContinueOnError)
	publicKey := fs.String("public-key", "", "override verification key in base58, did:key or hex format")
	jsonOutput := fs.Bool("json", false, "emit verification result as JSON")
	_ = fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: passport-cli verify [--public-key value] [--json] <passport.json>")
		return 2
	}

	result := verifyPassport(fs.Arg(0), *publicKey)
	emitResult(result, *jsonOutput)
	if result.Valid {
		return 0
	}
	return 1
}

func runReceiptCommand(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: passport-cli receipt verify <receipt.json>")
		return 2
	}
	if args[0] != "verify" {
		fmt.Fprintln(os.Stderr, "usage: passport-cli receipt verify <receipt.json>")
		return 2
	}

	fs := flag.NewFlagSet("receipt verify", flag.ContinueOnError)
	publicKey := fs.String("public-key", "", "override verification key in base58, did:key or hex format")
	jsonOutput := fs.Bool("json", false, "emit verification result as JSON")
	_ = fs.Parse(args[1:])
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: passport-cli receipt verify [--public-key value] [--json] <receipt.json>")
		return 2
	}

	result := verifyReceipt(fs.Arg(0), *publicKey)
	emitResult(result, *jsonOutput)
	if result.Valid {
		return 0
	}
	return 1
}

func runEnvelopeCommand(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: passport-cli envelope validate <envelope.json>")
		return 2
	}
	if args[0] != "validate" {
		fmt.Fprintln(os.Stderr, "usage: passport-cli envelope validate <envelope.json>")
		return 2
	}

	fs := flag.NewFlagSet("envelope validate", flag.ContinueOnError)
	publicKey := fs.String("public-key", "", "override verification key in base58, did:key or hex format")
	jsonOutput := fs.Bool("json", false, "emit validation result as JSON")
	_ = fs.Parse(args[1:])
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: passport-cli envelope validate [--public-key value] [--json] <envelope.json>")
		return 2
	}

	result := validateEnvelope(fs.Arg(0), *publicKey)
	emitResult(result, *jsonOutput)
	if result.Valid {
		return 0
	}
	return 1
}

func verifyPassport(path string, overrideKey string) verificationResult {
	result := verificationResult{Artifact: "passport", Path: path, Checks: map[string]string{}}
	result.Valid = true

	data, err := os.ReadFile(path)
	if err != nil {
		result.Valid = false
		result.Checks["file"] = err.Error()
		return result
	}

	var p passport.AgentPassport
	if err := json.Unmarshal(data, &p); err != nil {
		result.Valid = false
		result.Checks["json"] = err.Error()
		return result
	}

	if err := validatePassportSchema(&p); err != nil {
		result.Valid = false
		result.Checks["schema"] = err.Error()
	} else {
		result.Checks["schema"] = "ok"
	}

	hash, err := p.Hash()
	if err != nil {
		result.Valid = false
		result.Checks["passport_hash"] = err.Error()
	} else {
		result.Checks["passport_hash"] = "computed " + hash
	}

	snapshotPayload := map[string]interface{}{
		"skills":   p.Snapshot.Skills,
		"soul":     p.Snapshot.Soul,
		"policies": p.Snapshot.Policies,
	}
	snapshotHash, err := crypto.SnapshotHash(snapshotPayload)
	if err != nil {
		result.Valid = false
		result.Checks["snapshot_hash"] = err.Error()
	} else {
		snapshotMatch := snapshotHash == p.Snapshot.Hash
		result.Checks["snapshot_hash"] = fmt.Sprintf("%t (%s)", snapshotMatch, snapshotHash)
		if !snapshotMatch {
			result.Valid = false
		}
	}

	if p.Proof == nil {
		result.Valid = false
		result.Checks["signature"] = "missing proof"
	} else {
		pk, pkErr := resolvePublicKey(p.Keys.Signing.PublicKey, overrideKey, p.Proof.VerificationMethod)
		if pkErr != nil {
			result.Valid = false
			result.Checks["signature"] = "key resolution: " + pkErr.Error()
		} else {
			sigHex, sigErr := normalizeSignatureValue(p.Proof.ProofValue)
			if sigErr != nil {
				result.Valid = false
				result.Checks["signature"] = "signature: " + sigErr.Error()
			} else {
				copy := p
				copy.Proof = nil
				canonical, _ := crypto.CanonicalizeJSON(copy)
				ok, verifyErr := crypto.Ed25519Verify(pk, canonical, sigHex)
				if verifyErr != nil {
					result.Valid = false
					result.Checks["signature"] = "verify error: " + verifyErr.Error()
				} else {
					result.Checks["signature"] = fmt.Sprintf("%t", ok)
					if !ok {
						result.Valid = false
					}
				}
			}
		}
	}

	return result
}

func verifyReceipt(path string, overrideKey string) verificationResult {
	result := verificationResult{Artifact: "work_receipt", Path: path, Checks: map[string]string{}}
	result.Valid = true

	data, err := os.ReadFile(path)
	if err != nil {
		result.Valid = false
		result.Checks["file"] = err.Error()
		return result
	}

	var r receipt.WorkReceipt
	if err := json.Unmarshal(data, &r); err != nil {
		result.Valid = false
		result.Checks["json"] = err.Error()
		return result
	}

	if err := validateReceiptSchema(&r); err != nil {
		result.Valid = false
		result.Checks["schema"] = err.Error()
	} else {
		result.Checks["schema"] = "ok"
	}

	hash, err := r.Hash()
	if err != nil {
		result.Valid = false
		result.Checks["receipt_hash"] = err.Error()
	} else {
		result.Checks["receipt_hash"] = fmt.Sprintf("computed %s", hash)
		if r.ReceiptHash != hash {
			result.Valid = false
			result.Checks["receipt_hash_match"] = "false"
		} else {
			result.Checks["receipt_hash_match"] = "true"
		}
	}

	if r.Proof == nil {
		result.Valid = false
		result.Checks["signature"] = "missing proof"
	} else {
		pk, pkErr := resolvePublicKey("", overrideKey, r.Proof.VerificationMethod)
		if pkErr != nil {
			result.Valid = false
			result.Checks["signature"] = "key resolution: " + pkErr.Error()
		} else {
			sigHex, sigErr := normalizeSignatureValue(r.Proof.ProofValue)
			if sigErr != nil {
				result.Valid = false
				result.Checks["signature"] = "signature: " + sigErr.Error()
			} else {
				copy := r
				copy.Proof = nil
				canonical, _ := crypto.CanonicalizeJSON(copy)
				ok, verifyErr := crypto.Ed25519Verify(pk, canonical, sigHex)
				if verifyErr != nil {
					result.Valid = false
					result.Checks["signature"] = "verify error: " + verifyErr.Error()
				} else {
					result.Checks["signature"] = fmt.Sprintf("%t", ok)
					if !ok {
						result.Valid = false
					}
				}
			}
		}
	}

	return result
}

func validateEnvelope(path string, overrideKey string) verificationResult {
	result := verificationResult{Artifact: "security_envelope", Path: path, Checks: map[string]string{}}
	result.Valid = true

	data, err := os.ReadFile(path)
	if err != nil {
		result.Valid = false
		result.Checks["file"] = err.Error()
		return result
	}

	var e envelope.SecurityEnvelope
	if err := json.Unmarshal(data, &e); err != nil {
		result.Valid = false
		result.Checks["json"] = err.Error()
		return result
	}

	if err := validateEnvelopeSchema(&e); err != nil {
		result.Valid = false
		result.Checks["schema"] = err.Error()
	} else {
		result.Checks["schema"] = "ok"
	}

	if err := e.Validate(); err != nil {
		result.Valid = false
		result.Checks["policy"] = err.Error()
	} else {
		result.Checks["policy"] = "ok"
	}

	hash, err := e.Hash()
	if err != nil {
		result.Valid = false
		result.Checks["envelope_hash"] = err.Error()
	} else {
		if e.EnvelopeHash != hash {
			result.Valid = false
			result.Checks["envelope_hash_match"] = "false"
		} else {
			result.Checks["envelope_hash_match"] = "true"
		}
		result.Checks["envelope_hash"] = "computed " + hash
	}

	if e.Proof != nil {
		pk, pkErr := resolvePublicKey("", overrideKey, e.Proof.VerificationMethod)
		if pkErr != nil {
			result.Valid = false
			result.Checks["signature"] = "key resolution: " + pkErr.Error()
		} else {
			sigHex, sigErr := normalizeSignatureValue(e.Proof.ProofValue)
			if sigErr != nil {
				result.Valid = false
				result.Checks["signature"] = "signature: " + sigErr.Error()
			} else {
				copy := e
				copy.Proof = nil
				canonical, _ := crypto.CanonicalizeJSON(copy)
				ok, verifyErr := crypto.Ed25519Verify(pk, canonical, sigHex)
				if verifyErr != nil {
					result.Valid = false
					result.Checks["signature"] = "verify error: " + verifyErr.Error()
				} else {
					result.Checks["signature"] = fmt.Sprintf("%t", ok)
					if !ok {
						result.Valid = false
					}
				}
			}
		}
	} else {
		result.Checks["signature"] = "no proof field"
	}

	return result
}

func validatePassportSchema(p *passport.AgentPassport) error {
	if p.Context != "https://agentpassport.org/v0.1" {
		return errors.New("context must be https://agentpassport.org/v0.1")
	}
	if p.Type != "AgentPassport" {
		return errors.New("type must be AgentPassport")
	}
	if p.SpecVersion == "" {
		return errors.New("spec_version is required")
	}
	if p.ID == "" {
		return errors.New("id is required")
	}
	if p.Keys.Signing.PublicKey == "" {
		return errors.New("keys.signing.public_key is required")
	}
	if p.Keys.Signing.Algorithm != "Ed25519" {
		return errors.New("keys.signing.algorithm must be Ed25519")
	}
	if p.Proof == nil {
		return errors.New("proof is required")
	}
	if p.Snapshot.Hash == "" {
		return errors.New("snapshot.hash is required")
	}
	if p.GenesisOwner.ID == "" || p.CurrentOwner.ID == "" {
		return errors.New("owner DID fields are required")
	}
	if p.Snapshot.Version < 1 {
		return errors.New("snapshot.version must be >= 1")
	}
	return nil
}

func validateReceiptSchema(r *receipt.WorkReceipt) error {
	if r.Context != "https://agentpassport.org/v0.1" {
		return errors.New("context must be https://agentpassport.org/v0.1")
	}
	if r.Type != "WorkReceipt" {
		return errors.New("type must be WorkReceipt")
	}
	if r.SpecVersion == "" {
		return errors.New("spec_version is required")
	}
	if r.ReceiptID == "" {
		return errors.New("receipt_id is required")
	}
	if r.JobID == "" {
		return errors.New("job_id is required")
	}
	if r.AgentDID == "" || r.ClientDID == "" {
		return errors.New("agent_did and client_did are required")
	}
	if len(r.Events) == 0 {
		return errors.New("events must contain at least one event")
	}
	if r.ReceiptHash == "" {
		return errors.New("receipt_hash is required")
	}
	if r.Proof == nil {
		return errors.New("proof is required")
	}
	return nil
}

func validateEnvelopeSchema(e *envelope.SecurityEnvelope) error {
	if e.Context != "https://agentpassport.org/v0.1" {
		return errors.New("context must be https://agentpassport.org/v0.1")
	}
	if e.Type != "SecurityEnvelope" {
		return errors.New("type must be SecurityEnvelope")
	}
	if e.SpecVersion == "" {
		return errors.New("spec_version is required")
	}
	if e.AgentDID == "" {
		return errors.New("agent_did is required")
	}
	if e.EnvelopeHash == "" {
		return errors.New("envelope_hash is required")
	}
	if e.Proof == nil {
		return errors.New("proof is required")
	}
	return nil
}

func resolvePublicKey(keyHint, override, verificationMethod string) (ed25519.PublicKey, error) {
	if override != "" {
		return parsePublicKey(override)
	}
	if keyHint != "" {
		return parsePublicKey(keyHint)
	}
	if verificationMethod != "" {
		if idx := strings.Index(verificationMethod, "#"); idx >= 0 {
			verificationMethod = verificationMethod[:idx]
		}
		return parsePublicKey(verificationMethod)
	}
	return nil, errors.New("no public key source")
}

func parsePublicKey(raw string) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("public key is empty")
	}

	if strings.HasPrefix(trimmed, "did:key:") {
		trimmed = strings.TrimPrefix(trimmed, "did:key:")
	}

	// did:key form uses multibase-base58btc prefix `z`.
	if strings.HasPrefix(trimmed, "z") {
		decoded, err := decodeBase58(trimmed[1:])
		if err != nil {
			return nil, err
		}
		if len(decoded) == 34 && decoded[0] == 0xed && decoded[1] == 0x01 {
			decoded = decoded[2:]
		}
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("decoded public key has invalid length: %d", len(decoded))
		}
		return ed25519.PublicKey(decoded), nil
	}

	if isHex(trimmed) {
		decoded, err := hex.DecodeString(strings.TrimPrefix(trimmed, "0x"))
		if err != nil {
			return nil, err
		}
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("decoded public key has invalid length: %d", len(decoded))
		}
		return ed25519.PublicKey(decoded), nil
	}

	decoded, err := decodeBase58(trimmed)
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("decoded public key has invalid length: %d", len(decoded))
	}
	return ed25519.PublicKey(decoded), nil
}

func normalizeSignatureValue(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", errors.New("signature is empty")
	}
	if isHex(trimmed) {
		return strings.TrimPrefix(trimmed, "0x"), nil
	}
	decoded, err := decodeBase58(trimmed)
	if err != nil {
		return "", err
	}
	if len(decoded) != ed25519.SignatureSize {
		return "", fmt.Errorf("decoded signature has invalid length: %d", len(decoded))
	}
	return hex.EncodeToString(decoded), nil
}

func isHex(s string) bool {
	d := strings.TrimPrefix(s, "0x")
	if len(d) == 0 || len(d)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(d)
	return err == nil
}

func emitResult(result verificationResult, jsonOutput bool) {
	if jsonOutput {
		payload, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		fmt.Println(string(payload))
		return
	}

	status := "FAIL"
	if result.Valid {
		status = "PASS"
	}
	fmt.Printf("%s %s: %s\n", status, result.Artifact, result.Path)
	keys := make([]string, 0, len(result.Checks))
	for key := range result.Checks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Printf("  %s: %s\n", key, result.Checks[key])
	}
}

// --- Bundle types and commands ---

type agentPassportBundle struct {
	Context    string                   `json:"@context"`
	Type       string                   `json:"type"`
	Version    string                   `json:"spec_version"`
	BundleID   string                   `json:"bundle_id"`
	ExportedAt string                   `json:"exported_at"`
	Platform   string                   `json:"platform"`
	Passport   json.RawMessage          `json:"passport"`
	Receipts   []json.RawMessage        `json:"receipts,omitempty"`
	Attestations []json.RawMessage      `json:"attestations,omitempty"`
	Reputation   *json.RawMessage       `json:"reputation_summary,omitempty"`
	Anchoring    []json.RawMessage      `json:"anchoring_proofs,omitempty"`
	Proof      *passport.Proof          `json:"proof,omitempty"`
}

func runBundleCommand(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: passport-cli bundle <verify|inspect> <bundle.json>")
		return 2
	}
	switch args[0] {
	case "verify":
		return runBundleVerify(args[1:])
	case "inspect":
		return runBundleInspect(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "usage: passport-cli bundle <verify|inspect> <bundle.json>")
		return 2
	}
}

func runBundleVerify(args []string) int {
	fs := flag.NewFlagSet("bundle verify", flag.ContinueOnError)
	publicKey := fs.String("public-key", "", "override verification key")
	jsonOutput := fs.Bool("json", false, "emit result as JSON")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: passport-cli bundle verify [--public-key value] [--json] <bundle.json>")
		return 2
	}

	result := verificationResult{Artifact: "bundle", Path: fs.Arg(0), Checks: map[string]string{}}
	result.Valid = true

	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		result.Valid = false
		result.Checks["file"] = err.Error()
		emitResult(result, *jsonOutput)
		return 1
	}

	var bundle agentPassportBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		result.Valid = false
		result.Checks["json"] = err.Error()
		emitResult(result, *jsonOutput)
		return 1
	}
	result.Checks["json"] = "ok"

	if bundle.Type != "AgentPassportBundle" {
		result.Valid = false
		result.Checks["schema"] = "type must be AgentPassportBundle"
	} else if bundle.BundleID == "" {
		result.Valid = false
		result.Checks["schema"] = "bundle_id is required"
	} else {
		result.Checks["schema"] = "ok"
	}

	// Verify bundle-level signature
	if bundle.Proof == nil {
		result.Valid = false
		result.Checks["bundle_signature"] = "missing proof"
	} else {
		pk, pkErr := resolvePublicKey("", *publicKey, bundle.Proof.VerificationMethod)
		if pkErr != nil {
			result.Valid = false
			result.Checks["bundle_signature"] = "key resolution: " + pkErr.Error()
		} else {
			sigHex, sigErr := normalizeSignatureValue(bundle.Proof.ProofValue)
			if sigErr != nil {
				result.Valid = false
				result.Checks["bundle_signature"] = "signature: " + sigErr.Error()
			} else {
				bundleCopy := bundle
				bundleCopy.Proof = nil
				canonical, _ := crypto.CanonicalizeJSON(bundleCopy)
				ok, verifyErr := crypto.Ed25519Verify(pk, canonical, sigHex)
				if verifyErr != nil {
					result.Valid = false
					result.Checks["bundle_signature"] = "verify error: " + verifyErr.Error()
				} else {
					result.Checks["bundle_signature"] = fmt.Sprintf("%t", ok)
					if !ok {
						result.Valid = false
					}
				}
			}
		}
	}

	// Verify embedded passport signature
	var p passport.AgentPassport
	if err := json.Unmarshal(bundle.Passport, &p); err != nil {
		result.Valid = false
		result.Checks["passport_signature"] = "parse error: " + err.Error()
	} else if p.Proof == nil {
		result.Valid = false
		result.Checks["passport_signature"] = "missing proof"
	} else {
		pk, pkErr := resolvePublicKey(p.Keys.Signing.PublicKey, "", p.Proof.VerificationMethod)
		if pkErr != nil {
			result.Valid = false
			result.Checks["passport_signature"] = "key resolution: " + pkErr.Error()
		} else {
			sigHex, sigErr := normalizeSignatureValue(p.Proof.ProofValue)
			if sigErr != nil {
				result.Valid = false
				result.Checks["passport_signature"] = "signature: " + sigErr.Error()
			} else {
				pCopy := p
				pCopy.Proof = nil
				canonical, _ := crypto.CanonicalizeJSON(pCopy)
				ok, verifyErr := crypto.Ed25519Verify(pk, canonical, sigHex)
				if verifyErr != nil {
					result.Valid = false
					result.Checks["passport_signature"] = "verify error: " + verifyErr.Error()
				} else {
					result.Checks["passport_signature"] = fmt.Sprintf("%t", ok)
					if !ok {
						result.Valid = false
					}
				}
			}
		}
	}

	emitResult(result, *jsonOutput)
	if result.Valid {
		return 0
	}
	return 1
}

func runBundleInspect(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: passport-cli bundle inspect <bundle.json>")
		return 2
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return 1
	}

	var bundle agentPassportBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return 1
	}

	// Extract agent DID from passport
	var p passport.AgentPassport
	agentDID := "(unknown)"
	if err := json.Unmarshal(bundle.Passport, &p); err == nil {
		agentDID = p.ID
	}

	fmt.Printf("Bundle: %s\n", bundle.BundleID)
	fmt.Printf("  Agent DID:      %s\n", agentDID)
	fmt.Printf("  Platform:       %s\n", bundle.Platform)
	fmt.Printf("  Exported At:    %s\n", bundle.ExportedAt)
	fmt.Printf("  Receipts:       %d\n", len(bundle.Receipts))
	fmt.Printf("  Attestations:   %d\n", len(bundle.Attestations))

	if bundle.Reputation != nil {
		fmt.Printf("  Reputation:     present\n")
	} else {
		fmt.Printf("  Reputation:     none\n")
	}

	if len(bundle.Anchoring) > 0 {
		fmt.Printf("  Anchoring:      %d proof(s)\n", len(bundle.Anchoring))
	} else {
		fmt.Printf("  Anchoring:      none\n")
	}

	hasSig := "no"
	if bundle.Proof != nil {
		hasSig = "yes"
	}
	fmt.Printf("  Signed:         %s\n", hasSig)

	return 0
}

func printUsage() {
	fmt.Println("passport-cli verify <passport.json>")
	fmt.Println("passport-cli receipt verify <receipt.json>")
	fmt.Println("passport-cli envelope validate <envelope.json>")
	fmt.Println("passport-cli bundle verify <bundle.json>")
	fmt.Println("passport-cli bundle inspect <bundle.json>")
}

func decodeBase58(input string) ([]byte, error) {
	if input == "" {
		return nil, errors.New("base58 input is empty")
	}

	result := make([]byte, 1)
	for i := range input {
		value, ok := base58Map[input[i]]
		if !ok {
			return nil, fmt.Errorf("invalid base58 character: %q", input[i])
		}
		carry := value
		for j := 0; j < len(result); j++ {
			total := int(result[j])*58 + carry
			result[j] = byte(total & 0xff)
			carry = total >> 8
		}
		for carry > 0 {
			result = append(result, byte(carry&0xff))
			carry >>= 8
		}
	}

	zeroPrefix := 0
	for zeroPrefix < len(input) && input[zeroPrefix] == '1' {
		zeroPrefix++
	}

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	if zeroPrefix == 0 {
		return result, nil
	}

	decoded := make([]byte, zeroPrefix+len(result))
	copy(decoded[zeroPrefix:], result)
	return decoded, nil
}

var base58Map = func() map[byte]int {
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	m := make(map[byte]int, len(alphabet))
	for i := 0; i < len(alphabet); i++ {
		m[alphabet[i]] = i
	}
	return m
}()
