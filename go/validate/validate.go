// Package validate provides JSON Schema validation for APS documents.
package validate

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed schemas/*.json
var schemaFS embed.FS

var (
	passportSchema *jsonschema.Schema
	receiptSchema  *jsonschema.Schema
	envelopeSchema *jsonschema.Schema
	dnaSchema      *jsonschema.Schema
)

func init() {
	passportSchema = mustCompile("schemas/agent-passport.schema.json")
	receiptSchema = mustCompile("schemas/work-receipt.schema.json")
	envelopeSchema = mustCompile("schemas/security-envelope.schema.json")
	dnaSchema = mustCompile("schemas/dna.schema.json")
}

func mustCompile(path string) *jsonschema.Schema {
	data, err := schemaFS.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("read schema %s: %v", path, err))
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource(path, strings.NewReader(string(data))); err != nil {
		panic(fmt.Sprintf("add resource %s: %v", path, err))
	}
	schema, err := compiler.Compile(path)
	if err != nil {
		panic(fmt.Sprintf("compile schema %s: %v", path, err))
	}
	return schema
}

func validateAgainst(schema *jsonschema.Schema, data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return schema.Validate(v)
}

// ValidatePassport validates JSON bytes against agent-passport.schema.json.
func ValidatePassport(data []byte) error {
	return validateAgainst(passportSchema, data)
}

// ValidateReceipt validates JSON bytes against work-receipt.schema.json.
func ValidateReceipt(data []byte) error {
	return validateAgainst(receiptSchema, data)
}

// ValidateEnvelope validates JSON bytes against security-envelope.schema.json.
func ValidateEnvelope(data []byte) error {
	return validateAgainst(envelopeSchema, data)
}

// ValidateDNA validates JSON bytes against dna.schema.json.
func ValidateDNA(data []byte) error {
	return validateAgainst(dnaSchema, data)
}
