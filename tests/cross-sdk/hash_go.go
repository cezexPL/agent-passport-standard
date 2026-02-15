package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/agent-passport/standard-go/crypto"
)

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	canonical, err := crypto.CanonicalizeJSON(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(crypto.Keccak256(canonical))
}
