package did

import (
	"errors"
	"math/big"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// DecodeBase58BTC decodes a base58btc encoded string (without the 'z' multibase prefix).
func DecodeBase58BTC(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, errors.New("empty base58 string")
	}

	bigInt := new(big.Int)
	base := big.NewInt(58)

	for _, c := range s {
		idx := -1
		for i, a := range base58Alphabet {
			if a == c {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, errors.New("invalid base58 character")
		}
		bigInt.Mul(bigInt, base)
		bigInt.Add(bigInt, big.NewInt(int64(idx)))
	}

	// Count leading '1's (zeros)
	leadingZeros := 0
	for _, c := range s {
		if c == '1' {
			leadingZeros++
		} else {
			break
		}
	}

	b := bigInt.Bytes()
	result := make([]byte, leadingZeros+len(b))
	copy(result[leadingZeros:], b)
	return result, nil
}

// EncodeBase58BTC encodes bytes to base58btc (without multibase prefix).
func EncodeBase58BTC(data []byte) string {
	bigInt := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	mod := new(big.Int)
	var encoded []byte

	for bigInt.Sign() > 0 {
		bigInt.DivMod(bigInt, base, mod)
		encoded = append([]byte{base58Alphabet[mod.Int64()]}, encoded...)
	}

	for _, b := range data {
		if b == 0 {
			encoded = append([]byte{'1'}, encoded...)
		} else {
			break
		}
	}

	return string(encoded)
}
