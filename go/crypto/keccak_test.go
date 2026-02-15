package crypto

import (
	"testing"
)

func TestKeccak256_Empty(t *testing.T) {
	result := Keccak256([]byte(""))
	expected := "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestKeccak256_Hello(t *testing.T) {
	result := Keccak256([]byte("hello"))
	if len(result) != 66 {
		t.Errorf("unexpected hash length: %d", len(result))
	}
	// Known: keccak256("hello") = 0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
	expected := "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestKeccak256Bytes(t *testing.T) {
	result := Keccak256Bytes([]byte("hello"))
	if result[0] == 0 && result[1] == 0 {
		t.Error("expected non-zero hash")
	}
}

func TestSnapshotHash_Deterministic(t *testing.T) {
	input := map[string]interface{}{"a": 1, "b": 2}
	h1, err := SnapshotHash(input)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := SnapshotHash(input)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Error("non-deterministic")
	}
}

func TestHashExcludingFields(t *testing.T) {
	type doc struct {
		A string `json:"a"`
		B string `json:"b"`
		C string `json:"c"`
	}
	d := doc{A: "1", B: "2", C: "3"}
	h1, err := HashExcludingFields(d, "c")
	if err != nil {
		t.Fatal(err)
	}
	// Should equal hash of {"a":"1","b":"2"}
	h2, err := SnapshotHash(map[string]interface{}{"a": "1", "b": "2"})
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("got %s, want %s", h1, h2)
	}
}
