package crypto

import (
	"testing"
)

func TestCanonicalizeJSON_SortedKeys(t *testing.T) {
	input := map[string]interface{}{
		"z_key": "last",
		"a_key": "first",
		"m_key": map[string]interface{}{
			"nested_z": 2,
			"nested_a": 1,
		},
	}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := `{"a_key":"first","m_key":{"nested_a":1,"nested_z":2},"z_key":"last"}`
	if string(result) != expected {
		t.Errorf("got %s, want %s", string(result), expected)
	}
}

func TestCanonicalizeJSON_Deterministic(t *testing.T) {
	input := map[string]interface{}{
		"bot_id":  "abc-123",
		"version": 1,
		"skills":  []interface{}{"go", "rust"},
	}

	h1, err := SnapshotHash(input)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := SnapshotHash(input)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("non-deterministic: %s != %s", h1, h2)
	}
}

func TestCanonicalizeJSON_Array(t *testing.T) {
	input := []interface{}{
		map[string]interface{}{"b": 2, "a": 1},
		map[string]interface{}{"d": 4, "c": 3},
	}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `[{"a":1,"b":2},{"c":3,"d":4}]`
	if string(result) != expected {
		t.Errorf("got %s, want %s", string(result), expected)
	}
}

func TestCanonicalizeJSON_EmptyObject(t *testing.T) {
	result, err := CanonicalizeJSON(map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != "{}" {
		t.Errorf("got %s, want {}", string(result))
	}
}
