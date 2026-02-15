// Package crypto provides cryptographic primitives for the Agent Passport Standard v0.1.
package crypto

import (
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalizeJSON produces deterministic JSON output with sorted keys (RFC 8785-like).
func CanonicalizeJSON(v interface{}) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	var generic interface{}
	if err := json.Unmarshal(data, &generic); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	sorted := sortValue(generic)
	return json.Marshal(sorted)
}

func sortValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		return newSortedMap(val)
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = sortValue(item)
		}
		return result
	default:
		return v
	}
}

type sortedMap struct {
	keys   []string
	values map[string]interface{}
}

func (s sortedMap) MarshalJSON() ([]byte, error) {
	buf := []byte{'{'}
	for i, k := range s.keys {
		if i > 0 {
			buf = append(buf, ',')
		}
		key, _ := json.Marshal(k)
		val, err := json.Marshal(s.values[k])
		if err != nil {
			return nil, err
		}
		buf = append(buf, key...)
		buf = append(buf, ':')
		buf = append(buf, val...)
	}
	buf = append(buf, '}')
	return buf, nil
}

func newSortedMap(m map[string]interface{}) sortedMap {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	values := make(map[string]interface{}, len(m))
	for k, v := range m {
		values[k] = sortValue(v)
	}
	return sortedMap{keys: keys, values: values}
}
