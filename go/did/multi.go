package did

import "fmt"

// MultiResolver dispatches DID resolution to method-specific resolvers.
type MultiResolver struct {
	resolvers map[string]Resolver
}

func NewMultiResolver(resolvers ...Resolver) *MultiResolver {
	m := &MultiResolver{resolvers: make(map[string]Resolver)}
	for _, r := range resolvers {
		m.resolvers[r.Method()] = r
	}
	return m
}

func DefaultResolver() *MultiResolver {
	return NewMultiResolver(NewDIDKeyResolver(), NewDIDWebResolver())
}

func (m *MultiResolver) Resolve(did string) (*DIDDocument, error) {
	method, _, err := ParseDID(did)
	if err != nil {
		return nil, err
	}
	r, ok := m.resolvers[method]
	if !ok {
		return nil, fmt.Errorf("unsupported DID method: %s", method)
	}
	return r.Resolve(did)
}

func (m *MultiResolver) Method() string { return "multi" }
