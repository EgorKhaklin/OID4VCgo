package verifier

import (
	"context"
	"crypto"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
)

// loggingResolver wraps another resolver, as a logging or caching one
// would.
type loggingResolver struct{ inner MdocIssuerKeyResolver }

func (l loggingResolver) ResolveMdocIssuerKey(ctx context.Context, x5chain [][]byte, docType string) (crypto.PublicKey, oid4vci.COSEAlg, error) {
	return l.inner.ResolveMdocIssuerKey(ctx, x5chain, docType)
}

func (l loggingResolver) Unwrap() MdocIssuerKeyResolver { return l.inner }

// keyOnlyResolver authenticates a key but verifies no chain.
type keyOnlyResolver struct{}

func (keyOnlyResolver) ResolveMdocIssuerKey(context.Context, [][]byte, string) (crypto.PublicKey, oid4vci.COSEAlg, error) {
	return nil, 0, nil
}

// A wrapped chain resolver still gets the document signer checks,
// through Unwrap; one that verifies no chain doesn't, and production
// refuses it.
func TestMdocChainResolver(t *testing.T) {
	inner := X5ChainIssuerKeyResolver{}
	if got, ok := mdocChainResolver(loggingResolver{loggingResolver{inner}}); !ok || got == nil {
		t.Error("a twice-wrapped X5ChainIssuerKeyResolver wasn't found")
	}
	if _, ok := mdocChainResolver(keyOnlyResolver{}); ok {
		t.Error("a key-only resolver was taken for a chain resolver")
	}
	if _, ok := mdocChainResolver(loggingResolver{keyOnlyResolver{}}); ok {
		t.Error("a wrapped key-only resolver was taken for a chain resolver")
	}
}
