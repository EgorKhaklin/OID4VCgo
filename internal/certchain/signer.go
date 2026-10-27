package certchain

import (
	"crypto"
	"crypto/x509"
	"errors"
)

// SignerChainDERs checks chain starts with signer's certificate and is
// the chain HAIP 1.0 §6.1 has a status list signer present
// (CheckPresentedChain), and returns its DER encodings. Its errors carry
// no package prefix but CheckPresentedChain's, for the caller to add
// its own.
func SignerChainDERs(signer crypto.Signer, chain []*x509.Certificate) ([][]byte, error) {
	if len(chain) == 0 {
		return nil, errors.New("a certificate chain is required")
	}
	pub, ok := chain[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(signer.Public()) {
		return nil, errors.New("the chain's first certificate isn't the signer's")
	}
	if err := CheckPresentedChain(chain[0], chain[1:]); err != nil {
		return nil, err
	}
	ders := make([][]byte, len(chain))
	for i, c := range chain {
		ders[i] = c.Raw
	}
	return ders, nil
}

// BothPolicies is a leaf policy passing only what first and second
// both pass, first checked first; a nil one passes everything.
func BothPolicies(first, second func(*x509.Certificate, [][]*x509.Certificate) error) func(*x509.Certificate, [][]*x509.Certificate) error {
	if first == nil {
		return second
	}
	if second == nil {
		return first
	}
	return func(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
		if err := first(leaf, chains); err != nil {
			return err
		}
		return second(leaf, chains)
	}
}
