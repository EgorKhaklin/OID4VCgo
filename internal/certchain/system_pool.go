package certchain

import "crypto/x509"

// IsSystemPool reports whether pool is the platform's system root pool
// (x509.SystemCertPool), which anchors the Web PKI: as a credential
// role's trust anchors it would accept a certificate any public CA
// issues — a TLS server's, say. One built by adding certificates to it
// isn't reported.
func IsSystemPool(pool *x509.CertPool) bool {
	if pool == nil {
		return false
	}
	system, err := x509.SystemCertPool()
	return err == nil && pool.Equal(system)
}
