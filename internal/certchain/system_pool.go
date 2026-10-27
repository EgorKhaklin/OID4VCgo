package certchain

import (
	"crypto/x509"
	"runtime"
	"sync"
)

// systemPool is x509.SystemCertPool's result, loaded once: it's
// only read here, and loading (or cloning) it on every check would cost
// each verification that makes one.
var systemPool = sync.OnceValues(x509.SystemCertPool)

// systemSubjects are the raw subjects of the certificates the system
// pool holds as certificates (on Linux and the other Unix systems; on
// macOS and Windows it holds none, and defers to the platform
// verifier).
var systemSubjects = sync.OnceValue(func() map[string]bool {
	system, err := systemPool()
	if err != nil {
		return nil
	}
	subjects := map[string]bool{}
	for _, subject := range system.Subjects() { //nolint:staticcheck // the subjects of the certificates the pool holds are what's compared; a platform verifier's roots aren't among them
		subjects[string(subject)] = true
	}
	return subjects
})

// platformVerified reports whether this platform's system pool defers
// to the platform verifier rather than holding certificates.
func platformVerified() bool {
	switch runtime.GOOS {
	case "darwin", "ios", "windows":
		return true
	}
	return false
}

// IsSystemPool reports whether pool holds the platform's system root
// pool (x509.SystemCertPool), which anchors the Web PKI: as a credential
// role's trust anchors it would accept a certificate any public CA
// issues — a TLS server's, say.
//
// On Linux and the other Unix systems, where the system pool is a set
// of certificates, a pool holding a certificate for each of their
// subjects is reported, so one built from the system pool by adding
// certificates to it (AppendCertsFromPEM, AddCert) is too. On macOS and
// Windows the system pool defers to the platform verifier and holds no
// certificates to compare: only an unmodified copy of it is reported,
// and one built from it by adding certificates isn't detected.
func IsSystemPool(pool *x509.CertPool) bool {
	if pool == nil {
		return false
	}
	system, err := systemPool()
	if err != nil {
		return false
	}
	if platformVerified() {
		return pool.Equal(system)
	}
	return holdsAll(pool, systemSubjects())
}

// holdsAll reports whether pool holds a certificate with each of the
// raw subjects want, a non-empty set.
func holdsAll(pool *x509.CertPool, want map[string]bool) bool {
	if len(want) == 0 {
		return false
	}
	have := map[string]bool{}
	for _, subject := range pool.Subjects() { //nolint:staticcheck // see systemSubjects
		have[string(subject)] = true
	}
	if len(have) < len(want) {
		return false
	}
	for subject := range want {
		if !have[subject] {
			return false
		}
	}
	return true
}
