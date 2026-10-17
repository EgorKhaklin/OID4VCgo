package walletflow

import (
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/oid4vcgo"
)

// The SessionStore walletflow gives fapigo/client, over its
// AuthorizationStore, meets FAPIgo's own contract: single-use, atomic
// consume included.
func TestSessionStoreContract(t *testing.T) {
	storage.TestSessionStoreContract(t, func() storage.SessionStore {
		w, err := New(Config{Development: true}, Dependencies{Keys: NewMemoryKeyStore(), Credentials: NewMemoryCredentialStore()})
		if err != nil {
			t.Fatal(err)
		}
		return &sessionStore{w: w}
	})
}

// A configuration the wallet couldn't verify on arrival is refused
// before the holder authenticates: an unknown format, or one naming no
// vct or doctype.
func TestCheckReceivable(t *testing.T) {
	for _, tc := range []struct {
		conf oid4vci.CredentialConfigurationMetadata
		ok   bool
	}{
		{oid4vci.CredentialConfigurationMetadata{Format: "dc+sd-jwt", VCT: "urn:x"}, true},
		{oid4vci.CredentialConfigurationMetadata{Format: "mso_mdoc", DocType: "org.iso.18013.5.1.mDL"}, true},
		{oid4vci.CredentialConfigurationMetadata{Format: "jwt_vc_json"}, false},
		{oid4vci.CredentialConfigurationMetadata{Format: "dc+sd-jwt"}, false},
		{oid4vci.CredentialConfigurationMetadata{Format: "mso_mdoc"}, false},
	} {
		err := checkReceivable(tc.conf)
		if tc.ok != (err == nil) || (err != nil && !errors.Is(err, ErrFormatUnsupported)) {
			t.Errorf("%+v: %v", tc.conf, err)
		}
	}
}
