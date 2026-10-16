package mdoc

import (
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// FuzzVerifySignedMSO exercises Verify's post-signature path — MSO
// decoding, the version/docType checks, digest matching, the
// ValidityInfo window, DeviceKey decoding and KeyAuthorizations —
// which FuzzUnmarshalIssuerSigned can't reach: a mutated IssuerSigned
// there almost never carries a valid IssuerAuth signature. Here the
// fuzzer controls the MSO's own CBOR bytes and the harness signs them
// itself, modelling a malicious or compromised issuer whose key the
// caller trusts. NameSpaces stay fixed so that mutations which keep
// valueDigests intact still reach the checks after checkDigests.
func FuzzVerifySignedMSO(f *testing.F) {
	const docType = "org.iso.18013.5.1.mDL"
	issuerKey, base, now := issueFuzzSeed(f, &KeyAuthorizations{
		DataElements: map[string][]string{"org.iso.18013.5.1": {"given_name"}},
	})
	protected, unprotected, payload, err := cose.DecodeUnverified(base.IssuerAuth)
	if err != nil {
		f.Fatalf("DecodeUnverified(IssuerAuth): %v", err)
	}
	var wrapped cbor.Tag
	if err := decMode.Unmarshal(payload, &wrapped); err != nil {
		f.Fatalf("unmarshal MSO tag 24: %v", err)
	}
	validMSO, ok := wrapped.Content.([]byte)
	if !ok {
		f.Fatalf("MSO tag 24 content is %T, want []byte", wrapped.Content)
	}

	f.Add(validMSO)
	f.Add([]byte{0xa0})
	f.Add(validMSO[:len(validMSO)-1])
	// The MSO-structure rules a signed MSO can still break (ISO/IEC
	// 18013-5 §12.3.4, §12.3.5).
	for _, mutate := range []func(*MobileSecurityObject){
		func(m *MobileSecurityObject) { m.Version = "2.0" },
		func(m *MobileSecurityObject) { m.DigestAlgorithm = "SHA-1" },
		func(m *MobileSecurityObject) { m.DigestAlgorithm = SHA384 },
		func(m *MobileSecurityObject) { delete(m.ValueDigests, "org.iso.18013.5.1") },
		func(m *MobileSecurityObject) { m.DocType = "org.example.other.1" },
	} {
		var m MobileSecurityObject
		if err := decMode.Unmarshal(validMSO, &m); err != nil {
			f.Fatalf("unmarshal MSO: %v", err)
		}
		mutate(&m)
		seed, err := encMode.Marshal(m)
		if err != nil {
			f.Fatalf("marshal MSO: %v", err)
		}
		f.Add(seed)
	}

	deviceNameSpaces := map[string]map[string]interface{}{
		"org.iso.18013.5.1": {"given_name": "Alice"},
	}

	f.Fuzz(func(t *testing.T, mso []byte) {
		msoBytes, err := encMode.Marshal(cbor.Tag{Number: tag24, Content: mso})
		if err != nil {
			return
		}
		issuerAuth, err := cose.Sign(cose.ES256, issuerKey, protected, unprotected, msoBytes, []byte{})
		if err != nil {
			t.Fatalf("cose.Sign: %v", err)
		}
		signed := IssuerSigned{NameSpaces: base.NameSpaces, IssuerAuth: issuerAuth}

		verified, err := Verify(signed, docType, &issuerKey.PublicKey, cose.ES256, VerifyOptions{
			Now: func() time.Time { return now },
		})
		if err != nil {
			return
		}
		if verified.DeviceKey == nil {
			t.Fatal("Verify succeeded with a nil DeviceKey")
		}
		_ = CheckKeyAuthorizations(deviceNameSpaces, verified.KeyAuthorizations)
	})
}
