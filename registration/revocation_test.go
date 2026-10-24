package registration_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/registration"
)

// Registrars.Revocation refuses a registration whose registrar
// certificate is revoked.
func TestRegistrars_Revocation(t *testing.T) {
	reg := newRegistrar(t)
	token, err := registration.Issue(shop(), reg.key, reg.chain)
	if err != nil {
		t.Fatal(err)
	}
	testcert.RunRevocationCases(t, reg.ca, reg.caKey, reg.chain[0], func(t *testing.T, revocation certrevocation.Checker) error {
		_, err := registration.Registrars{Roots: reg.roots, Revocation: revocation}.Verify(context.Background(), token, clientID, time.Now())
		return err
	})
	if _, err := (registration.Registrars{Roots: reg.roots, Revocation: certrevocation.CRLs{}}).Verify(context.Background(), token, clientID, time.Now()); err == nil {
		t.Error("CRLs without Lists accepted")
	}
}
