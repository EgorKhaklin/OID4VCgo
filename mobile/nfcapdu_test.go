//go:build mobiletest

package mobile

import (
	"fmt"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// driveNFC runs x against holder, as the native reader and holder do.
// onMessage answers a session message the holder receives.
func driveNFC(t *testing.T, x *NFCExchange, holder *NFCHolder, onMessage func([]byte) []byte) []byte {
	t.Helper()
	defer x.Close()
	for c := x.Command(); c != nil; c = x.Command() {
		step := holder.Process(c)
		resp := step.Response
		if step.Message != nil {
			answer, err := holder.Respond(onMessage(step.Message))
			if err != nil {
				t.Fatal(err)
			}
			resp = answer.Response
		}
		if err := x.Next(resp); err != nil {
			t.Fatal(err)
		}
	}
	out, err := x.Result()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestNFCHolderEndToEnd presents an mdoc over NFC with every byte of the
// NFC exchange done by NFCHolder and NFCExchange.
func TestNFCHolderEndToEnd(t *testing.T) {
	reader := newTestReader(t)
	h := newHarness(t, false).withReaderRoots(t, reader)
	var credentialID string
	for _, credential := range h.receive(t) {
		if credential.Format == "mso_mdoc" {
			credentialID = credential.ID
		}
	}
	cfg, ks := readerConfig(t, h, &reader, nil)
	rd, err := NewProximityReader(cfg, ks)
	if err != nil {
		t.Fatal(err)
	}
	for _, negotiated := range []bool{false, true} {
		for _, data := range []bool{false, true} {
			t.Run(fmt.Sprintf("negotiated=%t/data=%t", negotiated, data), func(t *testing.T) {
				var presentation *ProximityPresentation
				var hr []byte
				switch {
				case negotiated && data:
					presentation, err = h.w.StartNFCNegotiatedDataProximityPresentation(255, 256)
					if err == nil {
						hr, err = NewNFCHandoverRequestWithNFCData(`["peripheral_server"]`, 255, 256)
					}
				case data:
					presentation, err = h.w.StartNFCDataProximityPresentation(255, 256)
				case negotiated:
					presentation, err = h.w.StartNFCNegotiatedProximityPresentationWithModes(`["peripheral_server"]`)
					if err == nil {
						hr, err = NewNFCHandoverRequest(`["peripheral_server"]`)
					}
				default:
					presentation, err = h.w.StartNFCProximityPresentationWithModes(`["peripheral_server"]`)
				}
				if err != nil {
					t.Fatal(err)
				}
				holder, err := presentation.NFCHolder(negotiated, data)
				if err != nil {
					t.Fatal(err)
				}
				read := NewNFCHandoverRead(261, hr)
				hs := driveNFC(t, read, holder, nil)
				if read.Negotiated() != negotiated {
					t.Fatalf("Negotiated = %v", read.Negotiated())
				}
				var session *ProximityReaderSession
				switch {
				case negotiated && data:
					session, err = rd.StartFromNegotiatedNFCDataHandover(hs, hr)
				case data:
					session, err = rd.StartFromNFCDataHandover(hs)
				case negotiated:
					session, err = rd.StartFromNegotiatedHandover(hs, hr)
				default:
					session, err = rd.StartFromHandover(hs)
				}
				if err != nil {
					t.Fatal(err)
				}
				if !data {
					return
				}
				if err := CheckNFCDataApplicationSelected(holder.Process(NFCSelectDataApplication()).Response); err != nil {
					t.Fatal(err)
				}
				request, err := session.Request(walletflowtest.DocType, `{"org.example.test.1":["family_name"]}`)
				if err != nil {
					t.Fatal(err)
				}
				p := decode[struct {
					MaxCommand  int `json:"max_command"`
					MaxResponse int `json:"max_response"`
				}](t, must(ParseNfcDataParameters(hs)))
				answer := driveNFC(t, NewNFCTransact(261, p.MaxCommand, p.MaxResponse, sent(t, decode[struct{ Send string }](t, request).Send)), holder, func(message []byte) []byte {
					if event := decode[proximityEvent](t, presentation.HandleMessage(NewOperation(0), message)); event.Event != "request" {
						t.Fatalf("request: %+v", event)
					}
					out, err := presentation.Respond(NewOperation(0), 0, credentialID, `[["org.example.test.1","family_name"]]`)
					if err != nil {
						t.Fatal(err)
					}
					return sent(t, decode[struct{ Send string }](t, out).Send)
				})
				verified := decode[readerEvent](t, session.HandleMessage(answer))
				if verified.Event != "verified" || verified.Verified.Claims[walletflowtest.NameSpace]["family_name"] != walletflowtest.FamilyName {
					t.Fatalf("verification: %+v", verified)
				}
			})
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
