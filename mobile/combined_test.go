//go:build mobiletest

package mobile

import (
	"fmt"
	"sync"
	"testing"

	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

func TestCombinedBindings(t *testing.T) {
	h := newHarness(t, false)
	h.receive(t)
	for _, negotiated := range []bool{false, true} {
		for _, data := range []bool{false, true} {
			for _, nfc := range []bool{false, true} {
				t.Run(fmt.Sprintf("negotiated=%t/data=%t/nfc=%t", negotiated, data, nfc), func(t *testing.T) {
					p, err := h.w.StartCombinedProximityPresentation(`["peripheral_server"]`, negotiated, data, false)
					if err != nil {
						t.Fatal(err)
					}
					eng := decode[struct {
						QRCode string `json:"qr_code"`
					}](t, p.Engagement())
					if !p.IsCombined() || eng.QRCode == "" || p.SelectedEngagement() != "" {
						t.Fatal("missing offers")
					}
					if err := p.SelectEngagement(nfc); err != nil {
						t.Fatal(err)
					}
					if err := p.SelectEngagement(!nfc); err == nil {
						t.Fatal("loser selected")
					}
					var r *proximity.ReaderSession
					if !nfc {
						r, err = proximity.NewReaderSession(eng.QRCode)
					} else {
						hs := p.HandoverSelect()
						var hr []byte
						if negotiated {
							if data {
								hr, err = NewNFCHandoverRequestWithNFCData(`["peripheral_server"]`, 255, 256)
							} else {
								hr, err = NewNFCHandoverRequest(`["peripheral_server"]`)
							}
							if err != nil {
								t.Fatal(err)
							}
							hs, err = p.HandleHandoverRequest(hr)
							if err != nil {
								t.Fatal(err)
							}
						}
						switch {
						case data && negotiated:
							r, err = proximity.NewNFCNegotiatedDataReaderSession(hs, hr)
						case data:
							r, err = proximity.NewNFCDataReaderSession(hs)
						case negotiated:
							r, err = proximity.NewNFCNegotiatedReaderSession(hs, hr)
						default:
							r, err = proximity.NewNFCReaderSession(hs)
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					message, err := r.Establishment(walletflowtest.DocType, map[string][]string{walletflowtest.NameSpace: {"family_name"}})
					if err != nil {
						t.Fatal(err)
					}
					event := decode[proximityEvent](t, p.HandleMessage(NewOperation(0), message))
					if event.Event != "request" {
						t.Fatalf("request: %+v", event)
					}
					p.Terminate()
					if err := p.SelectEngagement(nfc); err == nil {
						t.Fatal("closed owner revived")
					}
				})
			}
		}
	}
}

func TestCombinedConcurrentSelection(t *testing.T) {
	h := newHarness(t, false)
	for range 20 {
		p, err := h.w.StartCombinedProximityPresentation(`["peripheral_server"]`, false, true, false)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		results := make(chan bool, 2)
		for _, nfc := range []bool{false, true} {
			wg.Go(func() { results <- p.SelectEngagement(nfc) == nil })
		}
		wg.Wait()
		if a, b := <-results, <-results; a == b {
			t.Fatal("expected exactly one winner")
		}
		p.Terminate()
	}
	p, err := h.w.StartCombinedProximityPresentation(`["peripheral_server"]`, false, true, true)
	if err != nil {
		t.Fatal(err)
	}
	eng := decode[struct {
		QRCode string `json:"qr_code"`
	}](t, p.Engagement())
	if eng.QRCode != "" || p.SelectEngagement(false) == nil || p.SelectEngagement(true) != nil {
		t.Fatal("NFC-only fallback failed")
	}
	p.Terminate()
}

func TestCombinedOmittedQRDoesNotExposeNFCCarrierEarly(t *testing.T) {
	h := newHarness(t, false)
	for _, data := range []bool{false, true} {
		p, err := h.w.StartCombinedProximityPresentation(`["peripheral_server"]`, false, data, true)
		if err != nil {
			t.Fatal(err)
		}
		eng := decode[struct {
			QRCode   string        `json:"qr_code"`
			BLEModes []bleModeJSON `json:"ble_modes"`
		}](t, p.Engagement())
		if eng.QRCode != "" || len(eng.BLEModes) != 0 {
			t.Fatal("omitted QR exposed NFC carrier before selection")
		}
		if err := p.SelectEngagement(true); err != nil {
			t.Fatal(err)
		}
		selected := decode[struct {
			BLEModes []bleModeJSON `json:"ble_modes"`
		}](t, p.Engagement())
		if !data && len(selected.BLEModes) != 1 {
			t.Fatal("selected NFC BLE carrier missing")
		}
		p.Terminate()
	}
}
