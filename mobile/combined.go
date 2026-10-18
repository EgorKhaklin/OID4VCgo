package mobile

import "github.com/idfoundry/oid4vcgo/proximity"

// StartCombinedProximityPresentation prepares independent QR and NFC offers.
// Omit QR when Bluetooth permission is unavailable and nfcData is true.
// NFC-only uses command/response limits 255/256. All existing APIs are unchanged.
func (w *Wallet) StartCombinedProximityPresentation(modesJSON string, negotiated, nfcData, omitQR bool) (*ProximityPresentation, error) {
	modes, err := parseProximityModes(modesJSON)
	if err != nil {
		return nil, err
	}
	options := proximity.CombinedOptions{Negotiated: negotiated, OmitQR: omitQR}
	if nfcData {
		options.NFCData = &proximity.NFCDataParameters{MaxCommand: 255, MaxResponse: 256}
	}
	p, err := w.w.StartCombinedProximityPresentation(options, modes...)
	if err != nil {
		return nil, classify(err)
	}
	return &ProximityPresentation{p: p}, nil
}

// IsCombined reports whether native code must claim an engagement first.
func (p *ProximityPresentation) IsCombined() bool { return p.p.IsCombined() }

// SelectEngagement claims NFC when true, QR otherwise. The loser cannot attach.
func (p *ProximityPresentation) SelectEngagement(nfc bool) error {
	if err := p.p.SelectEngagement(nfc); err != nil {
		return newError(CodeWrongStep, err)
	}
	return nil
}

// SelectedEngagement returns "", "qr", "nfc_ble" or "nfc_data".
func (p *ProximityPresentation) SelectedEngagement() string { return p.p.SelectedEngagement() }
