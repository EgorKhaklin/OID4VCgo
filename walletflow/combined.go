package walletflow

import (
	"fmt"
	"github.com/idfoundry/oid4vcgo/proximity"
)

// StartCombinedProximityPresentation owns QR and NFC offers with one consent
// flow. Native transport code must call SelectEngagement before HandleMessage.
func (w *Wallet) StartCombinedProximityPresentation(options proximity.CombinedOptions, modes ...proximity.BLEMode) (*ProximityPresentation, error) {
	var opts []proximity.DeviceOption
	if len(modes) > 0 {
		opts = append(opts, proximity.WithBLEModes(modes...))
	}
	c, err := proximity.NewCombinedDeviceSession(w.deps.Random, options, opts...)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	s := c.QROffer()
	if s == nil {
		s = c.NFCOffer()
	}
	return &ProximityPresentation{w: w, s: s, combined: c, byID: map[string]StoredCredential{}}, nil
}

// IsCombined reports whether explicit engagement selection is required.
func (p *ProximityPresentation) IsCombined() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.combined != nil
}

// SelectEngagement atomically claims QR (false) or NFC (true). A competing
// selection fails without changing the selected key, handover or consent flow.
func (p *ProximityPresentation) SelectEngagement(nfc bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.combined == nil || p.state != proximityWaiting {
		return fmt.Errorf("walletflow: no engagement pending: %w", proximity.ErrSessionClosed)
	}
	s, err := p.combined.Select(nfc)
	if err != nil {
		return err
	}
	p.s = s
	return nil
}

// SelectedEngagement is empty until selection, then qr, nfc_ble or nfc_data.
func (p *ProximityPresentation) SelectedEngagement() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.combined == nil {
		return ""
	}
	return p.combined.SelectedEngagement()
}
