package proximity

import (
	"fmt"
	"io"
)

// CombinedOptions configures independent QR and NFC offers. NFCData selects
// classic NFC retrieval instead of BLE; nil selects BLE. OmitQR permits an
// NFC-only presentation when Bluetooth permission is unavailable.
type CombinedOptions struct {
	Negotiated bool
	NFCData    *NFCDataParameters
	OmitQR     bool
}

// CombinedDeviceSession owns two independent ephemeral keys and transcripts.
// Like DeviceSession, callers must serialize its methods and access to its
// offers. Platform code selects QR after BLE connection, or NFC on application
// selection, before handing any session message to the selected offer.
type CombinedDeviceSession struct {
	qr, nfc  *DeviceSession
	selected string
	closed   bool
}

// NewCombinedDeviceSession prepares both offers without performing radio I/O.
// Separate keys avoid relying on key reuse across engagement mechanisms.
func NewCombinedDeviceSession(random io.Reader, options CombinedOptions, opts ...DeviceOption) (*CombinedDeviceSession, error) {
	s := &CombinedDeviceSession{}
	var err error
	if !options.OmitQR {
		s.qr, err = NewDeviceSession(random, opts...)
		if err != nil {
			return nil, err
		}
	}
	switch {
	case options.NFCData != nil && options.Negotiated:
		s.nfc, err = NewNFCNegotiatedDataDeviceSession(random, *options.NFCData)
	case options.NFCData != nil:
		s.nfc, err = NewNFCDataDeviceSession(random, *options.NFCData)
	case options.Negotiated:
		s.nfc, err = NewNFCNegotiatedDeviceSession(random, opts...)
	default:
		s.nfc, err = NewNFCDeviceSession(random, opts...)
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// QROffer returns the QR session, or nil if omitted. Its transport starts now.
func (s *CombinedDeviceSession) QROffer() *DeviceSession { return s.qr }

// NFCOffer returns the NFC session. Its BLE transport must wait for full Hs read.
func (s *CombinedDeviceSession) NFCOffer() *DeviceSession { return s.nfc }

// SelectedEngagement is empty until selection, then "qr", "nfc_ble" or "nfc_data".
func (s *CombinedDeviceSession) SelectedEngagement() string { return s.selected }

// Select irreversibly claims an offer, closing the loser. Repeating the winning
// selection is idempotent. Selecting a loser or a closed session fails.
func (s *CombinedDeviceSession) Select(nfc bool) (*DeviceSession, error) {
	path, winner, loser := "qr", s.qr, s.nfc
	if nfc {
		path, winner, loser = "nfc_ble", s.nfc, s.qr
		if s.nfc.nfcDataParameters != nil {
			path = "nfc_data"
		}
	}
	if s.closed || winner == nil || (s.selected != "" && s.selected != path) {
		return nil, fmt.Errorf("proximity: engagement unavailable: %w", ErrSessionClosed)
	}
	s.selected = path
	if loser != nil {
		loser.Termination()
	}
	return winner, nil
}

// Close withdraws both offers. No subsequent selection may revive them.
func (s *CombinedDeviceSession) Close() {
	s.closed = true
	if s.qr != nil {
		s.qr.Termination()
	}
	if s.nfc != nil {
		s.nfc.Termination()
	}
}
