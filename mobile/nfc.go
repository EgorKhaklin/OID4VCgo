package mobile

import (
	"errors"
	"github.com/idfoundry/oid4vcgo/proximity"
)

// StartNFCDataProximityPresentation prepares static NFC engagement and
// classic NFC-only retrieval with the advertised APDU data-field limits.
func (w *Wallet) StartNFCDataProximityPresentation(maxCommand, maxResponse int) (*ProximityPresentation, error) {
	p, err := w.w.StartNFCDataProximityPresentation(proximity.NFCDataParameters{MaxCommand: maxCommand, MaxResponse: maxResponse})
	if err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return &ProximityPresentation{p: p}, nil
}

// StartNFCNegotiatedDataProximityPresentation prepares TNEP and classic NFC-only retrieval.
func (w *Wallet) StartNFCNegotiatedDataProximityPresentation(maxCommand, maxResponse int) (*ProximityPresentation, error) {
	p, err := w.w.StartNFCNegotiatedDataProximityPresentation(proximity.NFCDataParameters{MaxCommand: maxCommand, MaxResponse: maxResponse})
	if err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return &ProximityPresentation{p: p}, nil
}

// NewNFCHandoverRequestWithNFCData offers BLE modes and a classic NFC carrier.
func NewNFCHandoverRequestWithNFCData(modesJSON string, maxCommand, maxResponse int) ([]byte, error) {
	modes, err := parseProximityModes(modesJSON)
	if err != nil {
		return nil, err
	}
	hr, err := proximity.NewNFCHandoverRequestWithNFCData(nil, proximity.NFCDataParameters{MaxCommand: maxCommand, MaxResponse: maxResponse}, modes...)
	if err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return hr, nil
}

// StartFromNegotiatedNFCDataHandover validates negotiated NFC selection and
// binds the exact Hs/Hr messages using the reader's configured trust policy.
func (r *ProximityReader) StartFromNegotiatedNFCDataHandover(hs, hr []byte) (*ProximityReaderSession, error) {
	s, err := proximity.NewNFCNegotiatedDataReaderSession(hs, hr, r.opts...)
	if err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return &ProximityReaderSession{r: r, s: s}, nil
}

// ParseNfcDataParameters validates a static NFC data Hs and returns
// {"abi", "max_command", "max_response"}, excluding APDU headers/status.
func ParseNfcDataParameters(hs []byte) (string, error) {
	p, err := proximity.ParseNFCDataHandover(hs)
	if err != nil {
		return "", newError(CodeInvalidInput, err)
	}
	return marshal(struct {
		result
		MaxCommand  int `json:"max_command"`
		MaxResponse int `json:"max_response"`
	}{result{ABIVersion}, p.MaxCommand, p.MaxResponse})
}

// StartFromNFCDataHandover starts a classic NFC-only reader using the
// reader's configured authentication and issuer trust policy.
func (r *ProximityReader) StartFromNFCDataHandover(hs []byte) (*ProximityReaderSession, error) {
	s, err := proximity.NewNFCDataReaderSession(hs, r.opts...)
	if err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return &ProximityReaderSession{r: r, s: s}, nil
}

// StartNFCNegotiatedProximityPresentationWithModes prepares a holder
// for TNEP negotiated handover. The platform owns Type 4/TNEP and hands
// each complete Hr to HandleHandoverRequest. Only after it succeeds
// should the platform start the BLE mode returned by Engagement.
func (w *Wallet) StartNFCNegotiatedProximityPresentationWithModes(modesJSON string) (*ProximityPresentation, error) {
	return w.startProximityPresentationWithModes(modesJSON, w.w.StartNFCNegotiatedProximityPresentation)
}

// HandleHandoverRequest accepts a complete negotiated Hr NDEF message
// and returns a copy of Hs. Repeated identical requests are idempotent
// before establishment; a different request cannot replace the session.
func (p *ProximityPresentation) HandleHandoverRequest(hr []byte) ([]byte, error) {
	hs, err := p.p.HandleHandoverRequest(hr)
	if errors.Is(err, proximity.ErrSessionClosed) {
		return nil, newError(CodeWrongStep, err)
	}
	if err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return hs, nil
}

// NewNFCHandoverRequest builds a reader's Hr for mdoc BLE modes named
// in modesJSON. Keep these exact bytes for StartFromNegotiatedHandover.
// This function does not perform NFC I/O or implement TNEP.
func NewNFCHandoverRequest(modesJSON string) ([]byte, error) {
	modes, err := parseProximityModes(modesJSON)
	if err != nil {
		return nil, err
	}
	hr, err := proximity.NewNFCHandoverRequest(nil, modes...)
	if err != nil {
		return nil, newError(CodeInternal, err)
	}
	return hr, nil
}

// StartFromNegotiatedHandover starts the reader from the exact Hs and
// Hr messages exchanged over TNEP. Reader authentication, trust roots,
// clock skew and document signer policy are this reader's existing ones.
func (r *ProximityReader) StartFromNegotiatedHandover(hs, hr []byte) (*ProximityReaderSession, error) {
	s, err := proximity.NewNFCNegotiatedReaderSession(hs, hr, r.opts...)
	if err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return &ProximityReaderSession{r: r, s: s}, nil
}
