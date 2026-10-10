package walletflow_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/hkdf"
	"github.com/idfoundry/oid4vcgo/internal/readerauth"
	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

func cborTag24(t *testing.T, b []byte) []byte {
	t.Helper()
	out, err := cbor.Marshal(cbor.Tag{Number: 24, Content: b})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// multiDocSessionEstablishment is a reader's SessionEstablishment for
// p's QR code asking for two documents: a harmless one signed by
// reader, and the held mdoc's family_name, signed by reader too only
// when signBoth.
func multiDocSessionEstablishment(t *testing.T, p *walletflow.ProximityPresentation, reader mdocReader, signBoth bool) []byte {
	t.Helper()
	de, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(p.QRCode(), "mdoc:"))
	if err != nil {
		t.Fatal(err)
	}
	var deMap map[int]cbor.RawMessage
	var security []cbor.RawMessage
	var keyTag cbor.Tag
	var deviceKey mdoc.CoseKey
	if cbor.Unmarshal(de, &deMap) != nil || cbor.Unmarshal(deMap[1], &security) != nil ||
		cbor.Unmarshal(security[1], &keyTag) != nil || cbor.Unmarshal(keyTag.Content.([]byte), &deviceKey) != nil {
		t.Fatal("decode the device engagement")
	}
	pub, err := deviceKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	eReader, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	readerKey, _ := mdoc.NewCoseKey(&eReader.PublicKey)
	readerKeyBytes, _ := cbor.Marshal(readerKey)
	transcript, _ := cbor.Marshal([]cbor.RawMessage{cborTag24(t, de), cborTag24(t, readerKeyBytes), {0xf6}})
	transcriptBytes := cborTag24(t, transcript)
	a, _ := eReader.ECDH()
	b, _ := pub.(*ecdsa.PublicKey).ECDH()
	z, _ := a.ECDH(b)
	salt := sha256.Sum256(transcriptBytes)
	skReader, _ := hkdf.Key(salt[:], z, []byte("SKReader"), 32)

	docRequest := func(docType, ns, element string, sign bool) map[string]any {
		items, _ := cbor.Marshal(map[string]any{"docType": docType, "nameSpaces": map[string]map[string]bool{ns: {element: false}}})
		itemsBytes := cborTag24(t, items)
		out := map[string]any{"itemsRequest": cbor.RawMessage(itemsBytes)}
		if sign {
			authn, _ := cbor.Marshal([]any{"ReaderAuthentication", cbor.RawMessage(transcript), cbor.RawMessage(itemsBytes)})
			sig, err := readerauth.Sign(reader.key.Signer, reader.key.Chain, cborTag24(t, authn))
			if err != nil {
				t.Fatal(err)
			}
			out["readerAuth"] = cbor.RawMessage(sig)
		}
		return out
	}
	req, _ := cbor.Marshal(map[string]any{"version": "1.0", "docRequests": []any{
		docRequest("org.example.harmless", "x", "y", true),
		docRequest(walletflowtest.DocType, walletflowtest.NameSpace, "family_name", signBoth),
	}})
	block, _ := aes.NewCipher(skReader)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	nonce[11] = 1
	msg, _ := cbor.Marshal(map[string]any{"eReaderKey": cbor.RawMessage(cborTag24(t, readerKeyBytes)), "data": gcm.Seal(nil, nonce, req, nil)})
	return msg
}

// A trusted reader's signature on one document request doesn't vouch
// for another the same request carries: the holder can answer either,
// so trust takes every request's readerAuth into account.
func TestProximityPresentation_TrustCoversEveryDocRequest(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	reader := newMdocReader(t)
	wallet := func(require bool) *walletflow.Wallet {
		w, err := walletflow.New(walletflow.Config{
			ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
			MdocReaderRoots: reader.roots, RequireTrustedMdocReader: require, Development: true,
		}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	heldMdoc(t, receive(t, f, wallet(false), walletflowtest.MdocConfigurationID))
	ctx := context.Background()
	start := func(w *walletflow.Wallet, signBoth bool) (*walletflow.ProximityPresentation, walletflow.ProximityEvent) {
		t.Helper()
		p, err := w.StartProximityPresentation()
		if err != nil {
			t.Fatal(err)
		}
		return p, p.HandleMessage(ctx, multiDocSessionEstablishment(t, p, reader, signBoth))
	}

	if _, ev := start(wallet(true), false); ev.Request || !errors.Is(ev.Err, walletflow.ErrUntrustedVerifier) {
		t.Errorf("an unsigned document request beside a trusted one, RequireTrustedMdocReader: %+v, want refused as untrusted", ev)
	}
	if p, ev := start(wallet(false), false); !ev.Request || p.Reader().Status != proximity.ReaderUnauthenticated {
		t.Errorf("an unsigned document request beside a trusted one: %+v, reader %v; want shown, unauthenticated", ev, p.Reader().Status)
	}
	if p, ev := start(wallet(true), true); !ev.Request || p.Reader().Status != proximity.ReaderTrusted {
		t.Errorf("both signed by the trusted reader: %+v, reader %v; want trusted", ev, p.Reader().Status)
	}
}
