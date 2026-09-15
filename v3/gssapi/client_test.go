package gssapi

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/types"
)

// wrapTokenHeader builds a valid 16-byte acceptor WrapToken header with the
// given checksum length (EC) field.
func wrapTokenHeader(checksumLen uint16) []byte {
	h := make([]byte, gssapi.HdrLen)
	h[0], h[1] = 0x05, 0x04 // token id
	h[2] = 0x01             // acceptor flag set
	h[3] = gssapi.FillerByte
	binary.BigEndian.PutUint16(h[4:6], checksumLen)
	return h
}

// A malicious server can set the checksum-length field high enough that
// 16 + checksumL overflows uint16. The sanity check still passes because the
// token is large, so the bad offset reached the slice operations.
func TestUnmarshalWrapTokenChecksumLengthOverflow(t *testing.T) {
	const checksumLen = uint16(0xFFFF)
	b := wrapTokenHeader(checksumLen)
	// Pad so len(b)-HdrLen >= checksumLen and the sanity check is satisfied.
	b = append(b, make([]byte, int(checksumLen))...)

	wt := &gssapi.WrapToken{}
	if err := UnmarshalWrapToken(wt, b, true); err != nil {
		t.Logf("got expected error: %v", err)
	}
}

func TestUnmarshalWrapTokenSplit(t *testing.T) {
	checksum := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	payload := []byte("payload")

	b := wrapTokenHeader(uint16(len(checksum)))
	b = append(b, checksum...)
	b = append(b, payload...)

	wt := &gssapi.WrapToken{}
	if err := UnmarshalWrapToken(wt, b, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(wt.CheckSum) != string(checksum) {
		t.Errorf("checksum: got %x, want %x", wt.CheckSum, checksum)
	}
	if string(wt.Payload) != string(payload) {
		t.Errorf("payload: got %q, want %q", wt.Payload, payload)
	}
}

// contextPair returns the two ends of one established GSS-API context, sharing a key no KDC
// issued, so the security-layer leg can be tested without a directory or a KDC.
func contextPair(t *testing.T) (initiator, acceptor *gssapi.SecurityLayerSession) {
	t.Helper()

	kv := make([]byte, 32)
	if _, err := rand.Read(kv); err != nil {
		t.Fatal(err)
	}
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: kv}

	i, err := gssapi.NewSecurityLayerSession(key, gssapi.SecurityLayerIntegrity, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, err := gssapi.NewSecurityLayerSession(key, gssapi.SecurityLayerIntegrity, false, 0)
	if err != nil {
		t.Fatal(err)
	}

	return i, a
}

// The client's answer to the server's challenge is four octets: the selected security layer, then
// a maximum buffer size of zero because no layer was selected. RFC 4752 section 3.1.
func TestNegotiateSaslAuthSelectsNoLayer(t *testing.T) {
	initiator, acceptor := contextPair(t)
	c := &Client{sess: initiator}

	challenge, err := acceptor.Wrap([]byte{
		byte(gssapi.SecurityLayerNone | gssapi.SecurityLayerIntegrity | gssapi.SecurityLayerConfidentiality),
		0x00, 0xFF, 0xFF,
	})
	if err != nil {
		t.Fatal(err)
	}

	out, err := c.NegotiateSaslAuth(challenge, "")
	if err != nil {
		t.Fatalf("NegotiateSaslAuth: %v", err)
	}

	reply, err := acceptor.Unwrap(out)
	if err != nil {
		t.Fatalf("the server could not verify the reply: %v", err)
	}
	if len(reply) != 4 {
		t.Fatalf("reply is %d bytes (%#v), want 4", len(reply), reply)
	}
	// 0x01 and not a zero octet: a zero mask selects no layer at all, which a strict server
	// refuses.
	if got := gssapi.SecurityLayer(reply[0]); got != gssapi.SecurityLayerNone {
		t.Errorf("selected layer %s, want %s", got, gssapi.SecurityLayerNone)
	}
	if reply[1] != 0 || reply[2] != 0 || reply[3] != 0 {
		t.Errorf("announced a maximum buffer of %#v, want none", reply[1:4])
	}
}

// An authorization identity travels after the four octets.
func TestNegotiateSaslAuthCarriesAuthzID(t *testing.T) {
	initiator, acceptor := contextPair(t)
	c := &Client{sess: initiator}

	challenge, err := acceptor.Wrap([]byte{byte(gssapi.SecurityLayerNone), 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}

	const authzid = "dn:cn=reader,ou=svc,dc=example,dc=com"

	out, err := c.NegotiateSaslAuth(challenge, authzid)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := acceptor.Unwrap(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(reply[4:]); got != authzid {
		t.Errorf("authorization identity = %q, want %q", got, authzid)
	}
}

// A server that will not go unprotected offers no layer this client can select, and the handshake
// stops rather than completing with the two ends disagreeing about what follows it.
func TestNegotiateSaslAuthRefusesAServerThatRequiresALayer(t *testing.T) {
	initiator, acceptor := contextPair(t)
	c := &Client{sess: initiator}

	challenge, err := acceptor.Wrap([]byte{byte(gssapi.SecurityLayerConfidentiality), 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.NegotiateSaslAuth(challenge, ""); err == nil {
		t.Fatal("a server offering only confidentiality was accepted")
	}
}

// Nothing is negotiated before the context is established.
func TestNegotiateSaslAuthNeedsAContext(t *testing.T) {
	c := &Client{}
	if _, err := c.NegotiateSaslAuth([]byte{1, 2, 3, 4}, ""); err == nil {
		t.Fatal("negotiated over a context that was never established")
	}
}
