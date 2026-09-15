package gssapi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/types"

	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/spnego"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/messages"

	"github.com/go-krb5/krb5/credentials"
)

// Client implements ldap.GSSAPIClient interface.
type Client struct {
	*client.Client

	ekey   types.EncryptionKey
	Subkey types.EncryptionKey

	// seq is the sequence number of the authenticator this client sent in its AP-REQ. RFC 4121
	// section 4.2.6.2 starts an initiator's per-message tokens from it, and an acceptor that
	// checks sequence numbers refuses a token that starts anywhere else.
	seq uint64
	// sess protects the per-message tokens of the handshake once the context is established.
	sess *gssapi.SecurityLayerSession
}

// NewClientWithKeytab creates a new client from a keytab credential.
// Set the realm to empty string to use the default realm from config.
func NewClientWithKeytab(username, realm, keytabPath, krb5confPath string, settings ...func(*client.Settings)) (*Client, error) {
	krb5conf, err := config.Load(krb5confPath)
	if err != nil {
		return nil, err
	}

	keytab, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, err
	}

	client := client.NewWithKeytab(username, realm, keytab, krb5conf, settings...)

	return &Client{
		Client: client,
	}, nil
}

// NewClientWithPassword creates a new client from a password credential.
// Set the realm to empty string to use the default realm from config.
func NewClientWithPassword(username, realm, password string, krb5confPath string, settings ...func(*client.Settings)) (*Client, error) {
	krb5conf, err := config.Load(krb5confPath)
	if err != nil {
		return nil, err
	}

	client := client.NewWithPassword(username, realm, password, krb5conf, settings...)

	return &Client{
		Client: client,
	}, nil
}

// NewClientFromCCache creates a new client from a populated client cache.
func NewClientFromCCache(ccachePath, krb5confPath string, settings ...func(*client.Settings)) (*Client, error) {
	krb5conf, err := config.Load(krb5confPath)
	if err != nil {
		return nil, err
	}

	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, err
	}

	client, err := client.NewFromCCache(ccache, krb5conf, settings...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Client: client,
	}, nil
}

// Close deletes any established secure context and closes the client.
func (client *Client) Close() error {
	client.Client.Destroy()
	return nil
}

// DeleteSecContext destroys any established secure context.
func (client *Client) DeleteSecContext() error {
	client.ekey = types.EncryptionKey{}
	client.Subkey = types.EncryptionKey{}
	client.seq = 0
	client.sess = nil
	return nil
}

// InitSecContext initiates the establishment of a security context for
// GSS-API between the client and server.
// See RFC 4752 section 3.1.
func (client *Client) InitSecContext(target string, input []byte) ([]byte, bool, error) {
	return client.InitSecContextWithOptions(target, input, []int{})
}

// InitSecContextWithOptions initiates the establishment of a security context for
// GSS-API between the client and server.
// See RFC 4752 section 3.1.
func (client *Client) InitSecContextWithOptions(target string, input []byte, APOptions []int) ([]byte, bool, error) {
	gssapiFlags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual}

	switch input {
	case nil:
		tkt, ekey, err := client.Client.GetServiceTicket(target)
		if err != nil {
			return nil, false, err
		}
		client.ekey = ekey

		token, err := spnego.NewKRB5TokenAPREQ(client.Client, tkt, ekey, gssapiFlags, APOptions)
		if err != nil {
			return nil, false, err
		}

		if seq := token.APReq.Authenticator.SeqNumber; seq > 0 {
			client.seq = uint64(seq)
		}

		output, err := token.Marshal()
		if err != nil {
			return nil, false, err
		}

		return output, true, nil

	default:
		var token spnego.KRB5Token

		err := token.Unmarshal(input)
		if err != nil {
			return nil, false, err
		}

		var completed bool

		if token.IsAPRep() {
			completed = true

			encpart, err := crypto.DecryptEncPart(token.APRep.EncPart, client.ekey, keyusage.AP_REP_ENCPART)
			if err != nil {
				return nil, false, err
			}

			part := &messages.EncAPRepPart{}

			if err = part.Unmarshal(encpart); err != nil {
				return nil, false, err
			}
			client.Subkey = part.Subkey

			// RFC 4121 section 4.2.2: an acceptor that sends a subkey makes it the key of the
			// established context; without one the ticket's session key stays.
			key := client.ekey
			if len(client.Subkey.KeyValue) > 0 {
				key = client.Subkey
			}

			// Integrity and not none: the handshake's own tokens are integrity protected wrap
			// tokens even when the layer being negotiated is none, so a session created with none
			// would pass them through unprotected and the server would refuse the bind.
			client.sess, err = gssapi.NewSecurityLayerSession(key, gssapi.SecurityLayerIntegrity, true, 0,
				gssapi.InitialSendSequenceNumber(client.seq))
			if err != nil {
				return nil, false, err
			}
		}

		if token.IsKRBError() {
			return nil, !false, token.KRBError
		}

		return make([]byte, 0), !completed, nil
	}
}

// NegotiateSaslAuth performs the last step of the SASL handshake.
// See RFC 4752 section 3.1.
//
// The server offers a bit-mask of security layers and its maximum buffer size, and the client
// answers with the one layer it selects and a buffer size of its own. This client selects no
// security layer: SASL protection of the messages is redundant over TLS, and Active Directory
// refuses the combination outright (MS-ADTS section 5.1.1.1). A client that selects no layer
// announces a zero buffer, as RFC 4752 requires.
//
// The selection travels as the bit of the mask that means "no security layer", which is 0x01 and
// not a zero octet: a zero mask selects nothing at all, and a server that checks is entitled to
// refuse it.
func (client *Client) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	if client.sess == nil {
		return nil, errors.New("no established context to negotiate the security layer over")
	}

	challenge, err := client.sess.Unwrap(input)
	if err != nil {
		return nil, fmt.Errorf("server sent a final token that does not verify: %w", err)
	}

	if len(challenge) != 4 {
		return nil, fmt.Errorf("server sent a %d byte final token for SASL GSSAPI handshake, want 4", len(challenge))
	}

	if gssapi.SecurityLayer(challenge[0])&gssapi.SecurityLayerNone == 0 {
		return nil, fmt.Errorf("server offers security layers %#02x and not %s, which is the only one this client selects",
			challenge[0], gssapi.SecurityLayerNone)
	}

	payload := make([]byte, 4+len(authzid))
	payload[0] = byte(gssapi.SecurityLayerNone)
	// payload[1:4] stays zero: a client that selects no layer has no buffer to announce.
	copy(payload[4:], authzid)

	return client.sess.Wrap(payload)
}

func getGssWrapTokenId() *[2]byte {
	return &[2]byte{0x05, 0x04}
}

func UnmarshalWrapToken(wt *gssapi.WrapToken, b []byte, expectFromAcceptor bool) error {
	// Check if we can read a whole header
	if len(b) < 16 {
		return errors.New("bytes shorter than header length")
	}
	// Is the Token ID correct?
	if !bytes.Equal(getGssWrapTokenId()[:], b[0:2]) {
		return fmt.Errorf("wrong Token ID. Expected %s, was %s",
			hex.EncodeToString(getGssWrapTokenId()[:]),
			hex.EncodeToString(b[0:2]))
	}
	// Check the acceptor flag
	flags := b[2]
	isFromAcceptor := flags&0x01 == 1
	if isFromAcceptor && !expectFromAcceptor {
		return errors.New("unexpected acceptor flag is set: not expecting a token from the acceptor")
	}
	if !isFromAcceptor && expectFromAcceptor {
		return errors.New("expected acceptor flag is not set: expecting a token from the acceptor, not the initiator")
	}
	// Check the filler byte
	if b[3] != gssapi.FillerByte {
		return fmt.Errorf("unexpected filler byte: expecting 0xFF, was %s ", hex.EncodeToString(b[3:4]))
	}
	checksumL := binary.BigEndian.Uint16(b[4:6])
	// Sanity check on the checksum length
	if int(checksumL) > len(b)-gssapi.HdrLen {
		return fmt.Errorf("inconsistent checksum length: %d bytes to parse, checksum length is %d", len(b), checksumL)
	}

	// Compute the offset in int. checksumL is a uint16 read from the wire, so
	// 16 + checksumL overflows the uint16 range once checksumL exceeds 65519,
	// wrapping to a small value and turning the slices below into out-of-range
	// accesses that panic the bind goroutine.
	payloadStart := gssapi.HdrLen + int(checksumL)

	wt.Flags = flags
	wt.EC = checksumL
	wt.RRC = binary.BigEndian.Uint16(b[6:8])
	wt.SndSeqNum = binary.BigEndian.Uint64(b[8:16])
	wt.CheckSum = b[16:payloadStart]
	wt.Payload = b[payloadStart:]

	return nil
}
