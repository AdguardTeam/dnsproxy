package dnscrypt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"time"
)

// Cert - DNSCrypt server certificate
// See ResolverConfig for more info on how to create one
type Cert struct {
	// Serial - a 4 byte serial number in big-endian format. If more than
	// one certificates are valid, the client must prefer the certificate
	// with a higher serial number.
	Serial uint32

	// <es-version> ::= the cryptographic construction to use with this
	// certificate.
	// For X25519-XSalsa20Poly1305, <es-version> must be 0x00 0x01.
	// For X25519-XChacha20Poly1305, <es-version> must be 0x00 0x02.
	EsVersion CryptoConstruction

	// Signature - a 64-byte signature of (<resolver-pk> <client-magic>
	// <serial> <ts-start> <ts-end> <extensions>) using the Ed25519 algorithm and the
	// provider secret key. Ed25519 must be used in this version of the
	// protocol.
	Signature [ed25519.SignatureSize]byte

	// ResolverPk - the resolver's short-term public key, which is 32 bytes when using X25519.
	// This key is used to encrypt/decrypt DNS queries
	ResolverPk [keySize]byte

	// ResolverSk - the resolver's short-term private key, which is 32 bytes when using X25519.
	// Note that it's only used in the server implementation and never serialized/deserialized.
	// This key is used to encrypt/decrypt DNS queries
	ResolverSk [keySize]byte

	// ClientMagic - the first 8 bytes of a client query that is to be built
	// using the information from this certificate. It may be a truncated
	// public key. Two valid certificates cannot share the same <client-magic>.
	ClientMagic [clientMagicSize]byte

	// NotAfter - the date the certificate is valid from, as a big-endian
	// 4-byte unsigned Unix timestamp.
	NotBefore uint32

	// NotAfter - the date the certificate is valid until (inclusive), as a
	// big-endian 4-byte unsigned Unix timestamp.
	NotAfter uint32
}

// Serialize - serializes the cert to bytes
// <cert> ::= <cert-magic> <es-version> <protocol-minor-version> <signature>
//           <resolver-pk> <client-magic> <serial> <ts-start> <ts-end>
//           <extensions>
// Certificates made of these information, without extensions, are 116 bytes
// long. With the addition of the cert-magic, es-version and
// protocol-minor-version, the record is 124 bytes long.
func (c *Cert) Serialize() ([]byte, error) {
	// validate
	if c.EsVersion == UndefinedConstruction {
		return nil, ErrEsVersion
	}

	if !c.VerifyDate() {
		return nil, ErrInvalidDate
	}

	// start serializing
	b := make([]byte, 124)

	// <cert-magic>
	copy(b[:4], certMagic[:])
	// <es-version>
	binary.BigEndian.PutUint16(b[4:6], uint16(c.EsVersion))
	// <protocol-minor-version> - always 0x00 0x00
	copy(b[6:8], []byte{0, 0})
	// <signature>
	copy(b[8:72], c.Signature[:ed25519.SignatureSize])
	// signed: (<resolver-pk> <client-magic> <serial> <ts-start> <ts-end> <extensions>)
	c.writeSigned(b[72:])

	// done
	return b, nil
}

// Deserialize - deserializes certificate from a byte array
// <cert> ::= <cert-magic> <es-version> <protocol-minor-version> <signature>
//           <resolver-pk> <client-magic> <serial> <ts-start> <ts-end>
//           <extensions>
func (c *Cert) Deserialize(b []byte) error {
	if len(b) < 124 {
		return ErrCertTooShort
	}

	// <cert-magic>
	if !bytes.Equal(b[:4], certMagic[:4]) {
		return ErrCertMagic
	}

	// <es-version>
	switch esVersion := binary.BigEndian.Uint16(b[4:6]); esVersion {
	case uint16(XSalsa20Poly1305):
		c.EsVersion = XSalsa20Poly1305
	case uint16(XChacha20Poly1305):
		c.EsVersion = XChacha20Poly1305
	default:
		return ErrEsVersion
	}

	// Ignore 6:8, <protocol-minor-version>
	// <signature>
	copy(c.Signature[:], b[8:72])
	// <resolver-pk>
	copy(c.ResolverPk[:], b[72:104])
	// <client-magic>
	copy(c.ClientMagic[:], b[104:112])
	// <serial>
	c.Serial = binary.BigEndian.Uint32(b[112:116])
	// <ts-start> <ts-end>
	c.NotBefore = binary.BigEndian.Uint32(b[116:120])
	c.NotAfter = binary.BigEndian.Uint32(b[120:124])

	// Deserialized with no issues
	return nil
}

// VerifyDate - checks that cert is valid at this moment
func (c *Cert) VerifyDate() bool {
	if c.NotBefore >= c.NotAfter {
		return false
	}
	now := uint32(time.Now().Unix())
	if now > c.NotAfter || now < c.NotBefore {
		return false
	}
	return true
}

// VerifySignature - checks if the cert is properly signed with the specified signature
func (c *Cert) VerifySignature(publicKey ed25519.PublicKey) bool {
	b := make([]byte, 52)
	c.writeSigned(b)
	return ed25519.Verify(publicKey, b, c.Signature[:])
}

// Sign - creates cert.Signature
func (c *Cert) Sign(privateKey ed25519.PrivateKey) {
	b := make([]byte, 52)
	c.writeSigned(b)
	signature := ed25519.Sign(privateKey, b)
	copy(c.Signature[:64], signature[:64])
}

// String - Cert's string representation
func (c *Cert) String() string {
	return fmt.Sprintf("Certificate Serial=%d NotBefore=%s NotAfter=%s EsVersion=%s",
		c.Serial, time.Unix(int64(c.NotBefore), 0).String(),
		time.Unix(int64(c.NotAfter), 0).String(), c.EsVersion.String())
}

// writeSigned - writes (<resolver-pk> <client-magic> <serial> <ts-start> <ts-end> <extensions>)
func (c *Cert) writeSigned(dst []byte) {
	// <resolver-pk>
	copy(dst[:32], c.ResolverPk[:keySize])
	// <client-magic>
	copy(dst[32:40], c.ClientMagic[:clientMagicSize])
	// <serial>
	binary.BigEndian.PutUint32(dst[40:44], c.Serial)
	// <ts-start>
	binary.BigEndian.PutUint32(dst[44:48], c.NotBefore)
	// <ts-end>
	binary.BigEndian.PutUint32(dst[48:52], c.NotAfter)
}
