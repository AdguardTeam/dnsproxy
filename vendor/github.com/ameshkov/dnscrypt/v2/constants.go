package dnscrypt

import "errors"

var (
	// ErrTooShort - DNS query is shorter than possible
	ErrTooShort = errors.New("DNSCrypt message is too short")

	// ErrQueryTooLarge - DNS query is larger than max allowed size
	ErrQueryTooLarge = errors.New("DNSCrypt query is too large")

	// ErrEsVersion - cert contains unsupported es-version
	ErrEsVersion = errors.New("unsupported es-version")

	// ErrInvalidDate - cert is not valid for the current time
	ErrInvalidDate = errors.New("cert has invalid ts-start or ts-end")

	// ErrInvalidCertSignature - cert has invalid signature
	ErrInvalidCertSignature = errors.New("cert has invalid signature")

	// ErrInvalidQuery - failed to decrypt a DNSCrypt query
	ErrInvalidQuery = errors.New("DNSCrypt query is invalid and cannot be decrypted")

	// ErrInvalidClientMagic - client-magic does not match
	ErrInvalidClientMagic = errors.New("DNSCrypt query contains invalid client magic")

	// ErrInvalidResolverMagic - server-magic does not match
	ErrInvalidResolverMagic = errors.New("DNSCrypt response contains invalid resolver magic")

	// ErrInvalidResponse - failed to decrypt a DNSCrypt response
	ErrInvalidResponse = errors.New("DNSCrypt response is invalid and cannot be decrypted")

	// ErrInvalidPadding - failed to unpad a query
	ErrInvalidPadding = errors.New("invalid padding")

	// ErrInvalidDNSStamp - invalid DNS stamp
	ErrInvalidDNSStamp = errors.New("invalid DNS stamp")

	// ErrFailedToFetchCert - failed to fetch DNSCrypt certificate
	ErrFailedToFetchCert = errors.New("failed to fetch DNSCrypt certificate")

	// ErrCertTooShort - failed to deserialize cert, too short
	ErrCertTooShort = errors.New("cert is too short")

	// ErrCertMagic - invalid cert magic
	ErrCertMagic = errors.New("invalid cert magic")

	// ErrServerConfig - failed to start the DNSCrypt server - invalid configuration
	ErrServerConfig = errors.New("invalid server configuration")
)

const (
	// <min-query-len> is a variable length, initially set to 256 bytes, and
	// must be a multiple of 64 bytes. (see https://dnscrypt.info/protocol)
	// Some servers do not work if padded length is less than 256. Example: Quad9
	minUDPQuestionSize = 256

	// <max-query-len> - maximum allowed query length
	maxQueryLen = 1252

	// Minimum possible DNS packet size
	minDNSPacketSize = 12 + 5

	// See 11. Authenticated encryption and key exchange algorithm
	// The public and secret keys are 32 bytes long in storage
	keySize = 32

	// size of the shared key used to encrypt/decrypt messages
	sharedKeySize = 32

	// ClientMagic - the first 8 bytes of a client query that is to be built
	// using the information from this certificate. It may be a truncated
	// public key. Two valid certificates cannot share the same <client-magic>.
	clientMagicSize = 8

	// When using X25519-XSalsa20Poly1305, this construction requires a 24 bytes
	// nonce, that must not be reused for a given shared secret.
	nonceSize = 24

	// the first 8 bytes of every dnscrypt response. must match resolverMagic.
	resolverMagicSize = 8
)

var (
	// certMagic - bytes sequence that must be in the beginning of the serialized cert
	certMagic = [4]byte{0x44, 0x4e, 0x53, 0x43}

	// resolverMagic - byte sequence that must be in the beginning of every response
	resolverMagic = []byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
)

// CryptoConstruction represents the encryption algorithm (either XSalsa20Poly1305 or XChacha20Poly1305)
type CryptoConstruction uint16

const (
	// UndefinedConstruction is the default value for empty CertInfo only
	UndefinedConstruction CryptoConstruction = iota
	// XSalsa20Poly1305 encryption
	XSalsa20Poly1305 CryptoConstruction = 0x0001
	// XChacha20Poly1305 encryption
	XChacha20Poly1305 CryptoConstruction = 0x0002
)

func (c CryptoConstruction) String() string {
	switch c {
	case XChacha20Poly1305:
		return "XChacha20Poly1305"
	case XSalsa20Poly1305:
		return "XSalsa20Poly1305"
	default:
		return "Unknown"
	}
}
