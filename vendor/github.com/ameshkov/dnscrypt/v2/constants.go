package dnscrypt

// Error represents a dnscrypt error.
type Error string

func (e Error) Error() string { return "dnscrypt: " + string(e) }

const (
	// ErrTooShort means that the DNS query is shorter than possible
	ErrTooShort = Error("message is too short")

	// ErrQueryTooLarge means that the DNS query is larger than max allowed size
	ErrQueryTooLarge = Error("DNSCrypt query is too large")

	// ErrEsVersion means that the cert contains unsupported es-version
	ErrEsVersion = Error("unsupported es-version")

	// ErrInvalidDate means that the cert is not valid for the current time
	ErrInvalidDate = Error("cert has invalid ts-start or ts-end")

	// ErrInvalidCertSignature means that the cert has invalid signature
	ErrInvalidCertSignature = Error("cert has invalid signature")

	// ErrInvalidQuery means that it failed to decrypt a DNSCrypt query
	ErrInvalidQuery = Error("DNSCrypt query is invalid and cannot be decrypted")

	// ErrInvalidClientMagic means that client-magic does not match
	ErrInvalidClientMagic = Error("DNSCrypt query contains invalid client magic")

	// ErrInvalidResolverMagic means that server-magic does not match
	ErrInvalidResolverMagic = Error("DNSCrypt response contains invalid resolver magic")

	// ErrInvalidResponse means that it failed to decrypt a DNSCrypt response
	ErrInvalidResponse = Error("DNSCrypt response is invalid and cannot be decrypted")

	// ErrInvalidPadding means that it failed to unpad a query
	ErrInvalidPadding = Error("invalid padding")

	// ErrInvalidDNSStamp means an invalid DNS stamp
	ErrInvalidDNSStamp = Error("invalid DNS stamp")

	// ErrFailedToFetchCert means that it failed to fetch DNSCrypt certificate
	ErrFailedToFetchCert = Error("failed to fetch DNSCrypt certificate")

	// ErrCertTooShort means that it failed to deserialize cert, too short
	ErrCertTooShort = Error("cert is too short")

	// ErrCertMagic means an invalid cert magic
	ErrCertMagic = Error("invalid cert magic")

	// ErrServerConfig means that it failed to start the DNSCrypt server - invalid configuration
	ErrServerConfig = Error("invalid server configuration")

	// ErrServerNotStarted is returned if there's nothing to shutdown
	ErrServerNotStarted = Error("server is not started")
)

const (
	// <min-query-len> is a variable length, initially set to 256 bytes, and
	// must be a multiple of 64 bytes. (see https://dnscrypt.info/protocol)
	// Some servers do not work if padded length is less than 256. Example: Quad9
	minUDPQuestionSize = 256

	// Minimum possible DNS packet size
	minDNSPacketSize = 12 + 5

	// See 11. Authenticated encryption and key exchange algorithm
	// The public and secret keys are 32 bytes long in storage
	keySize = 32

	// size of the shared key used to encrypt/decrypt messages
	sharedKeySize = 32

	// ClientMagic is the first 8 bytes of a client query that is to be built
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
	// certMagic is a bytes sequence that must be in the beginning of the serialized cert
	certMagic = [4]byte{0x44, 0x4e, 0x53, 0x43}

	// resolverMagic is a byte sequence that must be in the beginning of every response
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
