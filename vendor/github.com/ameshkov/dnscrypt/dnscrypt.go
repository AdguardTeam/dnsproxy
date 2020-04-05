package dnscrypt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/ameshkov/dnscrypt/xsecretbox"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// CryptoConstruction represents the encryption algorithm (either XSalsa20Poly1305 or XChacha20Poly1305)
type CryptoConstruction uint16

const (
	// UndefinedConstruction is the default value for empty CertInfo only
	UndefinedConstruction CryptoConstruction = iota
	// XSalsa20Poly1305 encryption
	XSalsa20Poly1305
	// XChacha20Poly1305 encryption
	XChacha20Poly1305
)

var (
	certMagic           = [4]byte{0x44, 0x4e, 0x53, 0x43}
	serverMagic         = [8]byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
	minDNSPacketSize    = 12 + 5
	maxDNSPacketSize    = 4096
	maxDNSUDPPacketSize = 1252
)

const (
	clientMagicLen = 8
	nonceSize      = xsecretbox.NonceSize
	halfNonceSize  = xsecretbox.NonceSize / 2
	tagSize        = xsecretbox.TagSize
	publicKeySize  = 32
	queryOverhead  = clientMagicLen + publicKeySize + halfNonceSize + tagSize

	// <min-query-len> is a variable length, initially set to 256 bytes, and
	// must be a multiple of 64 bytes. (see https://dnscrypt.info/protocol)
	// Some servers do not work if padded length is less than 256. Example: Quad9
	minUDPQuestionSize = 256
)

// Client contains parameters for a DNSCrypt client
type Client struct {
	Proto             string        // Protocol ("udp" or "tcp"). Empty means "udp".
	Timeout           time.Duration // Timeout for read/write operations (0 means infinite timeout)
	AdjustPayloadSize bool          // If true, the client will automatically add a EDNS0 RR that will advertise a larger buffer
}

// CertInfo contains DnsCrypt server certificate data retrieved from the server
type CertInfo struct {
	Serial             uint32   // Cert serial number (the cert can be superseded by another one with a higher serial number)
	ServerPk           [32]byte // Server public key
	SharedKey          [32]byte // Shared key
	MagicQuery         [clientMagicLen]byte
	CryptoConstruction CryptoConstruction // Encryption algorithm
	NotBefore          uint32             // Cert is valid starting from this date (epoch time)
	NotAfter           uint32             // Cert is valid until this date (epoch time)
}

// ServerInfo contains DNSCrypt server information necessary for decryption/encryption
type ServerInfo struct {
	SecretKey       [32]byte          // Client secret key
	PublicKey       [32]byte          // Client public key
	ServerPublicKey ed25519.PublicKey // Server public key
	ServerAddress   string            // Server IP address
	ProviderName    string            // Provider name

	ServerCert *CertInfo // Certificate info (obtained with the first unencrypted DNS request)
}

// Dial fetches and validates DNSCrypt certificate from the given server
// Data received during this call is then used for DNS requests encryption/decryption
// stampStr is an sdns:// address which is parsed using go-dnsstamps package
func (c *Client) Dial(stampStr string) (*ServerInfo, time.Duration, error) {

	stamp, err := dnsstamps.NewServerStampFromString(stampStr)
	if err != nil {
		// Invalid SDNS stamp
		return nil, 0, err
	}

	if stamp.Proto != dnsstamps.StampProtoTypeDNSCrypt {
		return nil, 0, errors.New("stamp is not for a DNSCrypt server")
	}

	return c.DialStamp(stamp)
}

// DialStamp fetches and validates DNSCrypt certificate from the given server
// Data received during this call is then used for DNS requests encryption/decryption
func (c *Client) DialStamp(stamp dnsstamps.ServerStamp) (*ServerInfo, time.Duration, error) {

	serverInfo := ServerInfo{}

	// Generate the secret/public pair
	if _, err := rand.Read(serverInfo.SecretKey[:]); err != nil {
		return nil, 0, err
	}
	curve25519.ScalarBaseMult(&serverInfo.PublicKey, &serverInfo.SecretKey)

	// Set the provider properties
	serverInfo.ServerPublicKey = stamp.ServerPk
	serverInfo.ServerAddress = stamp.ServerAddrStr
	serverInfo.ProviderName = stamp.ProviderName
	if !strings.HasSuffix(serverInfo.ProviderName, ".") {
		serverInfo.ProviderName = serverInfo.ProviderName + "."
	}

	// Fetch the certificate and validate it
	certInfo, rtt, err := serverInfo.fetchCurrentDNSCryptCert(c.Proto, c.Timeout)

	if err != nil {
		return nil, rtt, err
	}

	serverInfo.ServerCert = &certInfo
	return &serverInfo, rtt, nil
}

// Exchange performs a synchronous DNS query to the specified DNSCrypt server and returns a DNS response.
// This method creates a new network connection for every call so avoid using it for TCP.
// DNSCrypt server information needs to be fetched and validated prior to this call using the c.DialStamp method.
func (c *Client) Exchange(m *dns.Msg, s *ServerInfo) (*dns.Msg, time.Duration, error) {

	now := time.Now()
	network := c.Proto
	if network == "" {
		network = "udp"
	}
	conn, err := net.Dial(network, s.ServerAddress)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	r, _, err := c.ExchangeConn(m, s, conn)
	if err != nil {
		return nil, 0, err
	}

	rtt := time.Since(now)
	return r, rtt, nil
}

// ExchangeConn performs a synchronous DNS query to the specified DNSCrypt server and returns a DNS response.
// DNSCrypt server information needs to be fetched and validated prior to this call using the c.DialStamp method
func (c *Client) ExchangeConn(m *dns.Msg, s *ServerInfo, conn net.Conn) (*dns.Msg, time.Duration, error) {
	now := time.Now()

	if c.AdjustPayloadSize {
		c.adjustPayloadSize(m)
	}
	query, err := m.Pack()
	if err != nil {
		return nil, 0, err
	}

	encryptedQuery, clientNonce, err := s.encrypt(c.Proto, query)
	if err != nil {
		return nil, 0, err
	}

	if c.Proto == "tcp" {
		encryptedQuery, err = prefixWithSize(encryptedQuery)
		if err != nil {
			return nil, 0, err
		}
	}

	if c.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	}
	_, _ = conn.Write(encryptedQuery)
	encryptedResponse := make([]byte, maxDNSPacketSize)

	// Reading the response
	// In case if the server ServerInfo is not valid anymore (for instance, certificate was rotated) the read operation will most likely time out.
	// This might be a signal to re-dial for the server certificate.
	if c.Proto == "tcp" {
		encryptedResponse, err = readPrefixed(conn)
		if err != nil {
			return nil, 0, err
		}
	} else {
		length, readErr := conn.Read(encryptedResponse)
		if readErr != nil {
			return nil, 0, readErr
		}
		encryptedResponse = encryptedResponse[:length]
	}

	decrypted, err := s.decrypt(encryptedResponse, clientNonce)
	if err != nil {
		return nil, 0, err
	}

	r := dns.Msg{}
	err = r.Unpack(decrypted)
	if err != nil {
		return nil, 0, err
	}

	rtt := time.Since(now)
	return &r, rtt, nil
}

// Adjusts the maximum payload size advertised in queries sent to upstream servers
// See https://github.com/jedisct1/dnscrypt-proxy/blob/master/dnscrypt-proxy/plugin_get_set_payload_size.go
// See here also: https://github.com/jedisct1/dnscrypt-proxy/issues/667
func (c *Client) adjustPayloadSize(msg *dns.Msg) {
	originalMaxPayloadSize := dns.MinMsgSize
	edns0 := msg.IsEdns0()
	dnssec := false
	if edns0 != nil {
		originalMaxPayloadSize = int(edns0.UDPSize())
		dnssec = edns0.Do()
	}
	var options *[]dns.EDNS0

	maxPayloadSize := min(maxDNSUDPPacketSize, max(originalMaxPayloadSize, maxDNSUDPPacketSize))

	if maxPayloadSize > dns.MinMsgSize {
		var extra2 []dns.RR
		for _, extra := range msg.Extra {
			if extra.Header().Rrtype != dns.TypeOPT {
				extra2 = append(extra2, extra)
			} else if xoptions := &extra.(*dns.OPT).Option; len(*xoptions) > 0 && options == nil {
				options = xoptions
			}
		}
		msg.Extra = extra2
		msg.SetEdns0(uint16(maxPayloadSize), dnssec)
		if options != nil {
			for _, extra := range msg.Extra {
				if extra.Header().Rrtype == dns.TypeOPT {
					extra.(*dns.OPT).Option = *options
					break
				}
			}
		}
	}
}

func (s *ServerInfo) fetchCurrentDNSCryptCert(proto string, timeout time.Duration) (CertInfo, time.Duration, error) {
	if len(s.ServerPublicKey) != ed25519.PublicKeySize {
		return CertInfo{}, 0, errors.New("invalid public key length")
	}

	query := new(dns.Msg)
	query.SetQuestion(s.ProviderName, dns.TypeTXT)
	client := dns.Client{Net: proto, UDPSize: uint16(maxDNSUDPPacketSize), Timeout: timeout}
	in, rtt, err := client.Exchange(query, s.ServerAddress)
	if err != nil {
		return CertInfo{}, 0, err
	}

	certInfo := CertInfo{CryptoConstruction: UndefinedConstruction}
	for _, answerRr := range in.Answer {
		recCertInfo, err := txtToCertInfo(answerRr, s)

		if err != nil {
			log.Printf("[%v] %s", s.ProviderName, err)
			continue
		}

		if recCertInfo.Serial < certInfo.Serial {
			log.Printf("[%v] Superseded by a previous certificate", s.ProviderName)
			continue
		}

		if recCertInfo.Serial == certInfo.Serial {
			if recCertInfo.CryptoConstruction > certInfo.CryptoConstruction {
				log.Printf("[%v] Upgrading the construction from %v to %v", s.ProviderName, certInfo.CryptoConstruction, recCertInfo.CryptoConstruction)
			} else {
				log.Printf("[%v] Keeping the previous, preferred crypto construction", s.ProviderName)
				continue
			}
		}

		// Set the cert info
		certInfo = recCertInfo
	}

	if certInfo.CryptoConstruction == UndefinedConstruction {
		return certInfo, 0, errors.New("no useable certificate found")
	}

	return certInfo, rtt, nil
}

func (s *ServerInfo) encrypt(proto string, packet []byte) (encrypted []byte, clientNonce []byte, err error) {
	nonce, clientNonce := make([]byte, nonceSize), make([]byte, halfNonceSize)
	rand.Read(clientNonce)
	copy(nonce, clientNonce)
	var publicKey *[publicKeySize]byte

	sharedKey := &s.ServerCert.SharedKey
	publicKey = &s.PublicKey

	minQuestionSize := queryOverhead + len(packet)
	if proto == "tcp" {
		var xpad [1]byte
		rand.Read(xpad[:])
		minQuestionSize += int(xpad[0])
	} else {
		minQuestionSize = max(minUDPQuestionSize, minQuestionSize)
	}
	paddedLength := min(maxDNSUDPPacketSize, (max(minQuestionSize, queryOverhead)+63) & ^63)

	if queryOverhead+len(packet)+1 > paddedLength {
		err = errors.New("question too large; cannot be padded")
		return
	}
	encrypted = append(s.ServerCert.MagicQuery[:], publicKey[:]...)
	encrypted = append(encrypted, nonce[:halfNonceSize]...)
	padded := pad(packet, paddedLength-queryOverhead)
	if s.ServerCert.CryptoConstruction == XChacha20Poly1305 {
		encrypted = xsecretbox.Seal(encrypted, nonce, padded, sharedKey[:])
	} else {
		var xsalsaNonce [24]byte
		copy(xsalsaNonce[:], nonce)
		encrypted = secretbox.Seal(encrypted, padded, &xsalsaNonce, sharedKey)
	}
	return
}

func (s *ServerInfo) decrypt(encrypted []byte, nonce []byte) ([]byte, error) {

	sharedKey := &s.ServerCert.SharedKey
	serverMagicLen := len(serverMagic)
	responseHeaderLen := serverMagicLen + nonceSize
	if len(encrypted) < responseHeaderLen+tagSize+minDNSPacketSize ||
		len(encrypted) > responseHeaderLen+tagSize+maxDNSPacketSize ||
		!bytes.Equal(encrypted[:serverMagicLen], serverMagic[:]) {
		return encrypted, errors.New("invalid message size or prefix")
	}
	serverNonce := encrypted[serverMagicLen:responseHeaderLen]
	if !bytes.Equal(nonce[:halfNonceSize], serverNonce[:halfNonceSize]) {
		return encrypted, errors.New("unexpected nonce")
	}
	var packet []byte
	var err error
	if s.ServerCert.CryptoConstruction == XChacha20Poly1305 {
		packet, err = xsecretbox.Open(nil, serverNonce, encrypted[responseHeaderLen:], sharedKey[:])
	} else {
		var xsalsaServerNonce [24]byte
		copy(xsalsaServerNonce[:], serverNonce)
		var ok bool
		packet, ok = secretbox.Open(nil, encrypted[responseHeaderLen:], &xsalsaServerNonce, sharedKey)
		if !ok {
			err = errors.New("incorrect tag")
		}
	}
	if err != nil {
		return encrypted, err
	}
	packet, err = unpad(packet)
	if err != nil || len(packet) < minDNSPacketSize {
		return encrypted, errors.New("incorrect padding")
	}
	return packet, nil
}

func txtToCertInfo(answerRr dns.RR, serverInfo *ServerInfo) (CertInfo, error) {
	now := uint32(time.Now().Unix())
	certInfo := CertInfo{CryptoConstruction: UndefinedConstruction}

	binCert, err := packTxtString(strings.Join(answerRr.(*dns.TXT).Txt, ""))

	// Validate the cert basic params
	if err != nil {
		return certInfo, errors.New("unable to unpack the certificate")
	}
	if len(binCert) < 124 {
		return certInfo, errors.New("certificate is too short")
	}
	if !bytes.Equal(binCert[:4], certMagic[:4]) {
		return certInfo, errors.New("invalid cert magic")
	}

	switch esVersion := binary.BigEndian.Uint16(binCert[4:6]); esVersion {
	case 0x0001:
		certInfo.CryptoConstruction = XSalsa20Poly1305
	case 0x0002:
		certInfo.CryptoConstruction = XChacha20Poly1305
	default:
		return certInfo, fmt.Errorf("unsupported crypto construction: %v", esVersion)
	}

	// Verify the server public key
	signature := binCert[8:72]
	signed := binCert[72:]
	if !ed25519.Verify(serverInfo.ServerPublicKey, signed, signature) {
		return certInfo, errors.New("incorrect signature")
	}

	certInfo.Serial = binary.BigEndian.Uint32(binCert[112:116])

	// Validate the certificate date
	certInfo.NotBefore = binary.BigEndian.Uint32(binCert[116:120])
	certInfo.NotAfter = binary.BigEndian.Uint32(binCert[120:124])
	if certInfo.NotBefore >= certInfo.NotAfter {
		return certInfo, fmt.Errorf("certificate ends before it starts (%v >= %v)", certInfo.NotBefore, certInfo.NotAfter)
	}
	if now > certInfo.NotAfter || now < certInfo.NotBefore {
		return certInfo, errors.New("certificate not valid at the current date")
	}

	var serverPk [32]byte
	copy(serverPk[:], binCert[72:104])
	certInfo.SharedKey = computeSharedKey(certInfo.CryptoConstruction, &serverInfo.SecretKey, &serverPk, &serverInfo.ProviderName)

	copy(certInfo.ServerPk[:], serverPk[:])
	copy(certInfo.MagicQuery[:], binCert[104:112])

	return certInfo, nil
}

func computeSharedKey(cryptoConstruction CryptoConstruction, secretKey *[32]byte, serverPk *[32]byte, providerName *string) (sharedKey [32]byte) {
	if cryptoConstruction == XChacha20Poly1305 {
		var err error
		sharedKey, err = xsecretbox.SharedKey(*secretKey, *serverPk)
		if err != nil {
			log.Printf("[%v] Weak public key", providerName)
		}
	} else {
		box.Precompute(&sharedKey, serverPk, secretKey)
	}
	return
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func dddToByte(s []byte) byte {
	return (s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0')
}

func packTxtString(s string) ([]byte, error) {
	bs := make([]byte, len(s))
	msg := make([]byte, 0)
	copy(bs, s)
	for i := 0; i < len(bs); i++ {
		if bs[i] == '\\' {
			i++
			if i == len(bs) {
				break
			}
			if i+2 < len(bs) && isDigit(bs[i]) && isDigit(bs[i+1]) && isDigit(bs[i+2]) {
				msg = append(msg, dddToByte(bs[i:]))
				i += 2
			} else if bs[i] == 't' {
				msg = append(msg, '\t')
			} else if bs[i] == 'r' {
				msg = append(msg, '\r')
			} else if bs[i] == 'n' {
				msg = append(msg, '\n')
			} else {
				msg = append(msg, bs[i])
			}
		} else {
			msg = append(msg, bs[i])
		}
	}
	return msg, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func pad(packet []byte, minSize int) []byte {
	packet = append(packet, 0x80)
	for len(packet) < minSize {
		packet = append(packet, 0)
	}
	return packet
}

func unpad(packet []byte) ([]byte, error) {
	for i := len(packet); ; {
		if i == 0 {
			return nil, errors.New("invalid padding (short packet)")
		}
		i--
		if packet[i] == 0x80 {
			return packet[:i], nil
		} else if packet[i] != 0x00 {
			return nil, errors.New("invalid padding (delimiter not found)")
		}
	}
}

func prefixWithSize(packet []byte) ([]byte, error) {
	packetLen := len(packet)
	if packetLen > 0xffff {
		return packet, errors.New("packet too large")
	}
	packet = append(append(packet, 0), 0)
	copy(packet[2:], packet[:len(packet)-2])
	binary.BigEndian.PutUint16(packet[0:2], uint16(len(packet)-2))
	return packet, nil
}

func readPrefixed(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 2+maxDNSPacketSize)
	packetLength, pos := -1, 0
	for {
		readnb, err := conn.Read(buf[pos:])
		if err != nil {
			return buf, err
		}
		pos += readnb
		if pos >= 2 && packetLength < 0 {
			packetLength = int(binary.BigEndian.Uint16(buf[0:2]))
			if packetLength > maxDNSPacketSize-1 {
				return buf, errors.New("packet too large")
			}
			if packetLength < minDNSPacketSize {
				return buf, errors.New("packet too short")
			}
		}
		if packetLength >= 0 && pos >= 2+packetLength {
			return buf[2 : 2+packetLength], nil
		}
	}
}
