package dnsstamps

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	defaultDNSCryptPort = 443
	defaultDoHPort      = 443
	defaultDoTPort      = 843
	defaultDoQPort      = 784
	defaultPlainPort    = 53
	stampProtocol       = "sdns://"
)

// ServerInformalProperties represents informal properties about the resolver
type ServerInformalProperties uint64

const (
	// ServerInformalPropertyDNSSEC means resolver does DNSSEC validation
	ServerInformalPropertyDNSSEC = ServerInformalProperties(1) << 0
	// ServerInformalPropertyNoLog means resolver does not record logs
	ServerInformalPropertyNoLog = ServerInformalProperties(1) << 1
	// ServerInformalPropertyNoFilter means resolver doesn't intentionally block domains
	ServerInformalPropertyNoFilter = ServerInformalProperties(1) << 2
)

// StampProtoType is a stamp protocol type
type StampProtoType uint8

const (
	// StampProtoTypePlain is plain DNS
	StampProtoTypePlain = StampProtoType(0x00)
	// StampProtoTypeDNSCrypt is DNSCrypt
	StampProtoTypeDNSCrypt = StampProtoType(0x01)
	// StampProtoTypeDoH is DNS-over-HTTPS
	StampProtoTypeDoH = StampProtoType(0x02)
	// StampProtoTypeTLS is DNS-over-TLS
	StampProtoTypeTLS = StampProtoType(0x03)
	// StampProtoTypeDoQ is DNS-over-QUIC
	StampProtoTypeDoQ = StampProtoType(0x04)
)

func (stampProtoType *StampProtoType) String() string {
	switch *stampProtoType {
	case StampProtoTypePlain:
		return "Plain"
	case StampProtoTypeDNSCrypt:
		return "DNSCrypt"
	case StampProtoTypeDoH:
		return "DoH"
	case StampProtoTypeTLS:
		return "DoT"
	case StampProtoTypeDoQ:
		return "DoQ"
	default:
		panic("Unexpected protocol")
	}
}

// ServerStamp is the DNS stamp representation
type ServerStamp struct {
	ServerAddrStr string  // Server address with port
	ServerPk      []uint8 // the DNSCrypt provider’s Ed25519 public key, as 32 raw bytes. Empty for other types.

	// Hash is the SHA256 digest of one of the TBS certificate found in the validation chain,
	// typically the certificate used to sign the resolver’s certificate. Multiple hashes can
	// be provided for seamless rotations.
	Hashes [][]uint8

	// Provider means different things depending on the stamp type
	// DNSCrypt: the DNSCrypt provider name
	// DOH and DOT: server's hostname
	// Plain DNS: not specified
	ProviderName string

	Path  string                   // Path is the HTTP path, and it has a meaning for DoH stamps only
	Props ServerInformalProperties // Server properties (DNSSec, NoLog, NoFilter)
	Proto StampProtoType           // Stamp protocol
}

// NewServerStampFromString creates a new DNS stamp from the stamp string
func NewServerStampFromString(stampStr string) (ServerStamp, error) {
	if !strings.HasPrefix(stampStr, stampProtocol) {
		return ServerStamp{}, fmt.Errorf("stamps are expected to start with %s", stampProtocol)
	}
	bin, err := base64.RawURLEncoding.DecodeString(stampStr[len(stampProtocol):])
	if err != nil {
		return ServerStamp{}, err
	}
	if len(bin) < 1 {
		return ServerStamp{}, errors.New("stamp is too short")
	}

	if bin[0] == uint8(StampProtoTypePlain) {
		return newPlainServerStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeDNSCrypt) {
		return newDNSCryptServerStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeDoH) {
		return newDoHServerStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeTLS) {
		return newDoTOrDoQServerStamp(bin, StampProtoTypeTLS, defaultDoTPort)
	} else if bin[0] == uint8(StampProtoTypeDoQ) {
		return newDoTOrDoQServerStamp(bin, StampProtoTypeDoQ, defaultDoQPort)
	}
	return ServerStamp{}, errors.New("unsupported stamp version or protocol")
}

func (stamp *ServerStamp) String() string {

	switch stamp.Proto {
	case StampProtoTypeDNSCrypt:
		return stamp.dnsCryptString()
	case StampProtoTypeDoH:
		return stamp.dohString()
	case StampProtoTypeTLS:
		return stamp.dotOrDoqString(StampProtoTypeTLS, defaultDoTPort)
	case StampProtoTypeDoQ:
		return stamp.dotOrDoqString(StampProtoTypeDoQ, defaultDoQPort)
	case StampProtoTypePlain:
		return stamp.plainString()
	}

	panic("Unsupported protocol")
}

// id(u8)=0x01 props addrLen(1) serverAddr pkStrlen(1) pkStr providerNameLen(1) providerName
func newDNSCryptServerStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypeDNSCrypt}
	if len(bin) < 66 {
		return stamp, errors.New("stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	stampLen := int(bin[pos])
	if 1+stampLen >= binLen-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+stampLen])
	pos += stampLen
	if net.ParseIP(strings.TrimRight(strings.TrimLeft(stamp.ServerAddrStr, "["), "]")) != nil {
		stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, defaultDNSCryptPort)
	}

	stampLen = int(bin[pos])
	if 1+stampLen >= binLen-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ServerPk = bin[pos : pos+stampLen]
	pos += stampLen

	stampLen = int(bin[pos])
	if stampLen >= binLen-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+stampLen])
	pos += stampLen

	if pos != binLen {
		return stamp, errors.New("invalid stamp (garbage after end)")
	}
	return stamp, nil
}

// id(u8)=0x02 props addrLen(1) serverAddr hashLen(1) hash providerNameLen(1) providerName pathLen(1) path
func newDoHServerStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypeDoH}
	if len(bin) < 22 {
		return stamp, errors.New("stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	stampLen := int(bin[pos])
	if 1+stampLen >= binLen-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+stampLen])
	pos += stampLen

	for {
		vlen := int(bin[pos])
		stampLen = vlen & ^0x80
		if 1+stampLen >= binLen-pos {
			return stamp, errors.New("invalid stamp")
		}
		pos++
		if stampLen > 0 {
			stamp.Hashes = append(stamp.Hashes, bin[pos:pos+stampLen])
		}
		pos += stampLen
		if vlen&0x80 != 0x80 {
			break
		}
	}

	stampLen = int(bin[pos])
	if 1+stampLen >= binLen-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+stampLen])
	pos += stampLen

	stampLen = int(bin[pos])
	if stampLen >= binLen-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.Path = string(bin[pos : pos+stampLen])
	pos += stampLen

	if pos != binLen {
		return stamp, errors.New("invalid stamp (garbage after end)")
	}

	if net.ParseIP(strings.TrimRight(strings.TrimLeft(stamp.ServerAddrStr, "["), "]")) != nil {
		stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, defaultDoHPort)
	}

	return stamp, nil
}

// id(u8)=0x03|0x04 props addrLen(1) serverAddr hashLen(1) hash providerNameLen(1) providerName
func newDoTOrDoQServerStamp(bin []byte, stampType StampProtoType, defaultPort uint16) (ServerStamp, error) {
	stamp := ServerStamp{Proto: stampType}
	if len(bin) < 22 {
		return stamp, errors.New("stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	stampLen := int(bin[pos])
	if 1+stampLen >= binLen-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+stampLen])
	pos += stampLen

	for {
		vlen := int(bin[pos])
		stampLen = vlen & ^0x80
		if 1+stampLen >= binLen-pos {
			return stamp, errors.New("invalid stamp")
		}
		pos++
		if stampLen > 0 {
			stamp.Hashes = append(stamp.Hashes, bin[pos:pos+stampLen])
		}
		pos += stampLen
		if vlen&0x80 != 0x80 {
			break
		}
	}

	stampLen = int(bin[pos])
	if stampLen >= binLen-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+stampLen])
	pos += stampLen

	if pos != binLen {
		return stamp, errors.New("invalid stamp (garbage after end)")
	}

	if net.ParseIP(strings.TrimRight(strings.TrimLeft(stamp.ServerAddrStr, "["), "]")) != nil {
		stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, defaultPort)
	}

	return stamp, nil
}

// id(u8)=0x00 props addrLen(1) serverAddr
func newPlainServerStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypePlain}
	if len(bin) < 17 {
		return stamp, fmt.Errorf("stamp is too short: len=%d", len(bin))
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	stampLen := int(bin[pos])
	if stampLen >= binLen-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+stampLen])
	pos += stampLen

	if pos != binLen {
		return stamp, errors.New("invalid stamp (garbage after end)")
	}

	if net.ParseIP(strings.TrimRight(strings.TrimLeft(stamp.ServerAddrStr, "["), "]")) != nil {
		stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, defaultPlainPort)
	}

	return stamp, nil
}

func (stamp *ServerStamp) dnsCryptString() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypeDNSCrypt)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.Props))

	serverAddrStr := stamp.ServerAddrStr
	if strings.HasSuffix(serverAddrStr, ":"+strconv.Itoa(defaultDNSCryptPort)) {
		serverAddrStr = serverAddrStr[:len(serverAddrStr)-1-len(strconv.Itoa(defaultDNSCryptPort))]
	}
	bin = append(bin, uint8(len(serverAddrStr)))
	bin = append(bin, []uint8(serverAddrStr)...)

	bin = append(bin, uint8(len(stamp.ServerPk)))
	bin = append(bin, stamp.ServerPk...)

	bin = append(bin, uint8(len(stamp.ProviderName)))
	bin = append(bin, []uint8(stamp.ProviderName)...)

	str := base64.RawURLEncoding.EncodeToString(bin)

	return stampProtocol + str
}

func (stamp *ServerStamp) dohString() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypeDoH)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.Props))

	serverAddrStr := stamp.ServerAddrStr
	if strings.HasSuffix(serverAddrStr, ":"+strconv.Itoa(defaultDoHPort)) {
		serverAddrStr = serverAddrStr[:len(serverAddrStr)-1-len(strconv.Itoa(defaultDoHPort))]
	}
	bin = append(bin, uint8(len(serverAddrStr)))
	bin = append(bin, []uint8(serverAddrStr)...)

	if len(stamp.Hashes) == 0 {
		bin = append(bin, uint8(0))
	} else {
		last := len(stamp.Hashes) - 1
		for i, hash := range stamp.Hashes {
			vlen := len(hash)
			if i < last {
				vlen |= 0x80
			}
			bin = append(bin, uint8(vlen))
			bin = append(bin, hash...)
		}
	}

	bin = append(bin, uint8(len(stamp.ProviderName)))
	bin = append(bin, []uint8(stamp.ProviderName)...)

	bin = append(bin, uint8(len(stamp.Path)))
	bin = append(bin, []uint8(stamp.Path)...)

	str := base64.RawURLEncoding.EncodeToString(bin)
	return stampProtocol + str
}

func (stamp *ServerStamp) dotOrDoqString(stampType StampProtoType, defaultPort uint16) string {
	bin := make([]uint8, 9)
	bin[0] = uint8(stampType)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.Props))

	serverAddrStr := stamp.ServerAddrStr
	if strings.HasSuffix(serverAddrStr, ":"+strconv.Itoa(int(defaultPort))) {
		serverAddrStr = serverAddrStr[:len(serverAddrStr)-1-len(strconv.Itoa(int(defaultPort)))]
	}
	bin = append(bin, uint8(len(serverAddrStr)))
	bin = append(bin, []uint8(serverAddrStr)...)

	if len(stamp.Hashes) == 0 {
		bin = append(bin, uint8(0))
	} else {
		last := len(stamp.Hashes) - 1
		for i, hash := range stamp.Hashes {
			vlen := len(hash)
			if i < last {
				vlen |= 0x80
			}
			bin = append(bin, uint8(vlen))
			bin = append(bin, hash...)
		}
	}

	bin = append(bin, uint8(len(stamp.ProviderName)))
	bin = append(bin, []uint8(stamp.ProviderName)...)

	str := base64.RawURLEncoding.EncodeToString(bin)
	return stampProtocol + str
}

func (stamp *ServerStamp) plainString() string {
	bin := make([]uint8, 9)
	bin[0] = uint8(StampProtoTypePlain)
	binary.LittleEndian.PutUint64(bin[1:9], uint64(stamp.Props))

	serverAddrStr := stamp.ServerAddrStr
	if strings.HasSuffix(serverAddrStr, ":"+strconv.Itoa(defaultPlainPort)) {
		serverAddrStr = serverAddrStr[:len(serverAddrStr)-1-len(strconv.Itoa(defaultPlainPort))]
	}
	bin = append(bin, uint8(len(serverAddrStr)))
	bin = append(bin, []uint8(serverAddrStr)...)

	str := base64.RawURLEncoding.EncodeToString(bin)
	return stampProtocol + str
}
