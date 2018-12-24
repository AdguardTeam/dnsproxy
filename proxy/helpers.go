package proxy

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// Checks if the error signals of a closed server connecting
func isConnClosed(err error) bool {
	if err == nil {
		return false
	}
	nerr, ok := err.(*net.OpError)
	if !ok {
		return false
	}

	if strings.Contains(nerr.Err.Error(), "use of closed network connection") {
		return true
	}

	return false
}

// getIPString is a helper function that extracts IP address from net.Addr
func getIPString(addr net.Addr) string {
	switch addr := addr.(type) {
	case *net.UDPAddr:
		return addr.IP.String()
	case *net.TCPAddr:
		return addr.IP.String()
	}
	return ""
}

// readPrefixed reads DNS message prefixed with its length (2 bytes)
func readPrefixed(conn *net.Conn) ([]byte, error) {
	buf := make([]byte, 2+dns.MaxMsgSize)
	packetLength, pos := -1, 0
	for {
		readnb, err := (*conn).Read(buf[pos:])
		if err != nil {
			return buf, err
		}
		pos += readnb
		if pos >= 2 && packetLength < 0 {
			packetLength = int(binary.BigEndian.Uint16(buf[0:2]))
			if packetLength >= dns.MaxMsgSize {
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

// prefixWithSize adds 2-byte prefix with the packet length
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
