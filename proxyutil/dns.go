package proxyutil

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/miekg/dns"
)

var (
	// ErrTooLarge - DNS message is larger than 64kb
	ErrTooLarge = errors.New("DNS message is too large")
)

// DNSSize returns if buffer size *advertised* in the requests OPT record.
// Or when the request was over TCP, we return the maximum allowed size of 64K.
func DNSSize(proto string, r *dns.Msg) int {
	size := uint16(0)
	if o := r.IsEdns0(); o != nil {
		size = o.UDPSize()
	}

	if proto != "udp" {
		return dns.MaxMsgSize
	}

	if size < dns.MinMsgSize {
		return dns.MinMsgSize
	}

	// normalize size
	return int(size)
}

// ReadPrefixed -- reads a DNS message with a 2-byte prefix containing message length
func ReadPrefixed(conn net.Conn) ([]byte, error) {
	l := make([]byte, 2)
	_, err := conn.Read(l)
	if err != nil {
		return nil, err
	}
	packetLen := binary.BigEndian.Uint16(l)
	if packetLen > dns.MaxMsgSize {
		return nil, ErrTooLarge
	}

	buf := make([]byte, packetLen)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// WritePrefixed -- write a DNS message to a TCP connection
// it first writes a 2-byte prefix followed by the message itself
func WritePrefixed(b []byte, conn net.Conn) error {
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(b)))
	_, err := (&net.Buffers{l, b}).WriteTo(conn)
	return err
}
