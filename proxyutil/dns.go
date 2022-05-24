package proxyutil

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

// ErrTooLarge means that a DNS message is larger than 64KiB.
const ErrTooLarge errors.Error = "dns message is too large"

// DNSSize returns if buffer size *advertised* in the requests OPT record.
// Or when the request was over TCP, we return the maximum allowed size of 64K.
func DNSSize(isUDP bool, r *dns.Msg) int {
	var size uint16
	if o := r.IsEdns0(); o != nil {
		size = o.UDPSize()
	}

	if !isUDP {
		return dns.MaxMsgSize
	}

	if size < dns.MinMsgSize {
		return dns.MinMsgSize
	}

	// normalize size
	return int(size)
}

// ReadPrefixed reads a DNS message with a 2-byte prefix containing message
// length from conn.
func ReadPrefixed(conn net.Conn) ([]byte, error) {
	l := make([]byte, 2)
	_, err := conn.Read(l)
	if err != nil {
		return nil, fmt.Errorf("reading len: %w", err)
	}

	packetLen := binary.BigEndian.Uint16(l)
	if packetLen > dns.MaxMsgSize {
		return nil, ErrTooLarge
	}

	buf := make([]byte, packetLen)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, fmt.Errorf("reading msg: %w", err)
	}

	return buf, nil
}

// WritePrefixed writes a DNS message to a TCP connection it first writes
// a 2-byte prefix followed by the message itself.
func WritePrefixed(b []byte, conn net.Conn) error {
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(b)))
	_, err := (&net.Buffers{l, b}).WriteTo(conn)

	return err
}

// AddPrefix adds a 2-byte prefix with the DNS message length.
func AddPrefix(b []byte) (m []byte) {
	m = make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(m, uint16(len(b)))
	copy(m[2:], b)

	return m
}
