package proxyutil

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/lucas-clemente/quic-go"
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

// WritePrefixed -- write a DNS message to a TCP connection
// it first writes a 2-byte prefix followed by the message itself
func WritePrefixed(b []byte, conn net.Conn) error {
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(b)))
	_, err := (&net.Buffers{l, b}).WriteTo(conn)
	return err
}

// ReadPrefixed reads a DNS message with a 2-byte prefix containing message
// length from QUIC stream.
func ReadPrefixedQUIC(conn quic.Stream, out []byte) (int, error) {
	l := make([]byte, 2 + dns.MaxMsgSize)
	n, _ := conn.Read(l)
	// err is not checked here because STREAM FIN sent by the client is indicated as error here.
	// instead, we should check the number of bytes received.

	if (n < 2) {
		return 0, fmt.Errorf("reading at least two-byte prefix from QUIC stream");
	}
	n -= 2

	packetLen := binary.BigEndian.Uint16(l[0:2])
	if packetLen > dns.MaxMsgSize { // silly? Uint16 can't be larger than 65535
		return 0, ErrTooLarge
	}

	if (n != int(packetLen)) {
		return 0, fmt.Errorf("mismatch in QUIC msg length: %d != %d", n, int(packetLen))
	}
	copy(out, l[2:])

	return n, nil
}

// WritePrefixed -- write a DNS message to a QUIC stream
// it first writes a 2-byte prefix followed by the message itself
func WritePrefixedQUIC(b []byte, conn quic.Stream) (int, error) {
	l := make([]byte, 2 + len(b))
	binary.BigEndian.PutUint16(l, uint16(len(b)))
	copy(l[2:], b)
	n, err := conn.Write(l)
	return n - 2, err
}
