package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oneByteReader returns at most one byte per Read, mimicking a TCP peer that
// delivers the 2-byte length prefix across two segments.
type oneByteReader struct {
	r *bytes.Reader
}

func (o *oneByteReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	return o.r.Read(p[:1])
}

// connWithReader is a net.Conn whose Read comes from r; other methods are unused.
type connWithReader struct {
	net.Conn
	r io.Reader
}

func (c *connWithReader) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func TestReadPrefixed_splitLengthPrefix(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))

	frame := append(lenBuf[:], payload...)
	conn := &connWithReader{r: &oneByteReader{r: bytes.NewReader(frame)}}

	got, err := readPrefixed(conn)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestReadPrefixed_emptyMessage(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	go func() {
		_, _ = client.Write([]byte{0x00, 0x00})
		_ = client.Close()
	}()

	require.NoError(t, server.SetDeadline(time.Now().Add(2*time.Second)))
	got, err := readPrefixed(server)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestReadPrefixed_shortPrefixEOF(t *testing.T) {
	conn := &connWithReader{r: bytes.NewReader([]byte{0x00})}
	_, err := readPrefixed(conn)
	require.Error(t, err)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}
