package upstream

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/log"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
)

const (
	// DoQCodeNoError is used when the connection or stream needs to be closed,
	// but there is no error to signal.
	DoQCodeNoError = quic.ApplicationErrorCode(0)
	// DoQCodeInternalError signals that the DoQ implementation encountered
	// an internal error and is incapable of pursuing the transaction or the
	// connection.
	DoQCodeInternalError = quic.ApplicationErrorCode(1)
	// DoQCodeProtocolError signals that the DoQ implementation encountered
	// a protocol error and is forcibly aborting the connection.
	DoQCodeProtocolError = quic.ApplicationErrorCode(2)
)

//
// dnsOverQUIC is a DNS-over-QUIC implementation according to the spec:
// https://www.rfc-editor.org/rfc/rfc9250.html
//
type dnsOverQUIC struct {
	// boot is a bootstrap DNS abstraction that is used to resolve the upstream
	// server's address and open a network connection to it.
	boot *bootstrapper
	// tokenStore is a QUIC token store that is used across QUIC connections.
	// Since the QUIC config is re-created when a connection is (re-)opened
	// the tokenStore is instead saved as part of the dnsOverQUIC struct.
	tokenStore quic.TokenStore
	// conn is the current active QUIC connection.  It can be closed and
	// re-opened when needed.
	conn quic.Connection
	// bytesPool is a *sync.Pool we use to store byte buffers in.  These byte
	// buffers are used to read responses from the upstream.
	bytesPool *sync.Pool
	// sync.RWMutex protects conn and bytesPool.
	sync.RWMutex
}

// type check
var _ Upstream = &dnsOverQUIC{}

// newDoQ returns the DNS-over-QUIC Upstream.
func newDoQ(uu *url.URL, opts *Options) (u Upstream, err error) {
	addPort(uu, defaultPortDoQ)

	var b *bootstrapper
	b, err = urlToBoot(uu, opts)
	if err != nil {
		return nil, fmt.Errorf("creating quic bootstrapper: %w", err)
	}

	return &dnsOverQUIC{boot: b, tokenStore: quic.NewLRUTokenStore(1, 10)}, nil
}

func (p *dnsOverQUIC) Address() string { return p.boot.URL.String() }

func (p *dnsOverQUIC) Exchange(m *dns.Msg) (res *dns.Msg, err error) {
	var conn quic.Connection
	conn, err = p.getConnection(true)
	if err != nil {
		return nil, err
	}

	// When sending queries over a QUIC connection, the DNS Message ID MUST be
	// set to zero.
	id := m.Id
	m.Id = 0
	defer func() {
		// Restore the original ID to not break compatibility with proxies
		m.Id = id
		if res != nil {
			res.Id = id
		}
	}()

	var buf []byte
	buf, err = m.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message for DoQ: %w", err)
	}

	var stream quic.Stream
	stream, err = p.openStream(conn)
	if err != nil {
		p.closeConnWithError(DoQCodeInternalError)
		return nil, fmt.Errorf("open new stream to %s: %w", p.Address(), err)
	}

	_, err = stream.Write(proxyutil.AddPrefix(buf))
	if err != nil {
		p.closeConnWithError(DoQCodeInternalError)
		return nil, fmt.Errorf("failed to write to a QUIC stream: %w", err)
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	// stream.Close() -- closes the write-direction of the stream.
	_ = stream.Close()

	res, err = p.readMsg(stream)
	if err != nil {
		// If a peer encounters such an error condition, it is considered a
		// fatal error.  It SHOULD forcibly abort the connection using QUIC's
		// CONNECTION_CLOSE mechanism and SHOULD use the DoQ error code
		// DOQ_PROTOCOL_ERROR.
		p.closeConnWithError(DoQCodeProtocolError)
	}
	return res, err
}

// getBytesPool returns (creates if needed) a pool we store byte buffers in.
func (p *dnsOverQUIC) getBytesPool() (pool *sync.Pool) {
	p.Lock()
	if p.bytesPool == nil {
		p.bytesPool = &sync.Pool{
			New: func() interface{} {
				b := make([]byte, dns.MaxMsgSize)

				return &b
			},
		}
	}
	p.Unlock()
	return p.bytesPool
}

// getConnection opens or returns an existing quic.Connection. useCached
// argument controls whether we should try to use the existing cached
// connection.  If it is false, we will forcibly create a new connection and
// close the existing one if needed.
func (p *dnsOverQUIC) getConnection(useCached bool) (quic.Connection, error) {
	var conn quic.Connection
	p.RLock()
	conn = p.conn
	if conn != nil && useCached {
		p.RUnlock()
		return conn, nil
	}
	if conn != nil {
		// we're recreating the connection, let's create a new one.
		_ = conn.CloseWithError(DoQCodeNoError, "")
	}
	p.RUnlock()

	p.Lock()
	defer p.Unlock()

	var err error
	conn, err = p.openConnection()
	if err != nil {
		// This does not look too nice, but QUIC (or maybe quic-go)
		// doesn't seem stable enough.
		// Maybe retransmissions aren't fully implemented in quic-go?
		// Anyways, the simple solution is to make a second try when
		// it fails to open the QUIC conn.
		conn, err = p.openConnection()
		if err != nil {
			return nil, err
		}
	}
	p.conn = conn
	return conn, nil
}

// openStream opens a new QUIC stream for the specified connection.
func (p *dnsOverQUIC) openStream(conn quic.Connection) (quic.Stream, error) {
	ctx := context.Background()

	if p.boot.options.Timeout > 0 {
		deadline := time.Now().Add(p.boot.options.Timeout)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
		defer cancel() // avoid resource leak
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err == nil {
		return stream, nil
	}

	// try to recreate the connection.
	newConn, err := p.getConnection(false)
	if err != nil {
		return nil, err
	}
	// open a new stream.
	return newConn.OpenStreamSync(ctx)
}

// openConnection opens a new QUIC connection.
func (p *dnsOverQUIC) openConnection() (conn quic.Connection, err error) {
	tlsConfig, dialContext, err := p.boot.get()
	if err != nil {
		return nil, fmt.Errorf("failed to bootstrap QUIC connection: %w", err)
	}

	// we're using bootstrapped address instead of what's passed to the function
	// it does not create an actual connection, but it helps us determine
	// what IP is actually reachable (when there're v4/v6 addresses).
	rawConn, err := dialContext(context.Background(), "udp", "")
	if err != nil {
		return nil, fmt.Errorf("failed to open a QUIC connection: %w", err)
	}
	// It's never actually used
	_ = rawConn.Close()

	udpConn, ok := rawConn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("failed to open connection to %s", p.Address())
	}

	addr := udpConn.RemoteAddr().String()
	quicConfig := &quic.Config{
		// Set the keep alive interval to 20s as it would be in the
		// quic-go@v0.27.1 with KeepAlive field set to true.  This value is
		// specified in
		// https://pkg.go.dev/github.com/lucas-clemente/quic-go/internal/protocol#MaxKeepAliveInterval.
		//
		// TODO(ameshkov):  Consider making it configurable.
		KeepAlivePeriod: 20 * time.Second,
		TokenStore:      p.tokenStore,
	}
	conn, err = quic.DialAddrEarlyContext(context.Background(), addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("opening quic connection to %s: %w", p.Address(), err)
	}

	return conn, nil
}

// closeConnWithError closes the active connection with error to make sure that
// new queries were processed in another connection. We can do that in the case
// of a fatal error.
func (p *dnsOverQUIC) closeConnWithError(code quic.ApplicationErrorCode) {
	p.Lock()
	defer p.Unlock()

	if p.conn == nil {
		// Do nothing, there's no active conn anyways.
		return
	}

	err := p.conn.CloseWithError(code, "")
	if err != nil {
		log.Error("failed to close the conn: %v", err)
	}
	p.conn = nil
}

// readMsg reads the incoming DNS message from the QUIC stream.
func (p *dnsOverQUIC) readMsg(stream quic.Stream) (m *dns.Msg, err error) {
	pool := p.getBytesPool()
	bufPtr := pool.Get().(*[]byte)

	defer pool.Put(bufPtr)

	respBuf := *bufPtr
	n, err := stream.Read(respBuf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("reading response from %s: %w", p.Address(), err)
	}

	// All DNS messages (queries and responses) sent over DoQ connections MUST
	// be encoded as a 2-octet length field followed by the message content as
	// specified in [RFC1035].
	// IMPORTANT: Note, that we ignore this prefix here as this implementation
	// does not support receiving multiple messages over a single connection.
	m = new(dns.Msg)
	err = m.Unpack(respBuf[2:])
	if err != nil {
		return nil, fmt.Errorf("unpacking response from %s: %w", p.Address(), err)
	}

	return m, nil
}
