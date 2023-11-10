package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// dialTimeout is the global timeout for establishing a TLS connection.
// TODO(ameshkov): use bootstrap timeout instead.
const dialTimeout = 10 * time.Second

// dnsOverTLS implements the [Upstream] interface for the DNS-over-TLS protocol.
type dnsOverTLS struct {
	// addr is the DNS-over-TLS server URL.
	addr *url.URL

	// getDialer either returns an initialized dial handler or creates a
	// new one.
	getDialer DialerInitializer

	// tlsConf is the configuration of TLS.
	tlsConf *tls.Config

	// connsMu protects conns.
	connsMu *sync.Mutex

	// conns stores the connections ready for reuse.  Don't use [sync.Pool]
	// here, since there is no need to deallocate these connections.
	//
	// TODO(e.burkov, ameshkov):  Currently connections just stored in FILO
	// order, which eventually makes most of them unusable due to timeouts.
	// This leads to weak performance for all exchanges coming across such
	// connections.
	conns []net.Conn
}

// newDoT returns the DNS-over-TLS Upstream.
func newDoT(addr *url.URL, opts *Options) (ups Upstream, err error) {
	addPort(addr, defaultPortDoT)

	tlsUps := &dnsOverTLS{
		addr:      addr,
		getDialer: newDialerInitializer(addr, opts),
		// #nosec G402 -- TLS certificate verification could be disabled by
		// configuration.
		tlsConf: &tls.Config{
			ServerName:   addr.Hostname(),
			RootCAs:      opts.RootCAs,
			CipherSuites: opts.CipherSuites,
			// Use the default capacity for the LRU cache.  It may be useful to
			// store several caches since the user may be routed to different
			// servers in case there's load balancing on the server-side.
			ClientSessionCache:    tls.NewLRUClientSessionCache(0),
			MinVersion:            tls.VersionTLS12,
			InsecureSkipVerify:    opts.InsecureSkipVerify,
			VerifyPeerCertificate: opts.VerifyServerCertificate,
			VerifyConnection:      opts.VerifyConnection,
		},
		connsMu: &sync.Mutex{},
	}

	runtime.SetFinalizer(tlsUps, (*dnsOverTLS).Close)

	return tlsUps, nil
}

// type check
var _ Upstream = (*dnsOverTLS)(nil)

// Address implements the [Upstream] interface for *dnsOverTLS.
func (p *dnsOverTLS) Address() string { return p.addr.String() }

// Exchange implements the [Upstream] interface for *dnsOverTLS.
func (p *dnsOverTLS) Exchange(m *dns.Msg) (reply *dns.Msg, err error) {
	h, err := p.getDialer()
	if err != nil {
		return nil, fmt.Errorf("getting conn to %s: %w", p.addr, err)
	}

	conn, err := p.conn(h)
	if err != nil {
		return nil, fmt.Errorf("getting conn to %s: %w", p.addr, err)
	}

	reply, err = p.exchangeWithConn(conn, m)
	if err != nil {
		// The pooled connection might have been closed already, see
		// https://github.com/AdguardTeam/dnsproxy/issues/3.  The following
		// connection from pool may also be malformed, so dial a new one.

		err = errors.WithDeferred(err, conn.Close())
		log.Debug("dot %s: bad conn from pool: %s", p.addr, err)

		// Retry.
		conn, err = tlsDial(h, p.tlsConf.Clone())
		if err != nil {
			return nil, fmt.Errorf(
				"dialing %s: connecting to %s: %w",
				p.addr,
				p.tlsConf.ServerName,
				err,
			)
		}

		reply, err = p.exchangeWithConn(conn, m)
		if err != nil {
			return reply, errors.WithDeferred(err, conn.Close())
		}
	}

	p.putBack(conn)

	return reply, nil
}

// Close implements the [Upstream] interface for *dnsOverTLS.
func (p *dnsOverTLS) Close() (err error) {
	runtime.SetFinalizer(p, nil)

	p.connsMu.Lock()
	defer p.connsMu.Unlock()

	var closeErrs []error
	for _, conn := range p.conns {
		closeErr := conn.Close()
		if closeErr != nil && isCriticalTCP(closeErr) {
			closeErrs = append(closeErrs, closeErr)
		}
	}

	return errors.Join(closeErrs...)
}

// conn returns the first available connection from the pool if there is any, or
// dials a new one otherwise.
func (p *dnsOverTLS) conn(h bootstrap.DialHandler) (conn net.Conn, err error) {
	// Dial a new connection outside the lock, if needed.
	defer func() {
		if conn == nil {
			conn, err = tlsDial(h, p.tlsConf.Clone())
			err = errors.Annotate(err, "connecting to %s: %w", p.tlsConf.ServerName)
		}
	}()

	p.connsMu.Lock()
	defer p.connsMu.Unlock()

	l := len(p.conns)
	if l == 0 {
		return nil, nil
	}

	p.conns, conn = p.conns[:l-1], p.conns[l-1]

	err = conn.SetDeadline(time.Now().Add(dialTimeout))
	if err != nil {
		log.Debug("dot upstream: setting deadline to conn from pool: %s", err)

		// If deadLine can't be updated it means that connection was already
		// closed.
		return nil, nil
	}

	log.Debug("dot upstream: using existing conn %s", conn.RemoteAddr())

	return conn, nil
}

func (p *dnsOverTLS) putBack(conn net.Conn) {
	p.connsMu.Lock()
	defer p.connsMu.Unlock()

	p.conns = append(p.conns, conn)
}

// exchangeWithConn tries to exchange the query using conn.
func (p *dnsOverTLS) exchangeWithConn(conn net.Conn, m *dns.Msg) (reply *dns.Msg, err error) {
	addr := p.Address()

	logBegin(addr, networkTCP, m)
	defer func() { logFinish(addr, networkTCP, err) }()

	dnsConn := dns.Conn{Conn: conn}

	err = dnsConn.WriteMsg(m)
	if err != nil {
		return nil, fmt.Errorf("sending request to %s: %w", addr, err)
	}

	reply, err = dnsConn.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", addr, err)
	} else if reply.Id != m.Id {
		return reply, dns.ErrId
	}

	return reply, err
}

// tlsDial is basically the same as tls.DialWithDialer, but we will call our own
// dialContext function to get connection.
func tlsDial(dialContext bootstrap.DialHandler, conf *tls.Config) (c *tls.Conn, err error) {
	// We're using bootstrapped address instead of what's passed to the
	// function.
	rawConn, err := dialContext(context.Background(), networkTCP, "")
	if err != nil {
		return nil, err
	}

	// We want the timeout to cover the whole process: TCP connection and TLS
	// handshake dialTimeout will be used as connection deadLine.
	conn := tls.Client(rawConn, conf)
	err = conn.SetDeadline(time.Now().Add(dialTimeout))
	if err != nil {
		// Must not happen in normal circumstances.
		panic(fmt.Errorf("dnsproxy: tls dial: setting deadline: %w", err))
	}

	err = conn.Handshake()
	if err != nil {
		return nil, errors.WithDeferred(err, conn.Close())
	}

	return conn, nil
}

// isCriticalTCP returns true if err isn't an expected error in terms of closing
// the TCP connection.
func isCriticalTCP(err error) (ok bool) {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}

	switch {
	case
		errors.Is(err, io.EOF),
		errors.Is(err, net.ErrClosed),
		errors.Is(err, os.ErrDeadlineExceeded),
		isConnBroken(err):
		return false
	default:
		return true
	}
}
