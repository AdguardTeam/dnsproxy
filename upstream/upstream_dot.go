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

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// dialTimeout is the global timeout for establishing a TLS connection.
// TODO(ameshkov): use bootstrap timeout instead.
const dialTimeout = 10 * time.Second

// dnsOverTLS is a struct that implements the Upstream interface for the
// DNS-over-TLS protocol.
type dnsOverTLS struct {
	// boot resolves the hostname upstream addresses.
	boot *bootstrapper

	// connsMu protects conns.
	connsMu sync.Mutex

	// conns stores the connections ready for reuse.  Don't use [sync.Pool]
	// here, since there is no need to deallocate these connections.
	//
	// TODO(e.burkov, ameshkov):  Currently connections just stored in FILO
	// order, which eventually makes most of them unusable due to timeouts.
	// This leads to weak performance for all exchanges coming across such
	// connections.
	conns []net.Conn
}

// type check
var _ Upstream = (*dnsOverTLS)(nil)

// newDoT returns the DNS-over-TLS Upstream.
func newDoT(u *url.URL, opts *Options) (ups Upstream, err error) {
	addPort(u, defaultPortDoT)

	boot, err := urlToBoot(u, opts)
	if err != nil {
		return nil, fmt.Errorf("creating tls bootstrapper: %w", err)
	}

	ups = &dnsOverTLS{
		boot: boot,
	}

	runtime.SetFinalizer(ups, (*dnsOverTLS).Close)

	return ups, nil
}

// Address implements the [Upstream] interface for *dnsOverTLS.
func (p *dnsOverTLS) Address() string { return p.boot.URL.String() }

// Exchange implements the [Upstream] interface for *dnsOverTLS.
func (p *dnsOverTLS) Exchange(m *dns.Msg) (reply *dns.Msg, err error) {
	conn, err := p.conn()
	if err != nil {
		return nil, fmt.Errorf("getting conn to %s: %w", p.Address(), err)
	}

	reply, err = p.exchangeWithConn(conn, m)
	if err != nil {
		// The pooled connection might have been closed already, see
		// https://github.com/AdguardTeam/dnsproxy/issues/3.  The following
		// connection from pool may also be malformed, so dial a new one.

		err = errors.WithDeferred(err, conn.Close())
		log.Debug("dot upstream: bad conn from pool: %s", err)

		// Retry.
		conn, err = p.dial()
		if err != nil {
			return nil, fmt.Errorf("dialing conn to %s: %w", p.Address(), err)
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

	if len(closeErrs) > 0 {
		return errors.List("closing tls conns", closeErrs...)
	}

	return nil
}

// conn returns the first available connection from the pool if there is any, or
// dials a new one otherwise.
func (p *dnsOverTLS) conn() (conn net.Conn, err error) {
	// Dial a new connection outside the lock, if needed.
	defer func() {
		if conn == nil {
			conn, err = p.dial()
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

	logBegin(addr, m)
	defer func() { logFinish(addr, err) }()

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

// dial dials a new connection that may be stored in pool.
func (p *dnsOverTLS) dial() (conn net.Conn, err error) {
	tlsConfig, dialContext, err := p.boot.get()
	if err != nil {
		return nil, err
	}

	conn, err = tlsDial(dialContext, "tcp", tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", tlsConfig.ServerName, err)
	}

	return conn, nil
}

// tlsDial is basically the same as tls.DialWithDialer, but we will call our own
// dialContext function to get connection.
func tlsDial(dialContext dialHandler, network string, config *tls.Config) (*tls.Conn, error) {
	// We're using bootstrapped address instead of what's passed to the
	// function.
	rawConn, err := dialContext(context.Background(), network, "")
	if err != nil {
		return nil, err
	}

	// We want the timeout to cover the whole process: TCP connection and
	// TLS handshake dialTimeout will be used as connection deadLine.
	conn := tls.Client(rawConn, config)
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
