package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
)

// dialTimeout is the global timeout for establishing a TLS connection.
// TODO(ameshkov): use bootstrap timeout instead.
const dialTimeout = 10 * time.Second

// TLSPool is a connections pool for the DNS-over-TLS Upstream.
//
// Example:
//
//	pool := TLSPool{Address: "tls://1.1.1.1:853"}
//	netConn, err := pool.Get()
//	if err != nil {panic(err)}
//	c := dns.Conn{Conn: netConn}
//	q := dns.Msg{}
//	q.SetQuestion("google.com.", dns.TypeA)
//	log.Println(q)
//	err = c.WriteMsg(&q)
//	if err != nil {panic(err)}
//	r, err := c.ReadMsg()
//	if err != nil {panic(err)}
//	log.Println(r)
//	pool.Put(c.Conn)
type TLSPool struct {
	boot *bootstrapper

	// conns is the list of connections available in the pool.
	conns   []net.Conn
	connsMu sync.Mutex
}

// type check
var _ io.Closer = (*TLSPool)(nil)

// Get gets a connection from the pool (if there's one available) or creates
// a new TLS connection.
func (n *TLSPool) Get() (conn net.Conn, err error) {
	// Get the connection from the slice inside the lock.
	n.connsMu.Lock()
	num := len(n.conns)
	if num > 0 {
		last := num - 1
		conn = n.conns[last]
		n.conns = n.conns[:last]
	}
	n.connsMu.Unlock()

	// If we got connection from the slice, update deadline and return it.
	if conn != nil {
		err = conn.SetDeadline(time.Now().Add(dialTimeout))

		// If deadLine can't be updated it means that connection was already closed
		if err == nil {
			log.Tracef(
				"Returning existing connection to %s with updated deadLine",
				conn.RemoteAddr(),
			)

			return conn, nil
		}
	}

	return n.Create()
}

// Create creates a new connection for the pool (but not puts it there).
func (n *TLSPool) Create() (conn net.Conn, err error) {
	tlsConfig, dialContext, err := n.boot.get()
	if err != nil {
		return nil, err
	}

	conn, err = tlsDial(dialContext, "tcp", tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", tlsConfig.ServerName, err)
	}

	return conn, nil
}

// Put returns the connection to the pool.
func (n *TLSPool) Put(conn net.Conn) {
	if conn == nil {
		return
	}

	n.connsMu.Lock()
	defer n.connsMu.Unlock()

	n.conns = append(n.conns, conn)
}

// Close implements io.Closer for *TLSPool.
func (n *TLSPool) Close() (err error) {
	n.connsMu.Lock()
	defer n.connsMu.Unlock()

	var closeErrs []error
	for _, c := range n.conns {
		cErr := c.Close()
		if cErr != nil {
			closeErrs = append(closeErrs, cErr)
		}
	}

	if len(closeErrs) > 0 {
		return errors.List("failed to close some connections", closeErrs...)
	}

	return nil
}

// tlsDial is basically the same as tls.DialWithDialer, but we will call our own
// dialContext function to get connection.
func tlsDial(dialContext dialHandler, network string, config *tls.Config) (*tls.Conn, error) {
	// We're using bootstrapped address instead of what's passed
	// to the function.
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
		panic(fmt.Errorf("cannot set deadline: %w", err))
	}

	err = conn.Handshake()
	if err != nil {
		return nil, errors.WithDeferred(err, conn.Close())
	}

	return conn, nil
}
