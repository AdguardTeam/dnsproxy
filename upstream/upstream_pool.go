package upstream

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/hmage/golibs/log"
)

const dialTimeout = 10 * time.Second

// TLSPool is a connections pool for the DNS-over-TLS Upstream.
//
// Example:
//  pool := TLSPool{Address: "tls://1.1.1.1:853"}
//  netConn, err := pool.Get()
//  if err != nil {panic(err)}
//  c := dns.Conn{Conn: netConn}
//  q := dns.Msg{}
//  q.SetQuestion("google.com.", dns.TypeA)
//  log.Println(q)
//  err = c.WriteMsg(&q)
//  if err != nil {panic(err)}
//  r, err := c.ReadMsg()
//  if err != nil {panic(err)}
//  log.Println(r)
//  pool.Put(c.Conn)
type TLSPool struct {
	boot *bootstrapper

	// connections
	conns      []net.Conn
	connsMutex sync.Mutex // protects conns
}

// Get gets or creates a new TLS connection
func (n *TLSPool) Get() (net.Conn, error) {
	_, _, err := n.boot.get()
	address := "fake_address"
	if err != nil {
		return nil, err
	}

	// get the connection from the slice inside the lock
	var c net.Conn
	n.connsMutex.Lock()
	num := len(n.conns)
	if num > 0 {
		last := num - 1
		c = n.conns[last]
		n.conns = n.conns[:last]
	}
	n.connsMutex.Unlock()

	// if we got connection from the slice, return it
	if c != nil {
		log.Tracef("Returning existing connection to %s", address)
		return c, nil
	}

	return n.Create()
}

// Create creates a new connection for the pool (but not puts it there)
func (n *TLSPool) Create() (net.Conn, error) {
	tlsConfig, dialContext, err := n.boot.get()

	if err != nil {
		return nil, err
	}

	// we'll need a new connection, dial now
	conn, err := tlsDial(dialContext, "tcp", tlsConfig)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Put returns connection to the pool
func (n *TLSPool) Put(c net.Conn) {
	if c == nil {
		return
	}
	n.connsMutex.Lock()
	n.conns = append(n.conns, c)
	n.connsMutex.Unlock()
}

// tlsDial is basically the same as tls.DialWithDialer, but we will call our own dialContext function to get connection
func tlsDial(dialContext func(ctx context.Context, network, addr string) (net.Conn, error), network string, config *tls.Config) (*tls.Conn, error) {
	// We want the timeout to cover the whole process:
	// TCP connection and TLS handshake. This means that we also need to start our own timers now.
	timeout := dialTimeout

	var errChannel chan error

	errChannel = make(chan error, 2)
	time.AfterFunc(timeout, func() {
		errChannel <- timeoutError{}
	})

	// important to avoid a resource leak
	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()

	// we're using bootstrapped address instead of what's passed to the function
	rawConn, err := dialContext(ctx, network, "")
	if err != nil {
		return nil, err
	}

	conn := tls.Client(rawConn, config)

	go func() {
		errChannel <- conn.Handshake()
	}()

	err = <-errChannel

	if err != nil {
		rawConn.Close()
		return nil, err
	}

	return conn, nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "upstream_pool: tlsDial timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
