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

	// if we got connection from the slice, update deadline and return it.
	if c != nil {
		err = c.SetDeadline(time.Now().Add(dialTimeout))

		// If deadLine can't be updated it means that connection was already closed
		if err == nil {
			log.Tracef("Returning existing connection to %s with updated deadLine", c.RemoteAddr())
			return c, nil
		}
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
func tlsDial(dialContext dialHandler, network string, config *tls.Config) (*tls.Conn, error) {
	ctx := context.TODO()

	// we're using bootstrapped address instead of what's passed to the function
	rawConn, err := dialContext(ctx, network, "")
	if err != nil {
		return nil, err
	}

	// we want the timeout to cover the whole process: TCP connection and TLS handshake
	// dialTimeout will be used as connection deadLine
	conn := tls.Client(rawConn, config)
	err = conn.SetDeadline(time.Now().Add(dialTimeout))
	if err != nil {
		log.Printf("DeadLine is not supported cause: %s", err)
		conn.Close()
		return nil, err
	}

	err = conn.Handshake()
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}
