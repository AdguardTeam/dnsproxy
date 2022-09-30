package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
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
	conns []*connAndStore
	// connsMutex protects conns.
	connsMutex sync.Mutex
}

// connAndStore is a sturct that assigns a store for out-of-order responses to each connection.
// We need this to process multiple queries through a single upstream (cf. PR #269).
type connAndStore struct {
	conn       net.Conn
	store      map[uint16]*dns.Msg // needed to save out-of-order responses when reusing the connection
	sync.Mutex                     // protects store
}

// Get gets a connection from the pool (if there's one available) or creates
// a new TLS connection.
func (n *TLSPool) Get() (*connAndStore, error) {
	// Get the connection from the slice inside the lock.
	var c *connAndStore
	n.connsMutex.Lock()
	num := len(n.conns)
	if num > 0 {
		last := num - 1
		c = n.conns[last]
		n.conns = n.conns[:last]
	}
	n.connsMutex.Unlock()

	// If we got connection from the slice, update deadline and return it.
	if c != nil {
		err := c.conn.SetDeadline(time.Now().Add(dialTimeout))

		// If deadLine can't be updated it means that connection was already closed
		if err == nil {
			log.Tracef("Returning existing connection to %s with updated deadLine", c.conn.RemoteAddr())
			return c, nil
		}
	}

	return n.Create()
}

// Create creates a new connection for the pool (but not puts it there).
func (n *TLSPool) Create() (*connAndStore, error) {
	tlsConfig, dialContext, err := n.boot.get()
	if err != nil {
		return nil, err
	}

	// we'll need a new connection, dial now
	conn, err := tlsDial(dialContext, "tcp", tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", tlsConfig.ServerName, err)
	}

	// initialize the store
	store := make(map[uint16]*dns.Msg)

	return &connAndStore{conn: conn, store: store}, nil
}

// Put returns the connection to the pool.
func (n *TLSPool) Put(c *connAndStore) {
	if c == nil {
		return
	}
	n.connsMutex.Lock()
	n.conns = append(n.conns, c)
	n.connsMutex.Unlock()
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
