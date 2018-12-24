package upstream

import (
	"crypto/tls"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/joomcode/errorx"
)

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
	address, tlsConfig, err := n.boot.get()
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
		log.Debugf("Returning existing connection to %s", address)
		return c, nil
	}

	// we'll need a new connection, dial now
	log.Debugf("Dialing to %s", address)

	conn, err := tlsDial("tcp", address, tlsConfig)
	if err != nil {
		return nil, errorx.Decorate(err, "Failed to connect to %s", address)
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

// tlsDial is basically the same as tls.Dial, but with timeout
func tlsDial(network, addr string, config *tls.Config) (*tls.Conn, error) {
	dialer := new(net.Dialer)
	dialer.Timeout = Timeout
	return tls.DialWithDialer(dialer, network, addr, config)
}
