package upstream

import (
	"fmt"
	"net"
	"net/url"
	"sync"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// dnsOverTLS is a struct that implements the Upstream interface for the
// DNS-over-TLS protocol.
type dnsOverTLS struct {
	boot *bootstrapper
	pool *TLSPool

	sync.RWMutex // protects pool
}

// type check
var _ Upstream = &dnsOverTLS{}

// newDoT returns the DNS-over-TLS Upstream.
func newDoT(uu *url.URL, opts *Options) (u Upstream, err error) {
	addPort(uu, defaultPortDoT)

	var b *bootstrapper
	b, err = urlToBoot(uu, opts)
	if err != nil {
		return nil, fmt.Errorf("creating tls bootstrapper: %w", err)
	}

	return &dnsOverTLS{boot: b}, nil
}

// Address implements the Upstream interface for *dnsOverTLS.
func (p *dnsOverTLS) Address() string { return p.boot.URL.String() }

// Exchange implements the Upstream interface for *dnsOverTLS.
func (p *dnsOverTLS) Exchange(m *dns.Msg) (reply *dns.Msg, err error) {
	var pool *TLSPool
	p.RLock()
	pool = p.pool
	p.RUnlock()
	if pool == nil {
		p.Lock()
		// lazy initialize it
		p.pool = &TLSPool{boot: p.boot}
		p.Unlock()
	}

	p.RLock()
	poolConn, err := p.pool.Get()
	// Put the connection right back in to allow the connection to be reused while requests are in flight
	p.pool.Put(poolConn)
	p.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("getting connection to %s: %w", p.Address(), err)
	}

	logBegin(p.Address(), m)
	reply, err = p.exchangeConn(poolConn, m)
	logFinish(p.Address(), err)
	if err != nil {
		log.Tracef("The TLS connection is expired due to %s", err)

		// The pooled connection might have been closed already (see https://github.com/AdguardTeam/dnsproxy/issues/3)
		// So we're trying to re-connect right away here.
		// We are forcing creation of a new connection instead of calling Get() again
		// as there's no guarantee that other pooled connections are intact
		p.RLock()
		poolConn, err = p.pool.Create()
		p.RUnlock()
		if err != nil {
			return nil, fmt.Errorf("creating new connection to %s: %w", p.Address(), err)
		}

		// Retry sending the DNS request
		logBegin(p.Address(), m)
		reply, err = p.exchangeConn(poolConn, m)
		logFinish(p.Address(), err)
	}

	return reply, err
}

func (p *dnsOverTLS) exchangeConn(conn net.Conn, m *dns.Msg) (reply *dns.Msg, err error) {
	defer func() {
		if err == nil {
			return
		}

		if cerr := conn.Close(); cerr != nil {
			err = &errors.Pair{Returned: err, Deferred: cerr}
		}
	}()

	dnsConn := dns.Conn{Conn: conn}

	err = dnsConn.WriteMsg(m)
	if err != nil {
		return nil, fmt.Errorf("sending request to %s: %w", p.Address(), err)
	}

	reply, err = dnsConn.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", p.Address(), err)
	} else if reply.Id != m.Id {
		err = dns.ErrId
	}

	return reply, err
}
