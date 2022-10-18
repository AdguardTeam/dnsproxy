package upstream

import (
	"fmt"
	"net"
	"net/url"
	"runtime"
	"sync"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// dnsOverTLS is a struct that implements the Upstream interface for the
// DNS-over-TLS protocol.
type dnsOverTLS struct {
	boot   *bootstrapper
	pool   *TLSPool
	poolMu sync.Mutex
}

// type check
var _ Upstream = (*dnsOverTLS)(nil)

// newDoT returns the DNS-over-TLS Upstream.
func newDoT(uu *url.URL, opts *Options) (u Upstream, err error) {
	addPort(uu, defaultPortDoT)

	var b *bootstrapper
	b, err = urlToBoot(uu, opts)
	if err != nil {
		return nil, fmt.Errorf("creating tls bootstrapper: %w", err)
	}

	u = &dnsOverTLS{boot: b}

	runtime.SetFinalizer(u, (*dnsOverTLS).Close)

	return u, nil
}

// Address implements the Upstream interface for *dnsOverTLS.
func (p *dnsOverTLS) Address() string { return p.boot.URL.String() }

// Exchange implements the Upstream interface for *dnsOverTLS.
func (p *dnsOverTLS) Exchange(m *dns.Msg) (reply *dns.Msg, err error) {
	pool := p.getPool()

	poolConn, err := pool.Get()
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
		poolConn, err = pool.Create()
		if err != nil {
			return nil, fmt.Errorf("creating new connection to %s: %w", p.Address(), err)
		}

		// Retry sending the DNS request
		logBegin(p.Address(), m)
		reply, err = p.exchangeConn(poolConn, m)
		logFinish(p.Address(), err)
	}

	if err == nil {
		pool.Put(poolConn)
	}
	return reply, err
}

// Close implements the Upstream interface for *dnsOverTLS.
func (p *dnsOverTLS) Close() (err error) {
	p.poolMu.Lock()
	defer p.poolMu.Unlock()

	runtime.SetFinalizer(p, nil)

	if p.pool == nil {
		return nil
	}

	return p.pool.Close()
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

func (p *dnsOverTLS) getPool() (pool *TLSPool) {
	p.poolMu.Lock()
	defer p.poolMu.Unlock()

	if p.pool == nil {
		p.pool = &TLSPool{boot: p.boot}
	}

	return p.pool
}
