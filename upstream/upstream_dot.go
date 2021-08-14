package upstream

import (
	"net"
	"sync"

	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

//
// DNS-over-TLS
//
type dnsOverTLS struct {
	boot *bootstrapper
	pool *TLSPool

	sync.RWMutex // protects pool
}

// type check
var _ Upstream = &dnsOverTLS{}

func (p *dnsOverTLS) Address() string { return p.boot.URL.String() }

func (p *dnsOverTLS) Exchange(m *dns.Msg) (*dns.Msg, error) {
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
	p.RUnlock()
	if err != nil {
		return nil, errorx.Decorate(err, "Failed to get a connection from TLSPool to %s", p.Address())
	}

	logBegin(p.Address(), m)
	reply, err := p.exchangeConn(poolConn, m)
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
			return nil, errorx.Decorate(err, "Failed to create a new connection from TLSPool to %s", p.Address())
		}

		// Retry sending the DNS request
		logBegin(p.Address(), m)
		reply, err = p.exchangeConn(poolConn, m)
		logFinish(p.Address(), err)
	}

	if err == nil {
		p.RLock()
		p.pool.Put(poolConn)
		p.RUnlock()
	}
	return reply, err
}

func (p *dnsOverTLS) exchangeConn(poolConn net.Conn, m *dns.Msg) (*dns.Msg, error) {
	c := dns.Conn{Conn: poolConn}
	err := c.WriteMsg(m)
	if err != nil {
		poolConn.Close()
		return nil, errorx.Decorate(err, "Failed to send a request to %s", p.Address())
	}

	reply, err := c.ReadMsg()
	if err != nil {
		poolConn.Close()
		return nil, errorx.Decorate(err, "Failed to read a request from %s", p.Address())
	} else if reply.Id != m.Id {
		err = dns.ErrId
	}

	return reply, err
}
