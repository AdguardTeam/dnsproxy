package upstream

import (
	"fmt"
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
	poolConnAndStore, err := p.pool.Get()
	// Put the connection right back in to allow the connection to be reused while requests are in flight
	p.pool.Put(poolConnAndStore)
	p.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("getting connection to %s: %w", p.Address(), err)
	}

	logBegin(p.Address(), m)
	reply, err = p.exchangeConn(poolConnAndStore, m)
	logFinish(p.Address(), err)
	if err != nil {
		log.Tracef("The TLS connection is expired due to %s", err)

		// The pooled connection might have been closed already (see https://github.com/AdguardTeam/dnsproxy/issues/3)
		// So we're trying to re-connect right away here.
		// We are forcing creation of a new connection instead of calling Get() again
		// as there's no guarantee that other pooled connections are intact
		p.RLock()
		poolConnAndStore, err = p.pool.Create()
		p.RUnlock()
		if err != nil {
			return nil, fmt.Errorf("creating new connection to %s: %w", p.Address(), err)
		}

		// Retry sending the DNS request
		logBegin(p.Address(), m)
		reply, err = p.exchangeConn(poolConnAndStore, m)
		logFinish(p.Address(), err)
	}

	return reply, err
}

func (p *dnsOverTLS) exchangeConn(connAndStore *connAndStore, m *dns.Msg) (reply *dns.Msg, err error) {
	defer func() {
		if err == nil {
			return
		}

		if cerr := connAndStore.conn.Close(); cerr != nil {
			err = &errors.Pair{Returned: err, Deferred: cerr}
		}
	}()

	dnsConn := dns.Conn{Conn: connAndStore.conn}

	err = dnsConn.WriteMsg(m)
	if err != nil {
		return nil, fmt.Errorf("sending request to %s: %w", p.Address(), err)
	}

	// Since we might receive out-of-order responses when processing multiple queries through a single upstream (cf.
	// PR #269), we will store all responses that don't match our DNS ID and retry until we find the response we are
	// looking for (either by receiving it directly or by finding it in the stored responses).
	responseFound := false
	present := false
	for !responseFound {
		connAndStore.Lock()

		// has someone already received our response?
		reply, present = connAndStore.store[m.Id]
		if present { // matching response in store
			log.Tracef("Found matching ID in store for request %d", m.Id)
			delete(connAndStore.store, m.Id) // delete response from store
			responseFound = true
		} else { // no matching response in store
			reply, err = dnsConn.ReadMsg()
			if err != nil {
				connAndStore.Unlock()
				return nil, fmt.Errorf("reading response from %s: %w", p.Address(), err)
			} else if reply.Id != m.Id {
				// not the response we were looking for -> store it in the store
				log.Tracef("Received unknown ID %d, storing in store for later use", reply.Id)
				connAndStore.store[reply.Id] = reply
			} else {
				responseFound = true
			}
		}
		connAndStore.Unlock()

		// yield to scheduler if we added something to the store
		if !responseFound {
			runtime.Gosched()
		}
	}

	// Match response QNAME, QCLASS, and QTYPE to query according to RFC 7766
	// (https://www.rfc-editor.org/rfc/rfc7766#section-7)
	if len(reply.Question) != 0 && len(m.Question) != 0 {
		if reply.Question[0].Name != m.Question[0].Name {
			err = fmt.Errorf("Query and response QNAME do not match; received %s, expected %s", reply.Question[0].Name, m.Question[0].Name)
			return reply, err
		}
		if reply.Question[0].Qtype != m.Question[0].Qtype {
			err = fmt.Errorf("Query and response QTYPE do not match; received %d, expected %d", reply.Question[0].Qtype, m.Question[0].Qtype)
			return reply, err
		}
		if reply.Question[0].Qclass != m.Question[0].Qclass {
			err = fmt.Errorf("Query and response QCLASS do not match; received %d, expected %d", reply.Question[0].Qclass, m.Question[0].Qclass)
			return reply, err
		}
	}

	return reply, err
}
