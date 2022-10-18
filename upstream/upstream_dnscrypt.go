package upstream

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
)

// dnsCrypt is a struct that implements the Upstream interface for the DNSCrypt
// protocol.
type dnsCrypt struct {
	boot       *bootstrapper
	client     *dnscrypt.Client       // DNSCrypt client properties
	serverInfo *dnscrypt.ResolverInfo // DNSCrypt resolver info

	sync.RWMutex // protects DNSCrypt client
}

// type check
var _ Upstream = (*dnsCrypt)(nil)

// Address implements the Upstream interface for *dnsCrypt.
func (p *dnsCrypt) Address() string { return p.boot.URL.String() }

// Exchange implements the Upstream interface for *dnsCrypt.
func (p *dnsCrypt) Exchange(m *dns.Msg) (*dns.Msg, error) {
	reply, err := p.exchangeDNSCrypt(m)

	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, io.EOF) {
		// If request times out, it is possible that the server configuration has been changed.
		// It is safe to assume that the key was rotated (for instance, as it is described here: https://dnscrypt.pl/2017/02/26/how-key-rotation-is-automated/).
		// We should re-fetch the server certificate info so that the new requests were not failing.
		p.Lock()
		p.client = nil
		p.serverInfo = nil
		p.Unlock()

		// Retry the request one more time
		return p.exchangeDNSCrypt(m)
	}

	return reply, err
}

// Close implements the Upstream interface for *dnsCrypt.
func (p *dnsCrypt) Close() (err error) {
	// Nothing to close here.
	return nil
}

// exchangeDNSCrypt attempts to send the DNS query and returns the response
func (p *dnsCrypt) exchangeDNSCrypt(m *dns.Msg) (reply *dns.Msg, err error) {
	p.RLock()
	client := p.client
	resolverInfo := p.serverInfo
	p.RUnlock()

	now := uint32(time.Now().Unix())
	if client == nil || resolverInfo == nil || resolverInfo.ResolverCert.NotAfter < now {
		client, resolverInfo, err = p.resetClient()
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return nil, err
		}
	}

	reply, err = client.Exchange(m, resolverInfo)
	if reply != nil && reply.Truncated {
		log.Tracef("truncated message received, retrying over tcp, question: %v", m.Question[0])
		tcpClient := dnscrypt.Client{Timeout: p.boot.options.Timeout, Net: "tcp"}
		reply, err = tcpClient.Exchange(m, resolverInfo)
	}
	if err == nil && reply != nil && reply.Id != m.Id {
		err = dns.ErrId
	}

	return reply, err
}

func (p *dnsCrypt) resetClient() (client *dnscrypt.Client, ri *dnscrypt.ResolverInfo, err error) {
	p.Lock()
	defer p.Unlock()

	// Using "udp" for DNSCrypt upstreams by default.
	client = &dnscrypt.Client{Timeout: p.boot.options.Timeout, Net: "udp"}
	ri, err = client.Dial(p.Address())
	if err != nil {
		return nil, nil, fmt.Errorf("fetching certificate info from %s: %w", p.Address(), err)
	}

	if p.boot.options.VerifyDNSCryptCertificate != nil {
		err = p.boot.options.VerifyDNSCryptCertificate(ri.ResolverCert)
		if err != nil {
			return nil, nil, fmt.Errorf("verifying certificate info from %s: %w", p.Address(), err)
		}
	}

	p.client = client
	p.serverInfo = ri

	return client, ri, nil
}
