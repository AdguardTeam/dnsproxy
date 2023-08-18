package upstream

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
)

// dnsCrypt implements the [Upstream] interface for the DNSCrypt protocol.
type dnsCrypt struct {
	// mu protects client and serverInfo.
	mu *sync.RWMutex

	// client stores the DNSCrypt client properties.
	client *dnscrypt.Client

	// resolverInfo stores the DNSCrypt server properties.
	resolverInfo *dnscrypt.ResolverInfo

	// addr is the DNSCrypt server URL.
	addr *url.URL

	// verifyCert is a callback that verifies the resolver's certificate.
	verifyCert func(cert *dnscrypt.Cert) (err error)

	// timeout is the timeout for the DNS requests.
	timeout time.Duration
}

// newDNSCrypt returns a new DNSCrypt Upstream.
func newDNSCrypt(addr *url.URL, opts *Options) (u *dnsCrypt) {
	return &dnsCrypt{
		mu:         &sync.RWMutex{},
		addr:       addr,
		verifyCert: opts.VerifyDNSCryptCertificate,
		timeout:    opts.Timeout,
	}
}

// type check
var _ Upstream = (*dnsCrypt)(nil)

// Address implements the [Upstream] interface for *dnsCrypt.
func (p *dnsCrypt) Address() string { return p.addr.String() }

// Exchange implements the [Upstream] interface for *dnsCrypt.
func (p *dnsCrypt) Exchange(m *dns.Msg) (resp *dns.Msg, err error) {
	resp, err = p.exchangeDNSCrypt(m)
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, io.EOF) {
		// If request times out, it is possible that the server configuration
		// has been changed.  It is safe to assume that the key was rotated, see
		// https://dnscrypt.pl/2017/02/26/how-key-rotation-is-automated.
		// Re-fetch the server certificate info for new requests to not fail.
		_, _, err = p.resetClient()
		if err != nil {
			return nil, err
		}

		return p.exchangeDNSCrypt(m)
	}

	return resp, err
}

// Close implements the [Upstream] interface for *dnsCrypt.
func (p *dnsCrypt) Close() (err error) {
	return nil
}

// exchangeDNSCrypt attempts to send the DNS query and returns the response.
func (p *dnsCrypt) exchangeDNSCrypt(m *dns.Msg) (resp *dns.Msg, err error) {
	var client *dnscrypt.Client
	var resolverInfo *dnscrypt.ResolverInfo
	func() {
		p.mu.RLock()
		defer p.mu.RUnlock()

		client, resolverInfo = p.client, p.resolverInfo
	}()

	// Check the client and server info are set and the certificate is not
	// expired, since any of these cases require a client reset.
	//
	// TODO(ameshkov):  Consider using [time.Time] for [dnscrypt.Cert.NotAfter].
	switch {
	case
		client == nil,
		resolverInfo == nil,
		resolverInfo.ResolverCert.NotAfter < uint32(time.Now().Unix()):
		client, resolverInfo, err = p.resetClient()
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return nil, err
		}
	default:
		// Go on.
	}

	resp, err = client.Exchange(m, resolverInfo)
	if resp != nil && resp.Truncated {
		q := &m.Question[0]
		log.Debug("dnscrypt %s: received truncated, falling back to tcp with %s", p.addr, q)

		tcpClient := &dnscrypt.Client{Timeout: p.timeout, Net: networkTCP}
		resp, err = tcpClient.Exchange(m, resolverInfo)
	}
	if err == nil && resp != nil && resp.Id != m.Id {
		err = dns.ErrId
	}

	return resp, err
}

// resetClient renews the DNSCrypt client and server properties and also sets
// those to nil on fail.
func (p *dnsCrypt) resetClient() (client *dnscrypt.Client, ri *dnscrypt.ResolverInfo, err error) {
	addr := p.Address()

	defer func() {
		p.mu.Lock()
		defer p.mu.Unlock()

		p.client, p.resolverInfo = client, ri
	}()

	// Use UDP for DNSCrypt upstreams by default.
	client = &dnscrypt.Client{Timeout: p.timeout, Net: networkUDP}
	ri, err = client.Dial(addr)
	if err != nil {
		// Trigger client and server info renewal on the next request.
		client, ri = nil, nil
		err = fmt.Errorf("fetching certificate info from %s: %w", addr, err)
	} else if p.verifyCert != nil {
		err = p.verifyCert(ri.ResolverCert)
		if err != nil {
			// Trigger client and server info renewal on the next request.
			client, ri = nil, nil
			err = fmt.Errorf("verifying certificate info from %s: %w", addr, err)
		}
	}

	return client, ri, err
}
