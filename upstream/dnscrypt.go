package upstream

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/AdguardTeam/dnscrypt"
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

	// logger is used for exchange logging.  It is never nil.
	logger *slog.Logger

	// verifyCert is a callback that verifies the resolver's certificate.
	verifyCert func(cert *dnscrypt.Certificate) (err error)

	// timeout is the timeout for the DNS requests.
	timeout time.Duration
}

// newDNSCrypt returns a new DNSCrypt Upstream.
func newDNSCrypt(addr *url.URL, opts *Options) (u *dnsCrypt) {
	return &dnsCrypt{
		mu:         &sync.RWMutex{},
		addr:       addr,
		logger:     opts.Logger,
		verifyCert: opts.VerifyDNSCryptCertificate,
		timeout:    opts.Timeout,
	}
}

// type check
var _ Upstream = (*dnsCrypt)(nil)

// Address implements the [Upstream] interface for *dnsCrypt.
func (p *dnsCrypt) Address() string { return p.addr.String() }

// Exchange implements the [Upstream] interface for *dnsCrypt.
func (p *dnsCrypt) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	ctx := context.Background()
	if p.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}

	// Don't wrap the error, because it's informative enough as is.
	return p.exchangeDNSCrypt(ctx, req)
}

// Close implements the [Upstream] interface for *dnsCrypt.
func (p *dnsCrypt) Close() (err error) {
	return nil
}

// exchangeDNSCrypt attempts to send the DNS query and returns the response.
func (p *dnsCrypt) exchangeDNSCrypt(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
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
	// TODO(a.garipov): Consider using [time.Time] for [dnscrypt.Cert.NotAfter].
	switch {
	case
		client == nil,
		resolverInfo == nil,
		resolverInfo.ResolverCert.NotAfter < uint32(time.Now().Unix()):
		client, resolverInfo, err = p.resetClient(ctx)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return nil, err
		}
	default:
		// Go on.
	}

	resp, err = client.ExchangeContext(ctx, req, resolverInfo)
	if resp != nil && resp.Truncated {
		q := &req.Question[0]
		p.logger.Debug(
			"dnscrypt received truncated, falling back to tcp",
			"addr", p.addr,
			"question", q,
		)

		tcpClient := dnscrypt.NewClient(&dnscrypt.ClientConfig{
			Logger: p.logger,
			Proto:  dnscrypt.ProtoTCP,
		})

		resp, err = tcpClient.ExchangeContext(ctx, req, resolverInfo)
	}
	if err == nil && resp != nil && resp.Id != req.Id {
		err = dns.ErrId
	}

	return resp, err
}

// resetClient renews the DNSCrypt client and server properties and also sets
// those to nil on fail.
func (p *dnsCrypt) resetClient(
	ctx context.Context,
) (client *dnscrypt.Client, ri *dnscrypt.ResolverInfo, err error) {
	addr := p.Address()

	defer func() {
		p.mu.Lock()
		defer p.mu.Unlock()

		p.client, p.resolverInfo = client, ri
	}()

	// Use UDP for DNSCrypt upstreams by default.
	client = dnscrypt.NewClient(&dnscrypt.ClientConfig{
		Logger: p.logger,
		Proto:  dnscrypt.ProtoUDP,
	})
	ri, err = client.DialContext(ctx, addr)
	if err != nil {
		// Trigger client and server info renewal on the next request.
		return nil, nil, fmt.Errorf("fetching certificate info from %s: %w", addr, err)
	}

	if p.verifyCert == nil {
		// Go on.
		return client, ri, nil
	}

	err = p.verifyCert(ri.ResolverCert)
	if err != nil {
		// Trigger client and server info renewal on the next request.
		return nil, nil, fmt.Errorf("verifying certificate info from %s: %w", addr, err)
	}

	return client, ri, nil
}
