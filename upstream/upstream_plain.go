package upstream

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// plainDNS implements the [Upstream] interface for the regular DNS protocol.
type plainDNS struct {
	// addr is the DNS server URL.  Scheme is always "udp" or "tcp".
	addr *url.URL

	// getDialer either returns an initialized dial handler or creates a new
	// one.
	getDialer DialerInitializer

	// timeout is the timeout for DNS requests.
	timeout time.Duration
}

// type check
var _ Upstream = &plainDNS{}

// newPlain returns the plain DNS Upstream.
func newPlain(addr *url.URL, opts *Options) (u *plainDNS, err error) {
	addPort(addr, defaultPortPlain)

	getDialer, err := newDialerInitializer(addr, opts)
	if err != nil {
		return nil, err
	}

	return &plainDNS{
		addr:      addr,
		getDialer: getDialer,
		timeout:   opts.Timeout,
	}, nil
}

// Address implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Address() string {
	if p.addr.Scheme == "udp" {
		return p.addr.Host
	}

	return p.addr.String()
}

// dialExchange performs a DNS exchange with the specified dial handler.
// network must be either "udp" or "tcp".
func (p *plainDNS) dialExchange(
	network string,
	dial bootstrap.DialHandler,
	m *dns.Msg,
) (resp *dns.Msg, err error) {
	addr := p.Address()
	client := &dns.Client{Timeout: p.timeout}

	conn := &dns.Conn{}
	if network == "udp" {
		conn.UDPSize = dns.MinMsgSize
	}

	logBegin(addr, m)
	conn.Conn, err = dial(context.Background(), network, "")
	if err != nil {
		logFinish(addr, err)

		return nil, fmt.Errorf("dialing %s over %s: %w", p.addr.Host, network, err)
	}

	resp, _, err = client.ExchangeWithConn(m, conn)
	logFinish(addr, err)

	return resp, err
}

// Exchange implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Exchange(m *dns.Msg) (resp *dns.Msg, err error) {
	dial, err := p.getDialer()
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return nil, err
	}

	addr := p.Address()

	resp, err = p.dialExchange(p.addr.Scheme, dial, m)
	if p.addr.Scheme == "udp" {
		if resp == nil || !resp.Truncated {
			return resp, err
		}

		log.Debug("plain %s: received truncated, falling back to tcp with %s", addr, &m.Question[0])

		resp, err = p.dialExchange("tcp", dial, m)
	}

	return resp, err
}

// Close implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Close() (err error) {
	return nil
}
