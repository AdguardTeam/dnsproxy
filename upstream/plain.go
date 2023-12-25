package upstream

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// plainDNS implements the [Upstream] interface for the regular DNS protocol.
type plainDNS struct {
	// addr is the DNS server URL.  Scheme is always either
	// [bootstrap.NetworkUDP] or [bootstrap.NetworkTCP].
	addr *url.URL

	// boot dials the address of the upstream DNS server.
	boot bootstrap.Dialer

	// network is the network of the connections.
	network bootstrap.Network

	// timeout is the timeout for DNS requests.
	timeout time.Duration
}

// newPlain returns the plain DNS Upstream.  addr.Scheme should be either
// [bootstrap.NetworkUDP] or [bootstrap.NetworkTCP].
func newPlain(addr *url.URL, opts *Options) (u *plainDNS, err error) {
	switch addr.Scheme {
	case bootstrap.NetworkUDP, bootstrap.NetworkTCP:
		// Go on.
	default:
		return nil, fmt.Errorf("unsupported url scheme: %s", addr.Scheme)
	}

	addPort(addr, defaultPortPlain)

	boot, err := opts.bootstrap(addr)
	if err != nil {
		return nil, fmt.Errorf("creating bootstrap dialer: %w", err)
	}

	return &plainDNS{
		addr:    addr,
		boot:    boot,
		network: addr.Scheme,
		timeout: opts.Timeout,
	}, nil
}

// type check
var _ Upstream = &plainDNS{}

// Address implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Address() string {
	switch p.network {
	case bootstrap.NetworkUDP:
		return p.addr.Host
	case bootstrap.NetworkTCP:
		return p.addr.String()
	default:
		panic(fmt.Sprintf("unexpected network: %s", p.network))
	}
}

// dialExchange performs a DNS exchange with the specified dial handler.
// network must be either [bootstrap.NetworkUDP] or [bootstrap.NetworkTCP].
func (p *plainDNS) dialExchange(
	network bootstrap.Network,
	req *dns.Msg,
) (resp *dns.Msg, err error) {
	addr := p.Address()
	client := &dns.Client{Timeout: p.timeout}
	hostname := p.addr.Hostname()

	conn := &dns.Conn{}
	if network == bootstrap.NetworkUDP {
		conn.UDPSize = dns.MinMsgSize
	}

	logBegin(addr, network, req)
	defer func() { logFinish(addr, network, err) }()

	ctx := context.Background()
	conn.Conn, err = p.boot.DialContext(ctx, network, hostname)
	if err != nil {
		return nil, fmt.Errorf("dialing %s over %s: %w", p.addr.Host, network, err)
	}
	defer func(c net.Conn) { err = errors.WithDeferred(err, c.Close()) }(conn.Conn)

	resp, _, err = client.ExchangeWithConn(req, conn)
	if isExpectedConnErr(err) {
		conn.Conn, err = p.boot.DialContext(ctx, network, hostname)
		if err != nil {
			return nil, fmt.Errorf("dialing %s over %s again: %w", p.addr.Host, network, err)
		}
		defer func(c net.Conn) { err = errors.WithDeferred(err, c.Close()) }(conn.Conn)

		resp, _, err = client.ExchangeWithConn(req, conn)
	}

	if err != nil {
		return resp, fmt.Errorf("exchanging with %s over %s: %w", addr, network, err)
	}

	return resp, validatePlainResponse(req, resp)
}

// isExpectedConnErr returns true if the error is expected.  In this case,
// we will make a second attempt to process the request.
func isExpectedConnErr(err error) (is bool) {
	var netErr net.Error

	return err != nil && (errors.As(err, &netErr) || errors.Is(err, io.EOF))
}

// Exchange implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	resp, err = p.dialExchange(p.network, req)
	if p.network != bootstrap.NetworkUDP {
		// The network is already TCP.
		return resp, err
	}

	if resp == nil {
		// There is likely an error with the upstream.
		return resp, err
	}

	if errors.Is(err, errQuestion) {
		// The upstream responds with malformed messages, so try TCP.
		log.Debug("plain %s: %s, using tcp", p.Address(), err)

		return p.dialExchange(bootstrap.NetworkTCP, req)
	} else if resp.Truncated {
		// Fallback to TCP on truncated responses.
		log.Debug("plain %s: resp for %s is truncated, using tcp", &req.Question[0], p.Address())

		return p.dialExchange(bootstrap.NetworkTCP, req)
	}

	// There is either no error or the error isn't related to the received
	// message.
	return resp, err
}

// Close implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Close() (err error) {
	return nil
}

// errQuestion is returned when a message has malformed question section.
const errQuestion errors.Error = "bad question section"

// validatePlainResponse validates resp from an upstream DNS server for
// compliance with req.  Any error returned wraps [ErrQuestion], since it
// essentially validates the question section of resp.
func validatePlainResponse(req, resp *dns.Msg) (err error) {
	if qlen := len(resp.Question); qlen != 1 {
		return fmt.Errorf("%w: only 1 question allowed; got %d", errQuestion, qlen)
	}

	reqQ, respQ := req.Question[0], resp.Question[0]

	if reqQ.Qtype != respQ.Qtype {
		return fmt.Errorf("%w: mismatched type %s", errQuestion, dns.Type(respQ.Qtype))
	}

	// Compare the names case-insensitively, just like CoreDNS does.
	if !strings.EqualFold(reqQ.Name, respQ.Name) {
		return fmt.Errorf("%w: mismatched name %q", errQuestion, respQ.Name)
	}

	return nil
}
