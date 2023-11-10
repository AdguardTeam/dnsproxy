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

// network is the semantic type alias of the network to pass to dialing
// functions.  It's either [networkUDP] or [networkTCP].  It may also be used as
// URL scheme for plain upstreams.
type network = string

const (
	// networkUDP is the UDP network.
	networkUDP network = "udp"

	// networkTCP is the TCP network.
	networkTCP network = "tcp"
)

// plainDNS implements the [Upstream] interface for the regular DNS protocol.
type plainDNS struct {
	// addr is the DNS server URL.  Scheme is always "udp" or "tcp".
	addr *url.URL

	// getDialer either returns an initialized dial handler or creates a new
	// one.
	getDialer DialerInitializer

	// net is the network of the connections.
	net network

	// timeout is the timeout for DNS requests.
	timeout time.Duration
}

// newPlain returns the plain DNS Upstream.  addr.Scheme should be either "udp"
// or "tcp".
func newPlain(addr *url.URL, opts *Options) (u *plainDNS, err error) {
	switch addr.Scheme {
	case networkUDP, networkTCP:
		// Go on.
	default:
		return nil, fmt.Errorf("unsupported url scheme: %s", addr.Scheme)
	}

	addPort(addr, defaultPortPlain)

	return &plainDNS{
		addr:      addr,
		getDialer: newDialerInitializer(addr, opts),
		net:       addr.Scheme,
		timeout:   opts.Timeout,
	}, nil
}

// type check
var _ Upstream = &plainDNS{}

// Address implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Address() string {
	switch p.net {
	case networkUDP:
		return p.addr.Host
	case networkTCP:
		return p.addr.String()
	default:
		panic(fmt.Sprintf("unexpected network: %s", p.net))
	}
}

// dialExchange performs a DNS exchange with the specified dial handler.
// network must be either [networkUDP] or [networkTCP].
func (p *plainDNS) dialExchange(
	network network,
	dial bootstrap.DialHandler,
	req *dns.Msg,
) (resp *dns.Msg, err error) {
	addr := p.Address()
	client := &dns.Client{Timeout: p.timeout}

	conn := &dns.Conn{}
	if network == networkUDP {
		conn.UDPSize = dns.MinMsgSize
	}

	logBegin(addr, network, req)
	defer func() { logFinish(addr, network, err) }()

	ctx := context.Background()
	conn.Conn, err = dial(ctx, network, "")
	if err != nil {
		return nil, fmt.Errorf("dialing %s over %s: %w", p.addr.Host, network, err)
	}
	defer func(c net.Conn) { err = errors.WithDeferred(err, c.Close()) }(conn.Conn)

	resp, _, err = client.ExchangeWithConn(req, conn)
	if isExpectedConnErr(err) {
		conn.Conn, err = dial(ctx, network, "")
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
	dial, err := p.getDialer()
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return nil, err
	}

	addr := p.Address()

	resp, err = p.dialExchange(p.net, dial, req)
	if p.net != networkUDP {
		// The network is already TCP.
		return resp, err
	}

	if resp == nil {
		// There is likely an error with the upstream.
		return resp, err
	}

	if errors.Is(err, errQuestion) {
		// The upstream responds with malformed messages, so try TCP.
		log.Debug("plain %s: %s, using tcp", addr, err)

		return p.dialExchange(networkTCP, dial, req)
	} else if resp.Truncated {
		// Fallback to TCP on truncated responses.
		log.Debug("plain %s: resp for %s is truncated, using tcp", &req.Question[0], addr)

		return p.dialExchange(networkTCP, dial, req)
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
