package upstream

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// Resolver is an alias for bootstrap.Resolver to avoid the import cycle.
type Resolver = bootstrap.Resolver

// NewResolver creates a Resolver.  resolverAddress should be either a plain IP
// address or empty.  If it is empty, the default [net.Resolver] is used, and
// sorting the resolved addresses is the caller's responsibility.  Otherwise, it
// creates an Upstream using opts.
//
// TODO(e.burkov):  Require resolverAddress not being empty and rename into
// NewUpstreamResolver.
func NewResolver(resolverAddress string, opts *Options) (r Resolver, err error) {
	if resolverAddress == "" {
		return &net.Resolver{}, nil
	}

	upsOpts := &Options{
		// Avoid recursion in case the bootstrap resolver is not valid.
		Bootstrap: []string{""},
	}

	// TODO(ameshkov):  Aren't other options needed here?
	if opts != nil {
		upsOpts.Timeout = opts.Timeout
		upsOpts.VerifyServerCertificate = opts.VerifyServerCertificate
	}

	ur := upstreamResolver{}
	ur.Upstream, err = AddressToUpstream(resolverAddress, upsOpts)
	if err != nil {
		err = fmt.Errorf("creating upstream: %w", err)
		log.Error("upstream bootstrap: %s", err)

		return ur, err
	}

	if err = validateBootstrap(ur.Upstream); err != nil {
		log.Error("upstream bootstrap %s: %s", resolverAddress, err)

		ur.Upstream = nil

		return ur, err
	}

	return ur, err
}

// validateBootstrap returns error if the upstream is not eligible to be a
// bootstrap DNS server.  DNSCrypt is always okay.  Plain DNS, DNS-over-TLS,
// DNS-over-HTTPS, and DNS-over-QUIC are okay only if those are defined by IP.
func validateBootstrap(upstream Upstream) (err error) {
	switch upstream := upstream.(type) {
	case *dnsCrypt:
		return nil
	case *dnsOverTLS:
		_, err = netip.ParseAddr(upstream.addr.Hostname())
	case *dnsOverHTTPS:
		_, err = netip.ParseAddr(upstream.addr.Hostname())
	case *dnsOverQUIC:
		_, err = netip.ParseAddr(upstream.addr.Hostname())
	case *plainDNS:
		_, err = netip.ParseAddr(upstream.addr.Hostname())
	default:
		err = fmt.Errorf("unknown upstream type: %T", upstream)
	}

	return errors.Annotate(err, "bootstrap %s: %w", upstream.Address())
}

// upstreamResolver is a wrapper around Upstream that implements the
// [bootstrap.Resolver] interface.  It sorts the resolved addresses preferring
// IPv4.
type upstreamResolver struct {
	// Upstream is embedded here to avoid implementing another Upstream's
	// methods.
	Upstream
}

// type check
var _ Resolver = upstreamResolver{}

// LookupNetIP implements the [Resolver] interface for upstreamResolver.
func (r upstreamResolver) LookupNetIP(
	ctx context.Context,
	network string,
	host string,
) (ipAddrs []netip.Addr, err error) {
	// TODO(e.burkov):  Investigate when [r.Upstream] is nil and why.
	if r.Upstream == nil || host == "" {
		return []netip.Addr{}, nil
	}

	host = dns.Fqdn(host)

	answers := make([][]dns.RR, 1, 2)
	var errs []error
	switch network {
	case "ip4", "ip6":
		qtype := dns.TypeA
		if network == "ip6" {
			qtype = dns.TypeAAAA
		}

		var resp *dns.Msg
		resp, err = r.resolve(host, qtype)
		if err != nil {
			return []netip.Addr{}, err
		}

		answers[0] = resp.Answer
	case "ip":
		resCh := make(chan *resolveResult, 2)

		go r.resolveAsync(resCh, host, dns.TypeA)
		go r.resolveAsync(resCh, host, dns.TypeAAAA)

		answers = answers[:0:cap(answers)]
		for i := 0; i < 2; i++ {
			res := <-resCh
			if res.err != nil {
				errs = append(errs, res.err)

				continue
			}

			answers = append(answers, res.resp.Answer)
		}
	default:
		return []netip.Addr{}, fmt.Errorf("unsupported network %s", network)
	}

	for _, ans := range answers {
		for _, rr := range ans {
			if addr, ok := netip.AddrFromSlice(proxyutil.IPFromRR(rr)); ok {
				ipAddrs = append(ipAddrs, addr)
			}
		}
	}

	// TODO(e.burkov):  Use [errors.Join] in Go 1.20.
	if len(ipAddrs) == 0 && len(errs) > 0 {
		return []netip.Addr{}, errs[0]
	}

	// Use the previous dnsproxy behavior: prefer IPv4 by default.
	//
	// TODO(a.garipov): Consider unexporting this entire method or
	// documenting that the order of addrs is undefined.
	proxynetutil.SortNetIPAddrs(ipAddrs, false)

	return ipAddrs, nil
}

// resolve performs a single DNS lookup of host.
func (r upstreamResolver) resolve(host string, qtype uint16) (resp *dns.Msg, err error) {
	req := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   host,
			Qtype:  qtype,
			Qclass: dns.ClassINET,
		}},
	}

	return r.Exchange(req)
}

// resolveResult is the result of a single concurrent lookup.
type resolveResult = struct {
	resp *dns.Msg
	err  error
}

// resolveAsync performs a single DNS lookup and sends the result to ch.  It's
// intended to be used as a goroutine.
func (r upstreamResolver) resolveAsync(
	resCh chan<- *resolveResult,
	host string,
	qtype uint16,
) {
	resp, err := r.resolve(host, qtype)
	resCh <- &resolveResult{resp: resp, err: err}
}
