package proxy

import (
	"context"
	"net/netip"
	"slices"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// helper struct to pass results of lookupIPAddr function
type lookupResult struct {
	resp *dns.Msg
	err  error
}

// lookupIPAddr resolves the specified host IP addresses.
func (p *Proxy) lookupIPAddr(host string, qtype uint16, ch chan *lookupResult) {
	req := (&dns.Msg{}).SetQuestion(host, qtype)

	d := p.newDNSContext(ProtoUDP, req)
	err := p.Resolve(d)
	ch <- &lookupResult{d.Res, err}
}

// ErrEmptyHost is returned by LookupIPAddr when the host is empty and can't be
// resolved.
const ErrEmptyHost = errors.Error("host is empty")

// type check
var _ upstream.Resolver = (*Proxy)(nil)

// LookupNetIP implements the [upstream.Resolver] interface for *Proxy.  It
// resolves the specified host IP addresses by sending two DNS queries (A and
// AAAA) in parallel. It returns both results for those two queries.
func (p *Proxy) LookupNetIP(
	_ context.Context,
	_ string,
	host string,
) (addrs []netip.Addr, err error) {
	if host == "" {
		return nil, ErrEmptyHost
	}

	host = dns.Fqdn(host)

	ch := make(chan *lookupResult)
	go p.lookupIPAddr(host, dns.TypeA, ch)
	go p.lookupIPAddr(host, dns.TypeAAAA, ch)

	var errs []error
	for range 2 {
		result := <-ch
		if result.err != nil {
			errs = append(errs, result.err)

			continue
		}

		for _, ans := range result.resp.Answer {
			a := proxyutil.IPFromRR(ans)
			if a != (netip.Addr{}) {
				addrs = append(addrs, a)
			}
		}
	}

	if len(addrs) == 0 && len(errs) != 0 {
		return addrs, errors.Join(errs...)
	}

	if p.Config.PreferIPv6 {
		slices.SortStableFunc(addrs, netutil.PreferIPv6)
	} else {
		slices.SortStableFunc(addrs, netutil.PreferIPv4)
	}

	return addrs, nil
}
