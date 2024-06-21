package proxy

import (
	"context"
	"net/netip"
	"slices"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// helper struct to pass results of lookupIPAddr function
type lookupResult struct {
	resp *dns.Msg
	err  error
}

// lookupIPAddr resolves the specified host IP addresses.  It is intended to be
// used as a goroutine.
func (p *Proxy) lookupIPAddr(
	ctx context.Context,
	host string,
	qtype uint16,
	ch chan *lookupResult,
) {
	defer slogutil.RecoverAndLog(ctx, p.logger)

	req := (&dns.Msg{}).SetQuestion(host, qtype)

	// TODO(d.kolyshev): Investigate why the client address is not defined.
	d := p.newDNSContext(ProtoUDP, req, netip.AddrPort{})
	err := p.Resolve(d)
	ch <- &lookupResult{
		resp: d.Res,
		err:  err,
	}
}

// ErrEmptyHost is returned by LookupIPAddr when the host is empty and can't be
// resolved.
const ErrEmptyHost = errors.Error("host is empty")

// type check
var _ upstream.Resolver = (*Proxy)(nil)

// LookupNetIP implements the [upstream.Resolver] interface for *Proxy.  It
// resolves the specified host IP addresses by sending two DNS queries (A and
// AAAA) in parallel.  It returns both results for those two queries.
func (p *Proxy) LookupNetIP(
	ctx context.Context,
	_ string,
	host string,
) (addrs []netip.Addr, err error) {
	if host == "" {
		return nil, ErrEmptyHost
	}

	host = dns.Fqdn(host)

	ch := make(chan *lookupResult)
	go p.lookupIPAddr(ctx, host, dns.TypeA, ch)
	go p.lookupIPAddr(ctx, host, dns.TypeAAAA, ch)

	var errs []error
	for range 2 {
		result := <-ch
		if result.err != nil {
			errs = append(errs, result.err)

			continue
		}

		addrs = appendAnswerAddrs(addrs, result.resp.Answer)
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

// appendAnswerAddrs returns addrs with addresses appended from the given ans.
func appendAnswerAddrs(addrs []netip.Addr, ans []dns.RR) (res []netip.Addr) {
	for _, ansRR := range ans {
		a := proxyutil.IPFromRR(ansRR)
		if a != (netip.Addr{}) {
			addrs = append(addrs, a)
		}
	}

	return addrs
}
