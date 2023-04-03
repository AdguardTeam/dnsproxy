package proxy

import (
	"net"

	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/errors"

	"github.com/miekg/dns"
)

// helper struct to pass results of lookupIPAddr function
type lookupResult struct {
	resp *dns.Msg
	err  error
}

func (p *Proxy) lookupIPAddr(host string, qtype uint16, ch chan *lookupResult) {
	req := &dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{
			Name:   host,
			Qtype:  qtype,
			Qclass: dns.ClassINET,
		},
	}

	d := p.newDNSContext(ProtoUDP, req)
	err := p.Resolve(d)
	ch <- &lookupResult{d.Res, err}
}

// ErrEmptyHost is returned by LookupIPAddr when the host is empty and can't be
// resolved.
const ErrEmptyHost = errors.Error("host is empty")

// LookupIPAddr resolves the specified host IP addresses
// It sends two DNS queries (A and AAAA) in parallel and returns both results
func (p *Proxy) LookupIPAddr(host string) ([]net.IPAddr, error) {
	if host == "" {
		return nil, ErrEmptyHost
	}

	host = dns.Fqdn(host)

	ch := make(chan *lookupResult)
	go p.lookupIPAddr(host, dns.TypeA, ch)
	go p.lookupIPAddr(host, dns.TypeAAAA, ch)

	var ipAddrs []net.IPAddr
	var errs []error
	for n := 0; n < 2; n++ {
		result := <-ch
		if result.err != nil {
			errs = append(errs, result.err)
		} else {
			// Copy IP addresses from dns.RR to the resulting IP slice.
			proxyutil.AppendIPAddrs(&ipAddrs, result.resp.Answer)
		}
	}

	if len(ipAddrs) == 0 && len(errs) != 0 {
		return []net.IPAddr{}, errs[0]
	}

	proxynetutil.SortIPAddrs(ipAddrs, p.Config.PreferIPv6)

	return ipAddrs, nil
}
