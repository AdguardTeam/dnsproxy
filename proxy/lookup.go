package proxy

import (
	"net"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxyutil"

	"github.com/miekg/dns"
)

// helper struct to pass results of lookupIPAddr function
type lookupResult struct {
	resp *dns.Msg
	err  error
}

func (p *Proxy) lookupIPAddr(host string, qtype uint16, ch chan *lookupResult) {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{
			Name:   host,
			Qtype:  qtype,
			Qclass: dns.ClassINET,
		},
	}

	ctx := &DNSContext{
		Proto:     "udp",
		Req:       &req,
		StartTime: time.Now(),
	}
	err := p.Resolve(ctx)
	ch <- &lookupResult{ctx.Res, err}
}

// LookupIPAddr resolves the specified host IP addresses
// It sends two DNS queries (A and AAAA) in parallel and returns both results
func (p *Proxy) LookupIPAddr(host string) ([]net.IPAddr, error) {
	if host[:1] != "." {
		host += "."
	}

	ch := make(chan *lookupResult)
	go p.lookupIPAddr(host, dns.TypeA, ch)
	go p.lookupIPAddr(host, dns.TypeAAAA, ch)

	var ipAddrs []net.IPAddr
	var errs []error
	n := 0
wait:
	for {
		var result *lookupResult
		select {
		case result = <-ch:
			if result.err != nil {
				errs = append(errs, result.err)
			} else {
				// copy IP addresses from dns.RR to the resulting IPs array
				proxyutil.AppendIPAddrs(&ipAddrs, result.resp.Answer)
			}
			n++
			if n == 2 {
				// Two parallel lookups are finished
				break wait
			}
		}
	}

	if len(ipAddrs) == 0 && len(errs) != 0 {
		return []net.IPAddr{}, errs[0]
	}

	return proxyutil.SortIPAddrs(ipAddrs), nil
}
