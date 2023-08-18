// Package fastip implements the algorithm that allows to query multiple
// resolvers, ping all IP addresses that were returned, and return the fastest
// one among them.
package fastip

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"golang.org/x/exp/maps"
)

// DefaultPingWaitTimeout is the default period of time for waiting ping
// operations to finish.
const DefaultPingWaitTimeout = 1 * time.Second

// FastestAddr provides methods to determine the fastest network addresses.
type FastestAddr struct {
	// pinger is the dialer with predefined timeout for pinging TCP
	// connections.
	pinger *net.Dialer

	// ipCacheLock protects ipCache.
	ipCacheLock *sync.Mutex

	// ipCache caches fastest IP addresses.
	ipCache cache.Cache

	// pingPorts are the ports to ping on.
	pingPorts []uint

	// PingWaitTimeout is the timeout for waiting all the resolved addresses
	// are pinged.  Any ping results received after it are cached but not
	// used at the moment.  It should be configured right after the
	// FastestAddr initialization since it isn't protected for concurrent
	// usage.
	PingWaitTimeout time.Duration
}

// NewFastestAddr initializes a new instance of the *FastestAddr.
func NewFastestAddr() (f *FastestAddr) {
	return &FastestAddr{
		ipCacheLock: &sync.Mutex{},
		ipCache: cache.New(cache.Config{
			MaxSize:   64 * 1024,
			EnableLRU: true,
		}),
		pingPorts:       []uint{80, 443},
		PingWaitTimeout: DefaultPingWaitTimeout,
		pinger:          &net.Dialer{Timeout: pingTCPTimeout},
	}
}

// ExchangeFastest queries each specified upstream and returns a response with
// the fastest IP address.  The fastest IP address is considered to be the first
// one successfully dialed and other addresses are removed from the answer.
func (f *FastestAddr) ExchangeFastest(req *dns.Msg, ups []upstream.Upstream) (
	resp *dns.Msg,
	u upstream.Upstream,
	err error,
) {
	replies, err := upstream.ExchangeAll(ups, req)
	if err != nil {
		return nil, nil, err
	}

	host := strings.ToLower(req.Question[0].Name)

	ipSet := map[netip.Addr]struct{}{}
	for _, r := range replies {
		for _, rr := range r.Resp.Answer {
			ip := ipFromRR(rr)
			if _, ok := ipSet[ip]; !ok && ip != (netip.Addr{}) {
				ipSet[ip] = struct{}{}
			}
		}
	}

	ips := maps.Keys(ipSet)
	if pingRes := f.pingAll(host, ips); pingRes != nil {
		return f.prepareReply(pingRes, replies)
	}

	log.Debug("%s: no fastest IP found, using the first response", host)

	return replies[0].Resp, replies[0].Upstream, nil
}

// prepareReply converts replies into the DNS answer message according to res.
// The returned upstreams is the one which replied with the fastest address.
func (f *FastestAddr) prepareReply(
	res *pingResult,
	replies []upstream.ExchangeAllResult,
) (resp *dns.Msg, u upstream.Upstream, err error) {
	ip := res.addrPort.Addr()
	for _, r := range replies {
		if hasInAns(r.Resp, ip) {
			resp = r.Resp
			u = r.Upstream

			break
		}
	}

	if resp == nil {
		log.Error("found no replies with IP %s, most likely this is a bug", ip)

		return replies[0].Resp, replies[0].Upstream, nil
	}

	// Modify the message and keep only A and AAAA records containing the
	// fastest IP address.
	ans := make([]dns.RR, 0, len(resp.Answer))
	ipBytes := ip.AsSlice()
	for _, rr := range resp.Answer {
		switch addr := rr.(type) {
		case *dns.A:
			if addr.A.Equal(ipBytes) {
				ans = append(ans, rr)
			}
		case *dns.AAAA:
			if addr.AAAA.Equal(ipBytes) {
				ans = append(ans, rr)
			}
		default:
			ans = append(ans, rr)
		}
	}

	// Set new answer.
	resp.Answer = ans

	return resp, u, nil
}

// hasInAns returns true if m contains ip in its Answer section.
func hasInAns(m *dns.Msg, ip netip.Addr) (ok bool) {
	for _, rr := range m.Answer {
		respIP := ipFromRR(rr)
		if respIP == ip {
			return true
		}
	}

	return false
}

// ipFromRR returns the IP address from rr if any.
func ipFromRR(rr dns.RR) (ip netip.Addr) {
	switch rr := rr.(type) {
	case *dns.A:
		ip, _ = netutil.IPToAddr(rr.A, netutil.AddrFamilyIPv4)
	case *dns.AAAA:
		ip, _ = netutil.IPToAddr(rr.AAAA, netutil.AddrFamilyIPv6)
	}

	return ip
}
