// Package fastip implements the algorithm that allows to query multiple
// resolvers, ping all IP addresses that were returned, and return the fastest
// one among them.
package fastip

import (
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// LogPrefix is a prefix for logging.
const LogPrefix = "fastip"

// DefaultPingWaitTimeout is the default period of time for waiting ping
// operations to finish.
const DefaultPingWaitTimeout = 1 * time.Second

// FastestAddr provides methods to determine the fastest network addresses.
type FastestAddr struct {
	// logger is used for logging during the process.  It is never nil.
	logger *slog.Logger

	// pinger is the dialer with predefined timeout for pinging TCP connections.
	pinger *net.Dialer

	// ipCacheLock protects ipCache.
	ipCacheLock *sync.Mutex

	// ipCache caches fastest IP addresses.
	ipCache cache.Cache

	// pingPorts are the ports to ping on.
	pingPorts []uint

	// pingWaitTimeout is the timeout for waiting all the resolved addresses to
	// be pinged.  Any ping results received after that moment are cached, but
	// won't be used.
	pingWaitTimeout time.Duration
}

// NewFastestAddr initializes a new instance of *FastestAddr.
//
// Deprecated: Use [New] instead.
func NewFastestAddr() (f *FastestAddr) {
	return &FastestAddr{
		logger:      slog.Default().With(slogutil.KeyPrefix, LogPrefix),
		ipCacheLock: &sync.Mutex{},
		ipCache: cache.New(cache.Config{
			MaxSize:   64 * 1024,
			EnableLRU: true,
		}),
		pingPorts:       []uint{80, 443},
		pingWaitTimeout: DefaultPingWaitTimeout,
		pinger:          &net.Dialer{Timeout: pingTCPTimeout},
	}
}

// Config contains all the fields necessary for proxy configuration.
type Config struct {
	// Logger is used as the base logger for the service.  If nil,
	// [slog.Default] with [LogPrefix] is used.
	Logger *slog.Logger

	// PingWaitTimeout is the timeout for waiting all the resolved addresses to
	// be pinged.  Any ping results received after that moment are cached, but
	// won't be used.  If zero, [DefaultPingWaitTimeout] is used.
	PingWaitTimeout time.Duration
}

// New initializes a new instance of *FastestAddr.
func New(c *Config) (f *FastestAddr) {
	f = &FastestAddr{
		ipCacheLock: &sync.Mutex{},
		ipCache: cache.New(cache.Config{
			MaxSize:   64 * 1024,
			EnableLRU: true,
		}),
		pingPorts: []uint{80, 443},
		pinger:    &net.Dialer{Timeout: pingTCPTimeout},
	}

	if c.PingWaitTimeout > 0 {
		f.pingWaitTimeout = c.PingWaitTimeout
	} else {
		f.pingWaitTimeout = DefaultPingWaitTimeout
	}

	if c.Logger != nil {
		f.logger = c.Logger
	} else {
		f.logger = slog.Default().With(slogutil.KeyPrefix, LogPrefix)
	}

	return f
}

// ExchangeFastest queries each specified upstream and returns the response with
// the fastest IP address.  The fastest IP address is considered to be the first
// one successfully dialed and other addresses are removed from the answer.
func (f *FastestAddr) ExchangeFastest(
	req *dns.Msg,
	ups []upstream.Upstream,
) (resp *dns.Msg, u upstream.Upstream, err error) {
	replies, err := upstream.ExchangeAll(ups, req)
	if err != nil {
		return nil, nil, err
	}

	ipSet := container.NewMapSet[netip.Addr]()
	for _, r := range replies {
		for _, rr := range r.Resp.Answer {
			ip := ipFromRR(rr)
			if ip.IsValid() && !ip.IsUnspecified() {
				ipSet.Add(ip)
			}
		}
	}

	ips := ipSet.Values()
	host := strings.ToLower(req.Question[0].Name)
	if pingRes := f.pingAll(host, ips); pingRes != nil {
		return f.prepareReply(pingRes, replies)
	}

	f.logger.Debug("no fastest ip found, using the first response", "host", host)

	return replies[0].Resp, replies[0].Upstream, nil
}

// prepareReply converts replies into the DNS answer message according to res.
// The returned upstream is the one which replied with the fastest address.
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
		f.logger.Error("found no replies, most likely this is a bug", "ip", ip)

		// TODO(d.kolyshev): Consider returning error?
		return replies[0].Resp, replies[0].Upstream, nil
	}

	filterResponseAnswer(resp, ip)

	return resp, u, nil
}

// filterResponseAnswer modifies the response message, it keeps only A and AAAA
// records with the given IP address.
func filterResponseAnswer(resp *dns.Msg, ip netip.Addr) {
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
