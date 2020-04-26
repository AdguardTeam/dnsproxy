package fastip

import (
	"net"
	"strings"
	"sync"

	"github.com/AdguardTeam/golibs/log"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/dnsproxy/upstream"
	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/miekg/dns"
)

// FastestAddr - object data
type FastestAddr struct {
	cache     glcache.Cache // cache of the fastest IP addresses
	cacheLock sync.Mutex    // for atomic find-and-store cache operation
	allowTCP  bool          // connect via TCP
	tcpPorts  []uint        // TCP ports we're using to check connection speed
}

// NewFastestAddr initializes a new instance of the FastestAddr
func NewFastestAddr() *FastestAddr {
	conf := glcache.Config{
		MaxSize:   64 * 1024,
		EnableLRU: true,
	}
	return &FastestAddr{
		cache:    glcache.New(conf),
		allowTCP: true,
		tcpPorts: []uint{80, 443},
	}
}

// ExchangeFastest queries all specified upstreams and returns a response with the fastest IP address.
//
// Algorithm:
// Return DNS response containing the fastest IP address
// Algorithm:
// . Send requests to all upstream servers
// . Receive responses
// . Search all IP addresses in cache:
//   . If all addresses have been found: choose the fastest
//   . If several (but not all) addresses have been found: remember the fastest
// . For each response, for each IP address (not found in cache):
//   . connect via TCP
// . Receive TCP connection status.  The first connected address - the fastest IP address.
// . Choose the fastest address between this and the one previously found in cache
// . Return DNS packet containing the chosen IP address (remove all other IP addresses from the packet)
func (f *FastestAddr) ExchangeFastest(req *dns.Msg, upstreams []upstream.Upstream) (*dns.Msg, upstream.Upstream, error) {
	replies, err := upstream.ExchangeAll(upstreams, req)
	if err != nil || len(replies) == 0 {
		return nil, nil, err
	}

	host := strings.ToLower(req.Question[0].Name)
	ips := f.getIPAddresses(replies)
	found, pingRes := f.pingAll(host, ips)

	if !found {
		log.Debug("%s: no fastest IP found, using the first response", host)
		return replies[0].Resp, replies[0].Upstream, nil
	}

	return f.prepareReply(pingRes, replies)
}

// prepareReply - prepares the DNS response that will be sent back to the client
//
// We should do the following:
// 1. Go through original DNS responses
// 2. Find the one that contains the fastest IP
// 3. Remove all other IP addresses from that response
// 4. Return it
func (f *FastestAddr) prepareReply(pingRes *pingResult, replies []upstream.ExchangeAllResult) (*dns.Msg, upstream.Upstream, error) {
	var m *dns.Msg
	var u upstream.Upstream

	for _, r := range replies {
		for _, rr := range r.Resp.Answer {
			ip := proxyutil.GetIPFromDNSRecord(rr)
			if ip != nil && ip.Equal(pingRes.ip) {
				// Found it!
				m = r.Resp
				u = r.Upstream
				break
			}
		}
	}

	if m == nil {
		// Something definitely went wrong
		log.Error("Found no replies with IP %s, most likely this is a bug", pingRes.ip)
		return replies[0].Resp, replies[0].Upstream, nil
	}

	// Now modify that message and keep only those A/AAAA records
	// that contain our fastest IP address
	ans := []dns.RR{}
	for _, rr := range m.Answer {
		switch addr := rr.(type) {
		case *dns.A:
			if pingRes.ip.Equal(addr.A.To4()) {
				ans = append(ans, rr)
			}

		case *dns.AAAA:
			if pingRes.ip.Equal(addr.AAAA) {
				ans = append(ans, rr)
			}

		default:
			ans = append(ans, rr)
		}
	}

	// Set new answer
	m.Answer = ans

	return m, u, nil
}

// getIPAddresses -- extracts all IP addresses from the list of upstream.ExchangeAllResult
func (f *FastestAddr) getIPAddresses(results []upstream.ExchangeAllResult) []net.IP {
	var ips []net.IP
	for _, r := range results {
		for _, rr := range r.Resp.Answer {
			ip := proxyutil.GetIPFromDNSRecord(rr)
			if ip != nil && !containsIP(ips, ip) {
				ips = append(ips, ip)
			}
		}
	}

	return ips
}

// containsIP - checks if IP address is in the list of IPs
func containsIP(ips []net.IP, ip net.IP) bool {
	if len(ips) == 0 {
		return false
	}

	for _, i := range ips {
		if i.Equal(ip) {
			return true
		}
	}

	return false
}
