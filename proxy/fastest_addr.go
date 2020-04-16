package proxy

import (
	"net"
	"strings"
	"sync"

	"github.com/AdguardTeam/dnsproxy/upstream"
	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

const (
	tcpTimeout = 1000
)

// FastestAddr - object data
type FastestAddr struct {
	cache     glcache.Cache // cache of the fastest IP addresses
	cacheLock sync.Mutex    // for atomic find-and-store cache operation
	allowTCP  bool          // connect via TCP
	tcpPorts  []uint        // TCP ports we're using to check connection speed
}

// Init - initialize module
func (f *FastestAddr) Init() {
	conf := glcache.Config{
		MaxSize:   64 * 1024,
		EnableLRU: true,
	}
	f.cache = glcache.New(conf)
	f.allowTCP = true
	f.tcpPorts = []uint{80, 443}
}

// Get the number of A and AAAA records
func (f *FastestAddr) totalIPAddrs(replies []upstream.ExchangeAllResult) int {
	n := 0
	for _, r := range replies {
		for _, a := range r.Resp.Answer {
			if getIPFromDNSRecord(a) == nil {
				continue
			}
			n++
		}
	}
	return n
}

type fastestAddrResult struct {
	res     *upstream.ExchangeAllResult
	ip      net.IP
	latency uint
	nCached int
}

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
func (f *FastestAddr) exchangeFastest(req *dns.Msg, upstreams []upstream.Upstream) (*dns.Msg, upstream.Upstream, error) {
	replies, err := upstream.ExchangeAll(upstreams, req)
	if err != nil || len(replies) == 0 {
		return nil, nil, err
	}
	host := strings.ToLower(req.Question[0].Name)

	ipAddrsLen := f.totalIPAddrs(replies)
	if ipAddrsLen <= 1 {
		// use the only response
		log.Debug("FastestAddr: %s: using the only response from upstream servers", host)
		return replies[0].Resp, replies[0].Upstream, nil
	}

	cachedResult := f.getFromCache(host, replies)
	if cachedResult.res != nil {
		log.Debug("%s: Found %s address as the fastest (from cache, %dms)",
			host, cachedResult.ip, cachedResult.latency)
		if cachedResult.nCached == ipAddrsLen {
			// use the result from cache only if all IP addresses are found in cache
			return prepareReply(cachedResult.res.Resp, cachedResult.ip), cachedResult.res.Upstream, nil
		}
	}

	chCap := 0
	if f.allowTCP {
		chCap = chCap + ipAddrsLen*len(f.tcpPorts)
	}

	ch := make(chan *pingResult, chCap)
	total := 0
	usedIPs := make(map[string]bool)
	for i, r := range replies {
		for _, a := range r.Resp.Answer {
			ip := getIPFromDNSRecord(a)
			if ip == nil {
				continue
			}

			if f.cacheFind(ip) == nil {
				ipStr := ip.String()
				_, ok := usedIPs[ipStr]
				if ok {
					continue // we've already scheduled a task for this IP
				}
				usedIPs[ipStr] = true

				if f.allowTCP {
					for _, port := range f.tcpPorts {
						go f.pingDoTCP(ip, port, &replies[i], ch)
						total++
					}
				}
			}
		}
	}

	if total == 0 {
		// use the first response
		return replies[0].Resp, replies[0].Upstream, nil
	}

	result, err2 := f.pingWait(total, ch)
	if err2 != nil {
		log.Debug("FastestAddr: %s: %s", host, err2)
		if cachedResult.res != nil {
			// use the result from cache
			return prepareReply(cachedResult.res.Resp, cachedResult.ip), cachedResult.res.Upstream, nil
		}
		// use the first response
		log.Debug("FastestAddr: %s: using the first response from upstream servers", host)
		return replies[0].Resp, replies[0].Upstream, nil
	}

	if cachedResult.res != nil && cachedResult.latency < result.latency {
		// use the result from cache
		result = cachedResult
	}

	return prepareReply(result.res.Resp, result.ip), result.res.Upstream, nil
}

// remove all A/AAAA records, leaving only the fastest one
func prepareReply(resp *dns.Msg, address net.IP) *dns.Msg {
	ans := []dns.RR{}
	for _, a := range resp.Answer {
		switch addr := a.(type) {
		case *dns.A:
			if address.To4().Equal(addr.A.To4()) {
				ans = append(ans, a)
			}

		case *dns.AAAA:
			if address.Equal(addr.AAAA) {
				ans = append(ans, a)
			}

		default:
			ans = append(ans, a)
		}
	}
	resp.Answer = ans
	return resp
}
