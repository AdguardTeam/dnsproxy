package proxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	ping "github.com/sparrc/go-ping"
)

const (
	icmpTimeout = 1000
	tcpTimeout  = 1000
)

// FastestAddr - object data
type FastestAddr struct {
	cache     glcache.Cache // cache of the fastest IP addresses
	cacheLock sync.Mutex    // for atomic find-and-store cache operation
	allowICMP bool          // send ICMP request
	allowTCP  bool          // connect via TCP
	tcpPort   uint          // TCP port we try to connect to
}

// Init - initialize module
func (f *FastestAddr) Init() {
	conf := glcache.Config{
		MaxSize:   64 * 1024,
		EnableLRU: true,
	}
	f.cache = glcache.New(conf)
	f.allowICMP = true
	f.allowTCP = true
	f.tcpPort = 80
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
//   . send ICMP packet
//   . connect via TCP
// . Receive ICMP packets.  The first received packet makes it the fastest IP address.
// . Receive TCP connection status.  The first connected address - the fastest IP address.
// . Choose the fastest address between this and the one previously found in cache
// . Return DNS packet containing the chosen IP address (remove all other IP addresses from the packet)
func (f *FastestAddr) exchangeFastest(req *dns.Msg, upstreams []upstream.Upstream) (*dns.Msg, upstream.Upstream, error) {
	replies, err := upstream.ExchangeAll(upstreams, req)
	if err != nil || len(replies) == 0 {
		return nil, nil, err
	}
	host := strings.ToLower(req.Question[0].Name)

	total := f.totalIPAddrs(replies)
	if total <= 1 {
		// use the only response
		log.Debug("FastestAddr: %s: using the only response from upstream servers", host)
		return replies[0].Resp, replies[0].Upstream, nil
	}

	cachedResult := f.getFromCache(host, replies)
	if cachedResult.res != nil {
		log.Debug("%s: Found %s address as the fastest (from cache, %dms)",
			host, cachedResult.ip, cachedResult.latency)
		if cachedResult.nCached == total {
			// use the result from cache only if all IP addresses are found in cache
			return prepareReply(cachedResult.res.Resp, cachedResult.ip), cachedResult.res.Upstream, nil
		}
	}

	ch := make(chan *pingResult, total)
	total = 0
	for _, r := range replies {
		for _, a := range r.Resp.Answer {
			ip := getIPFromDNSRecord(a)
			if ip == nil {
				continue
			}

			if f.cacheFind(ip) == nil {
				if f.allowICMP {
					go f.pingDo(ip, &r, ch)
					total++
				}
				if f.allowTCP {
					go f.pingDoTCP(ip, &r, ch)
					total++
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

type pingResult struct {
	addr        net.IP
	exres       *upstream.ExchangeAllResult
	err         error
	isICMP      bool // true: ICMP;  false: TCP
	latencyMsec uint
}

// Ping an address via ICMP and then send signal to the channel
func (f *FastestAddr) pingDo(addr net.IP, exres *upstream.ExchangeAllResult, ch chan *pingResult) {
	res := &pingResult{}
	res.addr = addr
	res.exres = exres
	res.isICMP = true
	respTTL := findLowestTTL(res.exres.Resp)

	pinger, err := ping.NewPinger(addr.String())
	if err != nil {
		log.Error("ping.NewPinger(): %v", err)
		res.err = err
		ch <- res
		return
	}

	pinger.SetPrivileged(true)
	pinger.Timeout = icmpTimeout * time.Millisecond
	pinger.Count = 1
	reply := false
	pinger.OnRecv = func(pkt *ping.Packet) {
		log.Debug("Received ICMP Reply from %s", addr.String())
		reply = true
	}
	log.Debug("%s: Sending ICMP Echo to %s",
		res.exres.Resp.Question[0].Name, addr)
	start := time.Now()
	pinger.Run()

	if !reply {
		res.err = fmt.Errorf("%s: no reply from %s",
			res.exres.Resp.Question[0].Name, addr)
		log.Debug("%s", res.err)

		f.cacheAddFailure(res.addr, respTTL)
	} else {
		res.latencyMsec = uint(time.Since(start).Milliseconds())
		f.cacheAddSuccessful(res.addr, respTTL, res.latencyMsec)
	}

	ch <- res
}

// Connect to a remote address via TCP and then send signal to the channel
func (f *FastestAddr) pingDoTCP(addr net.IP, exres *upstream.ExchangeAllResult, ch chan *pingResult) {
	res := &pingResult{}
	res.addr = addr
	res.exres = exres
	respTTL := findLowestTTL(res.exres.Resp)

	a := net.JoinHostPort(addr.String(), strconv.Itoa(int(f.tcpPort)))
	log.Debug("%s: Connecting to %s via TCP",
		res.exres.Resp.Question[0].Name, a)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", a, tcpTimeout*time.Millisecond)
	if err != nil {
		res.err = fmt.Errorf("%s: no reply from %s",
			res.exres.Resp.Question[0].Name, addr)
		log.Debug("%s", res.err)

		f.cacheAddFailure(res.addr, respTTL)

		ch <- res
		return
	}
	res.latencyMsec = uint(time.Since(start).Milliseconds())
	conn.Close()

	f.cacheAddSuccessful(res.addr, respTTL, res.latencyMsec)

	ch <- res
}

// Wait for the first successful ping result
func (f *FastestAddr) pingWait(total int, ch chan *pingResult) (fastestAddrResult, error) {
	result := fastestAddrResult{}
	n := 0
	for {
		select {
		case res := <-ch:
			n++

			if res.err != nil {
				break
			}

			proto := "icmp"
			if !res.isICMP {
				proto = "tcp"
			}
			log.Debug("%s: Determined %s address as the fastest (%s, %dms)",
				res.exres.Resp.Question[0].Name, res.addr, proto, res.latencyMsec)

			result.res = res.exres
			result.ip = res.addr
			result.latency = res.latencyMsec
			return result, nil
		}

		if n == total {
			return result, fmt.Errorf("all ping tasks were timed out")
		}
	}
}
