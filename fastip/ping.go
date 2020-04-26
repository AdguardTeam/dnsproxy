package fastip

import (
	"net"
	"strconv"
	"time"

	"github.com/AdguardTeam/golibs/log"
)

// Time we're waiting for ping operations to finish to
// If we don't receive any result for this period of time,
// we ignore all scheduled ping checks and return what we have
const pingWaitTimeout = 1 * time.Second

// TCP connection timeout. Note that it's higher that pingWaitTimeout
// If the connection really takes more than "pingWaitTimeout" to succeed,
// it will be ignored at first. However, we will record it to the cache
// and consider the IP address next time it's checked.
const pingTCPTimeout = 10 * time.Second

// pingResult - represents the ping result
type pingResult struct {
	ip      net.IP // ip address
	tcpPort uint   // tcp port that was probed
	latency uint   // ip latency (milliseconds)
	success bool   // if true -- the ping operation was successful
}

// pingAll -- pings all apps in parallel and returns as soon as the fastest one is found
// returns true if at least one ping was successful
// returns false if it failed to connect to all IPs
// returns the fastest address ping result
func (f *FastestAddr) pingAll(host string, ips []net.IP) (bool, *pingResult) {
	if len(ips) == 0 {
		return false, nil
	}

	// channel that we will use to get the ping result
	ch := make(chan *pingResult, len(ips)*len(f.tcpPorts))

	// fastest cached address
	var fCached *pingResult

	// the number of scheduled ping operations
	scheduled := 0

	// find the fastest cached IP address (if any)
	for _, ip := range ips {
		cached := f.cacheFind(ip)
		if cached == nil {
			// start async ping checks
			for _, port := range f.tcpPorts {
				// async ping the specified IP
				go f.pingDoTCP(host, ip, port, ch)
				scheduled++
			}

			continue
		}

		if cached.status == 0 {
			if fCached == nil || fCached.latency > cached.latencyMsec {
				fCached = &pingResult{
					ip:      ip,
					latency: cached.latencyMsec,
				}
			}
		}
	}

	// if there was no ping operations scheduled,
	// and there's a cached result, return it right away
	if fCached != nil && scheduled == 0 {
		log.Debug("pingAll: %s: return cached response: %s", host, fCached.ip)
		return true, fCached
	}

	// wait for the first successful ping result
	// or until ping timeout is finished
	for i := 0; i < scheduled; i++ {
		select {
		case res := <-ch:
			log.Debug("pingAll: %s: got result for %s status %v", host, res.ip, res.success)

			// if the result was successful, compare it to the fastest cached
			// and return the fastest one of them
			// if the result was not successful, just ignore it and do nothing
			if res.success {
				// Check what's faster -- cached or this one
				if fCached != nil && fCached.latency < res.latency {
					return true, fCached
				}

				return true, res
			}
		case <-time.After(pingWaitTimeout):
			if fCached != nil {
				log.Debug("pingAll: %s: ping checks timed out, returning cached response: %s", host, fCached.ip)
			} else {
				log.Debug("pingAll: %s: ping checks timed out, returning nothing", host)
			}

			return fCached != nil, fCached
		}
	}

	if fCached != nil {
		log.Debug("pingAll: %s: no successful ping check, returning cached response: %s", host, fCached.ip)
	} else {
		log.Debug("pingAll: %s: no successful ping check, returning nothing", host)
	}
	return fCached != nil, fCached
}

// pingDoTCP - connects to the specified IP:port and writes result to the channel
func (f *FastestAddr) pingDoTCP(host string, ip net.IP, port uint, ch chan *pingResult) {
	res := &pingResult{
		ip:      ip,
		tcpPort: port,
		success: true,
	}

	log.Debug("pingDoTCP: %s: connecting to %s:%d", host, ip, port)

	start := time.Now()
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	conn, err := net.DialTimeout("tcp", addr, pingTCPTimeout)

	// regardless of the result, save elapsed ms
	res.latency = uint(time.Since(start).Milliseconds())

	if err != nil {
		log.Debug("pingDoTCP: %s: failed to connect to %s:%d, elapsed %d ms: %v", host, ip, port, res.latency, err)

		res.success = false
		f.cacheAddFailure(ip)

		// notify of the result
		ch <- res
		return
	}

	log.Debug("pingDoTCP: %s: elapsed %d ms on %s:%d", host, res.latency, ip, port)
	_ = conn.Close()
	f.cacheAddSuccessful(ip, res.latency)
	ch <- res
}
