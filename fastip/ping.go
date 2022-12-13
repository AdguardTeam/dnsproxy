package fastip

import (
	"net/netip"
	"time"

	"github.com/AdguardTeam/golibs/log"
)

// pingTCPTimeout is a TCP connection timeout.  It's higher than pingWaitTimeout
// since the slower connections will be cached anyway.
const pingTCPTimeout = 4 * time.Second

// pingResult is the result of dialing the address.
type pingResult struct {
	// addrPort is the address-port pair the result is related to.
	addrPort netip.AddrPort
	// latency is the duration of dialing process in milliseconds.
	latency uint
	// success is true when the dialing succeeded.
	success bool
}

// pingAll pings all ips concurrently and returns as soon as the fastest one is
// found or the timeout is exceeded.
func (f *FastestAddr) pingAll(host string, ips []netip.Addr) (pr *pingResult) {
	ipN := len(ips)
	switch ipN {
	case 0:
		return nil
	case 1:
		return &pingResult{
			addrPort: netip.AddrPortFrom(ips[0], 0),
			success:  true,
		}
	}

	portN := len(f.pingPorts)
	resCh := make(chan *pingResult, ipN*portN)
	scheduled := 0

	// Find the fastest cached IP address and start pinging others.
	for _, ip := range ips {
		cached := f.cacheFind(ip)
		if cached == nil {
			for _, port := range f.pingPorts {
				go f.pingDoTCP(host, netip.AddrPortFrom(ip, uint16(port)), resCh)
			}
			scheduled += portN

			continue
		} else if cached.status != 0 {
			continue
		}

		if pr == nil || cached.latencyMsec < pr.latency {
			pr = &pingResult{
				addrPort: netip.AddrPortFrom(ip, 0),
				latency:  cached.latencyMsec,
				success:  true,
			}
		}
	}

	cached := pr != nil
	if scheduled == 0 {
		if cached {
			log.Debug("pingAll: %s: return cached response: %s", host, pr.addrPort)
		} else {
			log.Debug("pingAll: %s: returning nothing", host)
		}

		return pr
	}

	// Wait for the first successful ping result or the timeout.
	for i, after := 0, time.After(f.PingWaitTimeout); i < scheduled; i++ {
		select {
		case res := <-resCh:
			log.Debug(
				"pingAll: %s: got result for %s status %v",
				host,
				res.addrPort,
				res.success,
			)
			if !res.success {
				continue
			}

			if !cached || pr.latency >= res.latency {
				pr = res
			}

			return pr
		case <-after:
			if cached {
				log.Debug(
					"pingAll: %s: pinging timed out, returning cached: %s",
					host,
					pr.addrPort,
				)
			} else {
				log.Debug(
					"pingAll: %s: ping checks timed out, returning nothing",
					host,
				)
			}

			return pr
		}
	}

	return pr
}

// pingDoTCP sends the result of dialing the specified address into resCh.
func (f *FastestAddr) pingDoTCP(host string, addrPort netip.AddrPort, resCh chan *pingResult) {
	log.Debug("pingDoTCP: %s: connecting to %s", host, addrPort)

	start := time.Now()
	conn, err := f.pinger.Dial("tcp", addrPort.String())
	elapsed := time.Since(start)

	success := err == nil
	if success {
		if cerr := conn.Close(); cerr != nil {
			log.Debug("closing tcp connection: %s", cerr)
		}
	}

	latency := uint(elapsed.Milliseconds())

	resCh <- &pingResult{
		addrPort: addrPort,
		latency:  latency,
		success:  success,
	}

	addr := addrPort.Addr().Unmap()
	if success {
		log.Debug("pingDoTCP: %s: elapsed %s ms on %s", host, elapsed, addrPort)
		f.cacheAddSuccessful(addr, latency)
	} else {
		log.Debug(
			"pingDoTCP: %s: failed to connect to %s, elapsed %s ms: %v",
			host,
			addrPort,
			elapsed,
			err,
		)
		f.cacheAddFailure(addr)
	}
}
