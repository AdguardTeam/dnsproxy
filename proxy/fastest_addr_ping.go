package proxy

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxyutil"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/sparrc/go-ping"
)

var adminRights, _ = proxyutil.HaveAdminRights()

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

	if runtime.GOOS == "windows" && !adminRights {
		log.Debug("pinger requires admin rights on Windows")
		res.err = errors.New("pinger requires admin rights on Windows")
		ch <- res
		return
	}

	pinger, err := ping.NewPinger(addr.String())
	if err != nil {
		log.Error("ping.NewPinger(): %v", err)
		res.err = err
		ch <- res
		return
	}

	pinger.SetPrivileged(adminRights)
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

// pingDoTCP connect to a remote address via TCP and then send signal to the channel
func (f *FastestAddr) pingDoTCP(addr net.IP, tcpPort uint, exres *upstream.ExchangeAllResult, ch chan *pingResult) {
	res := &pingResult{}
	res.addr = addr
	res.exres = exres
	respTTL := findLowestTTL(res.exres.Resp)

	a := net.JoinHostPort(addr.String(), strconv.Itoa(int(tcpPort)))
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
			return result, fmt.Errorf("all ping tasks timed out")
		}
	}
}
