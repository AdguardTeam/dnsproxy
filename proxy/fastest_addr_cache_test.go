package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestFastestAddrCache(t *testing.T) {
	f := FastestAddr{}
	f.Init()
	f.tcpPorts = []uint{40812}
	up1 := &testUpstream{}

	ent := cacheEntry{
		status:      0,
		latencyMsec: 111,
	}
	// f.cacheAdd(&ent, net.ParseIP("1.1.1.1"), fastestAddrCacheMinTTLSec)
	val := packCacheEntry(&ent, 1) // ttl=1
	f.cache.Set(net.ParseIP("1.1.1.1").To4(), val)
	ent = cacheEntry{
		status:      0,
		latencyMsec: 222,
	}
	f.cacheAdd(&ent, net.ParseIP("2.2.2.2"), fastestAddrCacheTTLSec)
	replies := []upstream.ExchangeAllResult{
		upstream.ExchangeAllResult{
			Resp:     &dns.Msg{},
			Upstream: up1,
		},
		upstream.ExchangeAllResult{
			Resp:     &dns.Msg{},
			Upstream: up1,
		},
		upstream.ExchangeAllResult{
			Resp:     &dns.Msg{},
			Upstream: up1,
		},
	}
	replies[0].Resp.Answer = append(replies[0].Resp.Answer, createARec("test.org.", "2.2.2.2"))
	replies[1].Resp.Answer = append(replies[1].Resp.Answer, createARec("test.org.", "1.1.1.1"))
	replies[2].Resp.Answer = append(replies[2].Resp.Answer, createARec("test.org.", "3.3.3.3"))
	result := f.getFromCache("test.org.", replies)
	assert.True(t, result.ip.String() == "1.1.1.1")
	assert.True(t, result.nCached == 2)
	assert.True(t, result.latency == 111)

	time.Sleep(2 * time.Second)
	// 1.1.1.1 has expired now
	result = f.getFromCache("test.org.", replies)
	assert.True(t, result.ip.String() == "2.2.2.2")
	assert.True(t, result.nCached == 1)
	assert.True(t, result.latency == 222)
}
