package upstream

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewResolver(t *testing.T) {
	r, err := NewResolver("1.1.1.1:53", 3*time.Second)
	assert.Nil(t, err)

	ipAddrs, err := r.LookupIPAddr(context.TODO(), "cloudflare-dns.com")
	if err != nil {
		t.Fatalf("r.LookupIPAddr: %s", err)
	}

	// check that both IPv4 and IPv6 addresses exist
	var nIP4, nIP6 uint
	for _, ip := range ipAddrs {
		if ip.IP.To4() != nil {
			nIP4++
		} else {
			nIP6++
		}
	}

	if nIP4 == 0 || nIP6 == 0 {
		t.Fatalf("nIP4 == 0 || nIP6 == 0")
	}
}

func TestNewResolverIsValid(t *testing.T) {
	r, err := NewResolver("1.1.1.1:53", 3*time.Second)
	assert.Nil(t, err)
	assert.NotNil(t, r.upstream)
	addrs, err := r.LookupIPAddr(context.TODO(), "cloudflare-dns.com")
	assert.Nil(t, err)
	assert.True(t, len(addrs) > 0)

	r, err = NewResolver("tls://1.1.1.1", 3*time.Second)
	assert.Nil(t, err)
	assert.NotNil(t, r.upstream)
	addrs, err = r.LookupIPAddr(context.TODO(), "cloudflare-dns.com")
	assert.Nil(t, err)
	assert.True(t, len(addrs) > 0)

	r, err = NewResolver("https://1.1.1.1/dns-query", 3*time.Second)
	assert.Nil(t, err)
	assert.NotNil(t, r.upstream)
	addrs, err = r.LookupIPAddr(context.TODO(), "cloudflare-dns.com")
	assert.Nil(t, err)
	assert.True(t, len(addrs) > 0)

	r, err = NewResolver("sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20", 3*time.Second)
	assert.Nil(t, err)
	assert.NotNil(t, r.upstream)
	addrs, err = r.LookupIPAddr(context.TODO(), "cloudflare-dns.com")
	assert.Nil(t, err)
	assert.True(t, len(addrs) > 0)

	r, err = NewResolver("tcp://9.9.9.9", 3*time.Second)
	assert.Nil(t, err)
	assert.NotNil(t, r.upstream)
	addrs, err = r.LookupIPAddr(context.TODO(), "cloudflare-dns.com")
	assert.Nil(t, err)
	assert.True(t, len(addrs) > 0)

	// not an IP address:

	r, err = NewResolver("tls://dns.adguard.com", 3*time.Second)
	assert.NotNil(t, err)

	r, err = NewResolver("https://dns.adguard.com/dns-query", 3*time.Second)
	assert.NotNil(t, err)

	r, err = NewResolver("tcp://dns.adguard.com", 0)
	assert.NotNil(t, err)

	r, err = NewResolver("dns.adguard.com", 0)
	assert.NotNil(t, err)
}
