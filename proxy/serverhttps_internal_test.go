package proxy

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Common IP address strings for tests.
const (
	testIPStr1 = "192.0.2.1"
	testIPStr2 = "192.0.2.2"
	testIPStr3 = "192.0.2.3"
)

// Common IP adresses for tests.
var (
	testIP1 = netip.MustParseAddr(testIPStr1)
	testIP2 = netip.MustParseAddr(testIPStr2)

	testRaddr = netip.AddrPortFrom(testIP1, 1234)
)

func TestRemoteAddr_direct(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		remoteAddr string
		hdr        http.Header
		wantErr    string
		wantIP     netip.AddrPort
	}{{
		name:       "no_proxy",
		remoteAddr: testRaddr.String(),
		hdr:        nil,
		wantErr:    "",
		wantIP:     testRaddr,
	}, {
		name:       "no_port",
		remoteAddr: testIPStr1,
		hdr:        nil,
		wantErr:    "not an ip:port",
		wantIP:     netip.AddrPort{},
	}, {
		name:       "bad_port",
		remoteAddr: testIPStr1 + ":notport",
		hdr:        nil,
		wantErr:    `invalid port "notport" parsing "` + testIPStr1 + `:notport"`,
		wantIP:     netip.AddrPort{},
	}, {
		name:       "bad_host",
		remoteAddr: "host:1",
		hdr:        nil,
		wantErr:    `ParseAddr("host"): unable to parse IP`,
		wantIP:     netip.AddrPort{},
	}, {
		name:       "bad_proxied_host",
		remoteAddr: "host:1",
		hdr: http.Header{
			httphdr.CFConnectingIP: []string{testIPStr1},
		},
		wantErr: `ParseAddr("host"): unable to parse IP`,
		wantIP:  netip.AddrPort{},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testRemoteAddr(t, tc.remoteAddr, tc.hdr, tc.wantErr, tc.wantIP, netip.AddrPort{})
		})
	}
}

// testRemoteAddr makes sure that remoteAddr returns expected IP and proxy for
// given raddr and header.
func testRemoteAddr(
	tb testing.TB,
	raddr string,
	header http.Header,
	wantErrMsg string,
	wantIP netip.AddrPort,
	wantProxy netip.AddrPort,
) {
	r, err := http.NewRequest(http.MethodGet, dnsproxytest.Host, nil)
	require.NoError(tb, err)

	r.RemoteAddr = raddr
	r.Header = header

	var addr, prx netip.AddrPort
	addr, prx, err = remoteAddr(r, testLogger)
	if wantErrMsg != "" {
		testutil.AssertErrorMsg(tb, wantErrMsg, err)

		return
	}

	require.NoError(tb, err)
	assert.Equal(tb, wantIP, addr)
	assert.Equal(tb, wantProxy, prx)
}

func TestRemoteAddr_proxied(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		remoteAddr string
		hdr        http.Header
		wantErr    string
		wantIP     netip.AddrPort
		wantProxy  netip.AddrPort
	}{{
		name:       "proxied_with_cloudflare",
		remoteAddr: testRaddr.String(),
		hdr: http.Header{
			httphdr.CFConnectingIP: []string{testIPStr2},
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(testIP2, 0),
		wantProxy: testRaddr,
	}, {
		name:       "proxied_once",
		remoteAddr: testRaddr.String(),
		hdr: http.Header{
			httphdr.XForwardedFor: []string{testIPStr2},
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(testIP2, 0),
		wantProxy: testRaddr,
	}, {
		name:       "proxied_multiple",
		remoteAddr: testRaddr.String(),
		hdr: http.Header{
			httphdr.XForwardedFor: []string{testIPStr2 + "," + testIPStr3},
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(testIP2, 0),
		wantProxy: testRaddr,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testRemoteAddr(t, tc.remoteAddr, tc.hdr, tc.wantErr, tc.wantIP, tc.wantProxy)
		})
	}
}
