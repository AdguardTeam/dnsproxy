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

func TestRealIPFromHdrs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		hdrs    http.Header
		wantIP  netip.Addr
		wantErr string
	}{{
		name: "cf-connecting-ip",
		hdrs: http.Header{
			httphdr.CFConnectingIP: []string{testIPStr1},
		},
		wantIP:  testIP1,
		wantErr: "",
	}, {
		name: "true-client-ip",
		hdrs: http.Header{
			httphdr.TrueClientIP: []string{testIPStr1},
		},
		wantIP:  testIP1,
		wantErr: "",
	}, {
		name: "x-real-ip",
		hdrs: http.Header{
			httphdr.XRealIP: []string{testIPStr1},
		},
		wantIP:  testIP1,
		wantErr: "",
	}, {
		name: "cf-connecting-ip_redundant_spaces",
		hdrs: http.Header{
			httphdr.CFConnectingIP: []string{"  " + testIPStr1 + "\t"},
		},
		wantIP:  testIP1,
		wantErr: "",
	}, {
		name: "no_any",
		hdrs: http.Header{
			httphdr.CFConnectingIP: []string{"invalid"},
			httphdr.TrueClientIP:   []string{"invalid"},
			httphdr.XRealIP:        []string{"invalid"},
		},
		wantIP:  netip.Addr{},
		wantErr: `ParseAddr(""): unable to parse IP`,
	}, {
		name: "priority",
		hdrs: http.Header{
			httphdr.XForwardedFor:  []string{testIPStr2 + "," + testIPStr1},
			httphdr.TrueClientIP:   []string{testIPStr2},
			httphdr.XRealIP:        []string{testIPStr2},
			httphdr.CFConnectingIP: []string{testIPStr1},
		},
		wantIP:  testIP1,
		wantErr: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testRealIPFromHdrs(t, tc.hdrs, tc.wantIP, tc.wantErr)
		})
	}
}

// testRealIPFromHdrs checks that realIPFromHdrs returns wantIP and wantErrMsg
// for header.
func testRealIPFromHdrs(
	tb testing.TB,
	header http.Header,
	wantIP netip.Addr,
	wantErrMsg string,
) {
	r, err := http.NewRequest(http.MethodGet, "localhost", nil)
	require.NoError(tb, err)

	r.Header = header

	var ip netip.Addr
	ip, err = realIPFromHdrs(r)
	testutil.AssertErrorMsg(tb, wantErrMsg, err)

	assert.Equal(tb, wantIP, ip)
}

func TestRealIPFromHdrs_xff(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		hdrs    http.Header
		wantIP  netip.Addr
		wantErr string
	}{{
		name: "x-forwarded-for_simple",
		hdrs: http.Header{
			httphdr.XForwardedFor: []string{testIPStr2 + "," + testIPStr1},
		},
		wantIP:  testIP2,
		wantErr: "",
	}, {
		name: "x-forwarded-for_single",
		hdrs: http.Header{
			httphdr.XForwardedFor: []string{testIPStr1},
		},
		wantIP:  testIP1,
		wantErr: "",
	}, {
		name: "x-forwarded-for_invalid_proxy",
		hdrs: http.Header{
			httphdr.XForwardedFor: []string{testIPStr1 + ",invalid"},
		},
		wantIP:  testIP1,
		wantErr: "",
	}, {
		name: "x-forwarded-for_empty",
		hdrs: http.Header{
			httphdr.XForwardedFor: []string{""},
		},
		wantIP:  netip.Addr{},
		wantErr: `ParseAddr(""): unable to parse IP`,
	}, {
		name: "x-forwarded-for_redundant_spaces",
		hdrs: http.Header{
			httphdr.XForwardedFor: []string{"  " + testIPStr1 + "   ,\t" + testIPStr2},
		},
		wantIP:  testIP1,
		wantErr: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testRealIPFromHdrs(t, tc.hdrs, tc.wantIP, tc.wantErr)
		})
	}
}

func TestRemoteAddr_direct(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		remoteAddr string
		hdrs       http.Header
		wantErr    string
		wantIP     netip.AddrPort
	}{{
		name:       "no_proxy",
		remoteAddr: testRaddr.String(),
		hdrs:       nil,
		wantErr:    "",
		wantIP:     testRaddr,
	}, {
		name:       "no_port",
		remoteAddr: testIPStr1,
		hdrs:       nil,
		wantErr:    "not an ip:port",
		wantIP:     netip.AddrPort{},
	}, {
		name:       "bad_port",
		remoteAddr: testIPStr1 + ":notport",
		hdrs:       nil,
		wantErr:    `invalid port "notport" parsing "` + testIPStr1 + `:notport"`,
		wantIP:     netip.AddrPort{},
	}, {
		name:       "bad_host",
		remoteAddr: "host:1",
		hdrs:       nil,
		wantErr:    `ParseAddr("host"): unable to parse IP`,
		wantIP:     netip.AddrPort{},
	}, {
		name:       "bad_proxied_host",
		remoteAddr: "host:1",
		hdrs: http.Header{
			httphdr.CFConnectingIP: []string{testIPStr1},
		},
		wantErr: `ParseAddr("host"): unable to parse IP`,
		wantIP:  netip.AddrPort{},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testRemoteAddr(t, tc.remoteAddr, tc.hdrs, tc.wantErr, tc.wantIP, netip.AddrPort{})
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
		hdrs       http.Header
		wantErr    string
		wantIP     netip.AddrPort
		wantProxy  netip.AddrPort
	}{{
		name:       "proxied_with_cloudflare",
		remoteAddr: testRaddr.String(),
		hdrs: http.Header{
			httphdr.CFConnectingIP: []string{testIPStr2},
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(testIP2, 0),
		wantProxy: testRaddr,
	}, {
		name:       "proxied_once",
		remoteAddr: testRaddr.String(),
		hdrs: http.Header{
			httphdr.XForwardedFor: []string{testIPStr2},
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(testIP2, 0),
		wantProxy: testRaddr,
	}, {
		name:       "proxied_multiple",
		remoteAddr: testRaddr.String(),
		hdrs: http.Header{
			httphdr.XForwardedFor: []string{testIPStr2 + "," + testIPStr3},
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(testIP2, 0),
		wantProxy: testRaddr,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testRemoteAddr(t, tc.remoteAddr, tc.hdrs, tc.wantErr, tc.wantIP, tc.wantProxy)
		})
	}
}
