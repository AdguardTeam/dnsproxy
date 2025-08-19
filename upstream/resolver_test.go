package upstream_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUpstreamResolver(t *testing.T) {
	ups := &dnsproxytest.Upstream{
		OnAddress: func() (_ string) { panic(testutil.UnexpectedCall()) },
		OnClose:   func() (_ error) { panic(testutil.UnexpectedCall()) },
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			resp = (&dns.Msg{}).SetReply(req)
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: netip.MustParseAddr("1.2.3.4").AsSlice(),
			}}

			return resp, nil
		},
	}

	r := &upstream.UpstreamResolver{Upstream: ups}

	ipAddrs, err := r.LookupNetIP(context.Background(), "ip", "cloudflare-dns.com")
	require.NoError(t, err)

	assert.NotEmpty(t, ipAddrs)
}

func TestNewUpstreamResolver_validity(t *testing.T) {
	t.Parallel()

	withTimeoutOpt := &upstream.Options{
		Logger:  slogutil.NewDiscardLogger(),
		Timeout: 3 * time.Second,
	}

	testCases := []struct {
		name       string
		addr       string
		wantErrMsg string
	}{{
		name:       "udp",
		addr:       "1.1.1.1:53",
		wantErrMsg: "",
	}, {
		name:       "dot",
		addr:       "tls://1.1.1.1",
		wantErrMsg: "",
	}, {
		name:       "doh",
		addr:       "https://1.1.1.1/dns-query",
		wantErrMsg: "",
	}, {
		name:       "sdns",
		addr:       "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
		wantErrMsg: "",
	}, {
		name:       "tcp",
		addr:       "tcp://9.9.9.9",
		wantErrMsg: "",
	}, {
		name: "invalid_tls",
		addr: "tls://dns.adguard.com",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}, {
		name: "invalid_https",
		addr: "https://dns.adguard.com/dns-query",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}, {
		name: "invalid_tcp",
		addr: "tcp://dns.adguard.com",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}, {
		name: "invalid_no_scheme",
		addr: "dns.adguard.com",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := upstream.NewUpstreamResolver(tc.addr, withTimeoutOpt)
			if tc.wantErrMsg != "" {
				assert.Equal(t, tc.wantErrMsg, err.Error())
				if nberr := (&upstream.NotBootstrapError{}); errors.As(err, &nberr) {
					assert.NotNil(t, r)
				}

				return
			}

			require.NoError(t, err)

			addrs, err := r.LookupNetIP(context.Background(), "ip", "cloudflare-dns.com")
			require.NoError(t, err)

			assert.NotEmpty(t, addrs)
		})
	}
}
