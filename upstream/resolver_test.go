package upstream

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUpstreamResolver(t *testing.T) {
	r, err := NewUpstreamResolver("1.1.1.1:53", &Options{Timeout: 3 * time.Second})
	require.NoError(t, err)

	ipAddrs, err := r.LookupNetIP(context.Background(), "ip", "cloudflare-dns.com")
	require.NoError(t, err)

	assert.NotEmpty(t, ipAddrs)
}

func TestNewUpstreamResolver_validity(t *testing.T) {
	withTimeoutOpt := &Options{Timeout: 3 * time.Second}

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
		addr:       "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
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
			r, err := NewUpstreamResolver(tc.addr, withTimeoutOpt)
			if tc.wantErrMsg != "" {
				assert.Equal(t, tc.wantErrMsg, err.Error())
				if nberr := (&NotBootstrapError{}); errors.As(err, &nberr) {
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
