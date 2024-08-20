package handler

import (
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsmsg"
	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO(e.burkov):  Remove when [hostsfile.DefaultStorage] stops using [log].
func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)

	os.Exit(m.Run())
}

// TODO(e.burkov):  Add helpers to initialize [proxy.Proxy] to [dnsproxytest]
// and rewrite the tests.

// defaultTimeout is a default timeout for tests and contexts.
const defaultTimeout = 1 * time.Second

// testdata is the file system for test data.
var testdata fs.FS = os.DirFS("testdata")

func TestDefault_haltAAAA(t *testing.T) {
	t.Parallel()

	reqA := (&dns.Msg{}).SetQuestion("domain.example.", dns.TypeA)
	reqAAAA := (&dns.Msg{}).SetQuestion("domain.example.", dns.TypeAAAA)

	nodataResp := (&dns.Msg{}).SetReply(reqA)

	messages := dnsproxytest.NewTestMessageConstructor()
	messages.OnNewMsgNODATA = func(_ *dns.Msg) (resp *dns.Msg) {
		return nodataResp
	}

	t.Run("disabled", func(t *testing.T) {
		t.Parallel()

		hdlr, err := NewDefault(&DefaultConfig{
			Logger:             slogutil.NewDiscardLogger(),
			MessageConstructor: messages,
			HaltIPv6:           false,
			FileSystem:         testdata,
		})
		require.NoError(t, err)

		ctx := testutil.ContextWithTimeout(t, defaultTimeout)

		assert.Nil(t, hdlr.haltAAAA(ctx, reqA))
		assert.Nil(t, hdlr.haltAAAA(ctx, reqAAAA))
	})

	t.Run("enabled", func(t *testing.T) {
		t.Parallel()

		hdlr, err := NewDefault(&DefaultConfig{
			Logger:             slogutil.NewDiscardLogger(),
			MessageConstructor: messages,
			HaltIPv6:           true,
			FileSystem:         testdata,
		})
		require.NoError(t, err)

		ctx := testutil.ContextWithTimeout(t, defaultTimeout)

		assert.Nil(t, hdlr.haltAAAA(ctx, reqA))
		assert.Equal(t, nodataResp, hdlr.haltAAAA(ctx, reqAAAA))
	})
}

func TestDefault_resolveFromHosts(t *testing.T) {
	t.Parallel()

	// TODO(e.burkov):  Use the one from [dnsproxytest].
	messages := dnsmsg.DefaultMessageConstructor{}

	hdlr, err := NewDefault(&DefaultConfig{
		MessageConstructor: messages,
		FileSystem:         testdata,
		Logger:             slogutil.NewDiscardLogger(),
		HostsFiles:         []string{path.Join(t.Name(), "hosts")},
		HaltIPv6:           true,
	})
	require.NoError(t, err)

	const (
		domainV4 = "ipv4.domain.example"
		domainV6 = "ipv6.domain.example"
	)

	var (
		addrV4 = netip.MustParseAddr("1.2.3.4")
		addrV6 = netip.MustParseAddr("2001:db8::1")

		reversedV4      = errors.Must(netutil.IPToReversedAddr(addrV4.AsSlice()))
		reversedV6      = errors.Must(netutil.IPToReversedAddr(addrV6.AsSlice()))
		unknownReversed = errors.Must(netutil.IPToReversedAddr(net.IP{4, 3, 2, 1}))
	)

	testCases := []struct {
		wantAns dns.RR
		req     *dns.Msg
		name    string
	}{{
		wantAns: &dns.A{
			Hdr: dns.RR_Header{
				Name:   domainV4,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    10,
			},
			A: addrV4.AsSlice(),
		},
		req:  (&dns.Msg{}).SetQuestion(domainV4, dns.TypeA),
		name: "success_a",
	}, {
		wantAns: &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   domainV6,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    10,
			},
			AAAA: addrV6.AsSlice(),
		},
		req:  (&dns.Msg{}).SetQuestion(domainV6, dns.TypeAAAA),
		name: "success_aaaa",
	}, {
		wantAns: &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   reversedV4,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    10,
			},
			Ptr: domainV4,
		},
		req:  (&dns.Msg{}).SetQuestion(reversedV4, dns.TypePTR),
		name: "success_ptr_v4",
	}, {
		wantAns: &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   reversedV6,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    10,
			},
			Ptr: domainV6,
		},
		req:  (&dns.Msg{}).SetQuestion(reversedV6, dns.TypePTR),
		name: "success_ptr_v6",
	}, {
		wantAns: nil,
		req:     (&dns.Msg{}).SetQuestion("unknown.example", dns.TypeA),
		name:    "not_found_a",
	}, {
		wantAns: nil,
		req:     (&dns.Msg{}).SetQuestion("unknown.example", dns.TypeAAAA),
		name:    "not_found_aaaa",
	}, {
		wantAns: nil,
		req:     (&dns.Msg{}).SetQuestion(unknownReversed, dns.TypePTR),
		name:    "not_found_ptr",
	}, {
		wantAns: nil,
		req:     (&dns.Msg{}).SetQuestion("bad.ptr", dns.TypePTR),
		name:    "bad_ptr",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, defaultTimeout)
			resp := hdlr.resolveFromHosts(ctx, tc.req)
			if tc.wantAns == nil {
				assert.Nil(t, resp)

				return
			}

			require.NotNil(t, resp)
			require.Len(t, resp.Answer, 1)
			assert.Equal(t, tc.wantAns, resp.Answer[0])
		})
	}
}
