package proxy

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSContext_scrub_udpSize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		proto       Proto
		udpSize     uint16
		edns        bool
		wantTC      bool
		wantOver512 bool
	}{{
		name:        "udp_no_edns",
		proto:       ProtoUDP,
		wantTC:      true,
		wantOver512: false,
	}, {
		name:        "udp_edns",
		proto:       ProtoUDP,
		udpSize:     1232,
		edns:        true,
		wantTC:      false,
		wantOver512: true,
	}, {
		name:        "tcp_no_edns",
		proto:       ProtoTCP,
		wantTC:      false,
		wantOver512: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dctx := newDNSContext("example.org", dns.TypeTXT, dns.ClassINET, tc.edns, tc.udpSize)
			dctx.Proto = tc.proto
			dctx.calcFlagsAndSize()

			// DNSSEC injection mutates a non-EDNS request after the original
			// buffer size has been captured.
			p := &Proxy{
				dnsSecEnabled: true,
			}
			p.addDO(dctx.Req)

			dctx.Res = (&dns.Msg{}).SetReply(dctx.Req)
			dctx.Res.Answer = []dns.RR{&dns.TXT{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn("example.org"),
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				Txt: []string{
					strings.Repeat("a", 255),
					strings.Repeat("b", 255),
					strings.Repeat("c", 255),
					strings.Repeat("d", 255),
				},
			}}

			raw, err := dctx.Res.Pack()
			require.NoError(t, err)
			require.Greater(t, len(raw), dns.MinMsgSize)

			dctx.scrub()

			raw, err = dctx.Res.Pack()
			require.NoError(t, err)

			assert.Equal(t, tc.wantTC, dctx.Res.Truncated)
			if tc.wantOver512 {
				assert.Greater(t, len(raw), dns.MinMsgSize)
			} else {
				assert.LessOrEqual(t, len(raw), dns.MinMsgSize)
			}

			if tc.edns {
				assert.NotNil(t, dctx.Res.IsEdns0())
			} else {
				assert.Nil(t, dctx.Res.IsEdns0())
			}
		})
	}
}
