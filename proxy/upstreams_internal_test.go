package proxy

import (
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO(e.burkov):  Call [testing.T.Parallel] in this file.

// Domains specifications and their questions used in tests of [UpstreamConfig].
const (
	unqualifiedFQDN = "unqualified."
	unspecifiedFQDN = "unspecified.domain."

	topLevelDomain = "example"
	topLevelFQDN   = topLevelDomain + "."

	firstLevelDomain         = "name." + topLevelDomain
	firstLevelFQDN           = firstLevelDomain + "."
	wildcardFirstLevelDomain = "*." + topLevelDomain

	subDomain = "sub." + firstLevelDomain
	subFQDN   = subDomain + "."

	generalDomain = "general." + firstLevelDomain
	generalFQDN   = generalDomain + "."

	wildcardDomain = "*." + firstLevelDomain
	anotherSubFQDN = "another." + firstLevelDomain + "."
)

// Upstream URLs used in tests of [UpstreamConfig].
const (
	generalUpstream     = "tcp://general.upstream:53"
	unqualifiedUpstream = "tcp://unqualified.upstream:53"
	tldUpstream         = "tcp://tld.upstream:53"
	domainUpstream      = "tcp://domain.upstream:53"
	wildcardUpstream    = "tcp://wildcard.upstream:53"
	subdomainUpstream   = "tcp://subdomain.upstream:53"
)

// testUpstreamConfigLines is the common set of upstream configurations used in
// tests of [UpstreamConfig].
var testUpstreamConfigLines = []string{
	generalUpstream,
	"[//]" + unqualifiedUpstream,
	"[/" + topLevelDomain + "/]" + tldUpstream,
	"[/" + wildcardFirstLevelDomain + "/]#",
	"[/" + firstLevelDomain + "/]" + domainUpstream,
	"[/" + wildcardDomain + "/]" + wildcardUpstream,
	"[/" + generalDomain + "/]#",
	"[/" + subDomain + "/]" + subdomainUpstream,
}

func TestUpstreamConfig_GetUpstreamsForDomain(t *testing.T) {
	t.Parallel()

	config, err := ParseUpstreamsConfig(testUpstreamConfigLines, nil)
	require.NoError(t, err)

	testCases := []struct {
		name string
		in   string
		want []string
	}{{
		name: "unspecified",
		in:   unspecifiedFQDN,
		want: []string{generalUpstream},
	}, {
		name: "unqualified",
		in:   unqualifiedFQDN,
		want: []string{unqualifiedUpstream},
	}, {
		name: "tld",
		in:   topLevelFQDN,
		want: []string{tldUpstream},
	}, {
		name: "unspecified_subdomain",
		in:   unspecifiedFQDN + topLevelFQDN,
		want: []string{generalUpstream},
	}, {
		name: "domain",
		in:   firstLevelFQDN,
		want: []string{domainUpstream},
	}, {
		name: "wildcard",
		in:   anotherSubFQDN,
		want: []string{wildcardUpstream},
	}, {
		name: "general",
		in:   generalFQDN,
		want: []string{generalUpstream},
	}, {
		name: "subdomain",
		in:   subFQDN,
		want: []string{subdomainUpstream},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ups := config.getUpstreamsForDomain(tc.in)
			assertUpstreamsAddrs(t, ups, tc.want)
		})
	}
}

func TestUpstreamConfig_GetUpstreamsForDS(t *testing.T) {
	t.Parallel()

	config, err := ParseUpstreamsConfig(testUpstreamConfigLines, nil)
	require.NoError(t, err)

	testCases := []struct {
		name string
		in   string
		want []string
	}{{
		name: "unspecified",
		in:   unspecifiedFQDN,
		want: []string{unqualifiedUpstream},
	}, {
		name: "unqualified",
		in:   unqualifiedFQDN,
		want: []string{generalUpstream},
	}, {
		name: "tld",
		in:   topLevelFQDN,
		want: []string{generalUpstream},
	}, {
		name: "unspecified_subdomain",
		in:   unspecifiedFQDN + topLevelFQDN,
		want: []string{generalUpstream},
	}, {
		name: "domain",
		in:   firstLevelFQDN,
		want: []string{tldUpstream},
	}, {
		name: "wildcard",
		in:   anotherSubFQDN,
		want: []string{domainUpstream},
	}, {
		name: "general",
		in:   "label." + generalFQDN,
		want: []string{generalUpstream},
	}, {
		name: "subdomain",
		in:   "label." + subFQDN,
		want: []string{subdomainUpstream},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ups := config.getUpstreamsForDS(tc.in)
			assertUpstreamsAddrs(t, ups, tc.want)
		})
	}
}

func TestUpstreamConfig_Validate(t *testing.T) {
	testCases := []struct {
		name    string
		wantErr error
		in      []string
	}{{
		name:    "empty",
		wantErr: upstream.ErrNoUpstreams,
		in:      []string{},
	}, {
		name:    "nil",
		wantErr: upstream.ErrNoUpstreams,
		in:      nil,
	}, {
		name:    "valid",
		wantErr: nil,
		in: []string{
			"udp://upstream.example:53",
		},
	}, {
		name:    "no_default",
		wantErr: errors.Error("no default upstreams specified"),
		in: []string{
			"[/domain.example/]udp://upstream.example:53",
			"[/another.domain.example/]#",
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ParseUpstreamsConfig(tc.in, nil)
			require.NoError(t, err)

			assert.ErrorIs(t, c.validate(), tc.wantErr)
		})
	}

	t.Run("actual_nil", func(t *testing.T) {
		assert.ErrorIs(t, (*UpstreamConfig)(nil).validate(), errors.Error("upstream config is nil"))
	})
}

func TestValidatePrivateConfig(t *testing.T) {
	ss := netutil.SubnetSetFunc(netutil.IsLocallyServed)

	testCases := []struct {
		name    string
		wantErr string
		u       string
	}{{
		name:    "success_address",
		wantErr: ``,
		u:       "[/1.0.0.127.in-addr.arpa/]#",
	}, {
		name:    "success_subnet",
		wantErr: ``,
		u:       "[/127.in-addr.arpa/]#",
	}, {
		name:    "success_v4_family",
		wantErr: ``,
		u:       "[/in-addr.arpa/]#",
	}, {
		name:    "success_v6_family",
		wantErr: ``,
		u:       "[/ip6.arpa/]#",
	}, {
		name:    "bad_arpa_domain",
		wantErr: `bad arpa domain name "arpa": not a reversed ip network`,
		u:       "[/arpa/]#",
	}, {
		name:    "not_arpa_subnet",
		wantErr: `bad arpa domain name "hello.world": not a reversed ip network`,
		u:       "[/hello.world/]#",
	}, {
		name:    "non-private_arpa_address",
		wantErr: `reversed subnet in "1.2.3.4.in-addr.arpa." is not private`,
		u:       "[/1.2.3.4.in-addr.arpa/]#",
	}, {
		name:    "non-private_arpa_subnet",
		wantErr: `reversed subnet in "128.in-addr.arpa." is not private`,
		u:       "[/128.in-addr.arpa/]#",
	}, {
		name: "several_bad",
		wantErr: `reversed subnet in "1.2.3.4.in-addr.arpa." is not private` +
			"\n" + `bad arpa domain name "non.arpa": not a reversed ip network`,
		u: "[/non.arpa/1.2.3.4.in-addr.arpa/127.in-addr.arpa/]#",
	}, {
		name:    "partial_good",
		wantErr: "",
		u:       "[/a.1.2.3.10.in-addr.arpa/a.10.in-addr.arpa/]#",
	}}

	for _, tc := range testCases {
		set := []string{"192.168.0.1", tc.u}

		t.Run(tc.name, func(t *testing.T) {
			upsConf, err := ParseUpstreamsConfig(set, nil)
			require.NoError(t, err)

			testutil.AssertErrorMsg(t, tc.wantErr, ValidatePrivateConfig(upsConf, ss))
		})
	}
}

func TestGetUpstreamsForDomainWithoutDuplicates(t *testing.T) {
	upstreams := []string{"[/example.com/]1.1.1.1", "[/example.org/]1.1.1.1"}
	config, err := ParseUpstreamsConfig(upstreams, &upstream.Options{
		Logger:             slogutil.NewDiscardLogger(),
		InsecureSkipVerify: false,
		Bootstrap:          nil,
		Timeout:            testTimeout,
	})
	assert.NoError(t, err)
	assert.Len(t, config.Upstreams, 0)
	assert.Len(t, config.DomainReservedUpstreams, 2)

	u1 := config.DomainReservedUpstreams["example.com."][0]
	u2 := config.DomainReservedUpstreams["example.org."][0]

	// Check that the very same Upstream instance is used for both domains.
	assert.Same(t, u1, u2)
}

func TestGetUpstreamsForDomain_wildcards(t *testing.T) {
	conf := []string{
		"0.0.0.1",
		"[/a.x/]0.0.0.2",
		"[/*.a.x/]0.0.0.3",
		"[/b.a.x/]0.0.0.4",
		"[/*.b.a.x/]0.0.0.5",
		"[/*.x.z/]0.0.0.6",
		"[/c.b.a.x/]#",
	}

	uconf, err := ParseUpstreamsConfig(conf, nil)
	require.NoError(t, err)

	testCases := []struct {
		name string
		in   string
		want []string
	}{{
		name: "default",
		in:   "d.x.",
		want: []string{"0.0.0.1:53"},
	}, {
		name: "specified_one",
		in:   "a.x.",
		want: []string{"0.0.0.2:53"},
	}, {
		name: "wildcard",
		in:   "c.a.x.",
		want: []string{"0.0.0.3:53"},
	}, {
		name: "specified_two",
		in:   "b.a.x.",
		want: []string{"0.0.0.4:53"},
	}, {
		name: "wildcard_two",
		in:   "d.b.a.x.",
		want: []string{"0.0.0.5:53"},
	}, {
		name: "specified_three",
		in:   "c.b.a.x.",
		want: []string{"0.0.0.1:53"},
	}, {
		name: "specified_four",
		in:   "d.c.b.a.x.",
		want: []string{"0.0.0.1:53"},
	}, {
		name: "unspecified_wildcard",
		in:   "x.z.",
		want: []string{"0.0.0.1:53"},
	}, {
		name: "unspecified_wildcard_sub",
		in:   "a.x.z.",
		want: []string{"0.0.0.6:53"},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ups := uconf.getUpstreamsForDomain(tc.in)
			assertUpstreamsAddrs(t, ups, tc.want)
		})
	}
}

func TestGetUpstreamsForDomain_sub_wildcards(t *testing.T) {
	conf := []string{
		"0.0.0.1",
		"[/a.x/]0.0.0.2",
		"[/*.a.x/]0.0.0.3",
		"[/*.b.a.x/]0.0.0.5",
	}

	uconf, err := ParseUpstreamsConfig(conf, nil)
	require.NoError(t, err)

	testCases := []struct {
		name string
		in   string
		want []string
	}{{
		name: "specified",
		in:   "a.x.",
		want: []string{"0.0.0.2:53"},
	}, {
		name: "wildcard",
		in:   "c.a.x.",
		want: []string{"0.0.0.3:53"},
	}, {
		name: "sub_spec_ignore",
		in:   "b.a.x.",
		want: []string{"0.0.0.3:53"},
	}, {
		name: "sub_spec_wildcard",
		in:   "d.b.a.x.",
		want: []string{"0.0.0.5:53"},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ups := uconf.getUpstreamsForDomain(tc.in)
			assertUpstreamsAddrs(t, ups, tc.want)
		})
	}
}

func TestGetUpstreamsForDomain_default_wildcards(t *testing.T) {
	conf := []string{
		"127.0.0.1:5301",
		"[/example.org/]127.0.0.1:5302",
		"[/*.example.org/]127.0.0.1:5303",
		"[/www.example.org/]127.0.0.1:5304",
		"[/*.www.example.org/]#",
	}

	uconf, err := ParseUpstreamsConfig(conf, nil)
	require.NoError(t, err)

	testCases := []struct {
		name string
		in   string
		want []string
	}{{
		name: "domain",
		in:   "example.org.",
		want: []string{"127.0.0.1:5302"},
	}, {
		name: "sub_wildcard",
		in:   "sub.example.org.",
		want: []string{"127.0.0.1:5303"},
	}, {
		name: "spec_sub",
		in:   "www.example.org.",
		want: []string{"127.0.0.1:5304"},
	}, {
		name: "def_wildcard",
		in:   "abc.www.example.org.",
		want: []string{"127.0.0.1:5301"},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ups := uconf.getUpstreamsForDomain(tc.in)
			assertUpstreamsAddrs(t, ups, tc.want)
		})
	}
}

// upsSink is the typed sink variable for the result of benchmarked function.
var upsSink []upstream.Upstream

func BenchmarkGetUpstreamsForDomain(b *testing.B) {
	upstreams := []string{
		"[/google.com/local/]4.3.2.1",
		"[/www.google.com//]1.2.3.4",
		"[/maps.google.com/]#",
		"[/www.google.com/]tls://1.1.1.1",
	}

	config, _ := ParseUpstreamsConfig(upstreams, &upstream.Options{
		Logger:             slogutil.NewDiscardLogger(),
		InsecureSkipVerify: false,
		Bootstrap:          nil,
		Timeout:            testTimeout,
	})

	domains := []string{
		"www.google.com.",
		"www2.google.com.",
		"internal.local.",
		"google.",
		"maps.google.com.",
	}

	l := len(domains)
	for i := range b.N {
		upsSink = config.getUpstreamsForDomain(domains[i%l])
	}
}

// assertUpstreamsAddrs checks the addresses of ups to exactly match want.
func assertUpstreamsAddrs(tb testing.TB, ups []upstream.Upstream, want []string) {
	tb.Helper()

	require.Len(tb, ups, len(want))
	for i, up := range ups {
		assert.Equalf(tb, want[i], up.Address(), "at index %d", i)
	}
}
