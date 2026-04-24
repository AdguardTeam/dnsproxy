package proxy

import (
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO(e.burkov):  Consider making the below tests external when the
// [UpstreamConfig]'s API is exported.

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
	testutil.CleanupAndRequireSuccess(t, config.Close)

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
		name: "root",
		in:   ".",
		want: []string{generalUpstream},
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
	testutil.CleanupAndRequireSuccess(t, config.Close)

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
		name: "root",
		in:   ".",
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
	t.Parallel()

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
		wantErr: errors.ErrNoValue,
		in: []string{
			"[/domain.example/]udp://upstream.example:53",
			"[/another.domain.example/]#",
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := ParseUpstreamsConfig(tc.in, nil)
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, c.Close)

			assert.ErrorIs(t, c.validate(), tc.wantErr)
		})
	}

	t.Run("actual_nil", func(t *testing.T) {
		t.Parallel()

		var c *UpstreamConfig

		assert.Equal(t, c.validate(), errors.ErrNoValue)
	})
}

func TestUpstreamConfig_GetUpstreamsForDomain_wildcards(t *testing.T) {
	t.Parallel()

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
	testutil.CleanupAndRequireSuccess(t, uconf.Close)

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
			t.Parallel()

			ups := uconf.getUpstreamsForDomain(tc.in)
			assertUpstreamsAddrs(t, ups, tc.want)
		})
	}
}

func TestUpstreamConfig_GetUpstreamsForDomain_subWildcards(t *testing.T) {
	conf := []string{
		"0.0.0.1",
		"[/a.x/]0.0.0.2",
		"[/*.a.x/]0.0.0.3",
		"[/*.b.a.x/]0.0.0.5",
	}

	uconf, err := ParseUpstreamsConfig(conf, nil)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, uconf.Close)

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
			t.Parallel()

			ups := uconf.getUpstreamsForDomain(tc.in)
			assertUpstreamsAddrs(t, ups, tc.want)
		})
	}
}

func TestUpstreamConfig_GetUpstreamsForDomain_defaultWildcards(t *testing.T) {
	t.Parallel()

	conf := []string{
		"127.0.0.1:5301",
		"[/example.org/]127.0.0.1:5302",
		"[/*.example.org/]127.0.0.1:5303",
		"[/www.example.org/]127.0.0.1:5304",
		"[/*.www.example.org/]#",
	}

	uconf, err := ParseUpstreamsConfig(conf, nil)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, uconf.Close)

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
			t.Parallel()

			ups := uconf.getUpstreamsForDomain(tc.in)
			assertUpstreamsAddrs(t, ups, tc.want)
		})
	}
}

func BenchmarkUpstreamConfig_GetUpstreamsForDomain(b *testing.B) {
	upstreamsAddrs := []string{
		"[/google.com/local/]4.3.2.1",
		"[/www.google.com//]1.2.3.4",
		"[/maps.google.com/]#",
		"[/www.google.com/]tls://1.1.1.1",
		"192.0.2.1",
	}

	config, _ := ParseUpstreamsConfig(upstreamsAddrs, &upstream.Options{
		Logger:             testLogger,
		InsecureSkipVerify: false,
		Bootstrap:          nil,
		Timeout:            testTimeout,
	})
	testutil.CleanupAndRequireSuccess(b, config.Close)

	domains := []string{
		"www.google.com.",
		"www2.google.com.",
		"internal.local.",
		"google.",
		"maps.google.com.",
	}

	var upstreams []upstream.Upstream
	l := len(domains)

	b.Run("get", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; b.Loop(); i++ {
			upstreams = config.getUpstreamsForDomain(domains[i%l])
		}

		assert.NotEmpty(b, upstreams)
	})

	// Most recent results:
	//
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/dnsproxy/proxy
	//	cpu: Apple M4 Pro
	//  BenchmarkUpstreamConfig_GetUpstreamsForDomain/get-14    48695488    24.51 ns/op     0 B/op	0 allocs/op
}

// assertUpstreamsAddrs checks the addresses of ups to exactly match want.
func assertUpstreamsAddrs(tb testing.TB, ups []upstream.Upstream, want []string) {
	tb.Helper()

	require.Len(tb, ups, len(want))
	for i, up := range ups {
		assert.Equalf(tb, want[i], up.Address(), "at index %d", i)
	}
}
