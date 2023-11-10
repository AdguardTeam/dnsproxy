package proxy

import (
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpstreamConfig_GetUpstreamsForDomain(t *testing.T) {
	upstreams := []string{
		"[/google.com/local/]4.3.2.1",
		"[/www.google.com//]1.2.3.4",
		"[/maps.google.com/]#",
		"[/www.google.com/]tls://1.1.1.1",
		"[/_acme-challenge.example.org/]#",
		"[/example.com/]1.1.1.1 2.2.2.2 3.3.3.3",
	}

	config, err := ParseUpstreamsConfig(
		upstreams,
		&upstream.Options{
			InsecureSkipVerify: false,
			Bootstrap:          nil,
			Timeout:            1 * time.Second,
		},
	)
	require.NoError(t, err)

	testCases := []struct {
		name string
		in   string
		want []string
	}{{
		name: "direct_match",
		in:   "www.google.com.",
		want: []string{"1.2.3.4:53", "tls://1.1.1.1:853"},
	}, {
		name: "subdomain_match",
		in:   "www2.google.com.",
		want: []string{"4.3.2.1:53"},
	}, {
		name: "second_subdomain_match",
		in:   "internal.local.",
		want: []string{"4.3.2.1:53"},
	}, {
		name: "unqualified_match",
		in:   "google.",
		want: []string{"1.2.3.4:53"},
	}, {
		name: "default",
		in:   "_acme-challenge.example.org.",
		want: []string{},
	}, {
		name: "another_default",
		in:   "maps.google.com.",
		want: []string{},
	}, {
		name: "multiple_reserved",
		in:   "example.com.",
		want: []string{"1.1.1.1:53", "2.2.2.2:53", "3.3.3.3:53"},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ups := config.getUpstreamsForDomain(tc.in)
			assertUpstreamsForDomain(t, ups, tc.want)
		})
	}
}

func TestUpstreamConfig_GetUpstreamsForDS(t *testing.T) {
	upstreams := []string{
		"[/google.com/local/]4.3.2.1",
		"[/www.google.com//]1.2.3.4",
		"[/maps.google.com/]#",
		"[/www.google.com/]tls://1.1.1.1",
		"[/_acme-challenge.example.org/]#",
	}

	config, err := ParseUpstreamsConfig(
		upstreams,
		&upstream.Options{
			InsecureSkipVerify: false,
			Timeout:            1 * time.Second,
		},
	)
	require.NoError(t, err)

	testCases := []struct {
		name string
		in   string
		want []string
	}{{
		name: "direct_match",
		in:   "www.google.com.",
		want: []string{"4.3.2.1:53"},
	}, {
		name: "subdomain_match",
		in:   "abc.www.google.com.",
		want: []string{"1.2.3.4:53", "tls://1.1.1.1:853"},
	}, {
		name: "unqualified_match",
		in:   "internal.local.",
		want: []string{"1.2.3.4:53"},
	}, {
		name: "more_unqualified_match",
		in:   "google.",
		want: []string{"1.2.3.4:53"},
	}, {
		name: "default",
		in:   "_acme-challenge.example.org.",
		want: []string{},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ups := config.getUpstreamsForDS(tc.in)
			assertUpstreamsForDomain(t, ups, tc.want)
		})
	}
}

func TestUpstreamConfig_Validate(t *testing.T) {
	testCases := []struct {
		name            string
		wantValidateErr error
		in              []string
	}{{
		name:            "empty",
		wantValidateErr: upstream.ErrNoUpstreams,
		in:              []string{},
	}, {
		name:            "nil",
		wantValidateErr: upstream.ErrNoUpstreams,
		in:              nil,
	}, {
		name:            "valid",
		wantValidateErr: nil,
		in: []string{
			"udp://upstream.example:53",
		},
	}, {
		name:            "no_default",
		wantValidateErr: errNoDefaultUpstreams,
		in: []string{
			"[/domain.example/]udp://upstream.example:53",
			"[/another.domain.example/]#",
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ParseUpstreamsConfig(tc.in, nil)
			require.NoError(t, err)

			assert.ErrorIs(t, c.validate(), tc.wantValidateErr)
		})
	}

	t.Run("actual_nil", func(t *testing.T) {
		assert.ErrorIs(t, (*UpstreamConfig)(nil).validate(), errNoDefaultUpstreams)
	})
}

func TestGetUpstreamsForDomainWithoutDuplicates(t *testing.T) {
	upstreams := []string{"[/example.com/]1.1.1.1", "[/example.org/]1.1.1.1"}
	config, err := ParseUpstreamsConfig(
		upstreams,
		&upstream.Options{
			InsecureSkipVerify: false,
			Bootstrap:          nil,
			Timeout:            1 * time.Second,
		},
	)
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
			assertUpstreamsForDomain(t, ups, tc.want)
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
			assertUpstreamsForDomain(t, ups, tc.want)
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
			assertUpstreamsForDomain(t, ups, tc.want)
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

	config, _ := ParseUpstreamsConfig(
		upstreams,
		&upstream.Options{
			InsecureSkipVerify: false,
			Bootstrap:          nil,
			Timeout:            1 * time.Second,
		},
	)

	domains := []string{
		"www.google.com.",
		"www2.google.com.",
		"internal.local.",
		"google.",
		"maps.google.com.",
	}

	for i, l := 0, len(domains); i < b.N; i++ {
		upsSink = config.getUpstreamsForDomain(domains[i%l])
	}
}

// assertUpstreamsForDomain checks the addresses of the specified domain
// upstreams and their number.
func assertUpstreamsForDomain(tb testing.TB, ups []upstream.Upstream, want []string) {
	tb.Helper()

	require.Len(tb, ups, len(want))
	for i, up := range ups {
		assert.Equalf(tb, want[i], up.Address(), "bad upstream at index %d", i)
	}
}
