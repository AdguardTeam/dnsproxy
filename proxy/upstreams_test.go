package proxy_test

import (
	"testing"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpstreamConfig_ValidatePrivateConfig(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			upsConf, err := proxy.ParseUpstreamsConfig(set, nil)
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, upsConf.Close)

			testutil.AssertErrorMsg(t, tc.wantErr, proxy.ValidatePrivateConfig(upsConf, ss))
		})
	}
}

func TestUpstreamConfig_GetUpstreamsForDomain_noDuplicates(t *testing.T) {
	t.Parallel()

	upstreams := []string{"[/example.com/]1.1.1.1", "[/example.org/]1.1.1.1"}
	config, err := proxy.ParseUpstreamsConfig(upstreams, &upstream.Options{
		Logger:             testLogger,
		InsecureSkipVerify: false,
		Bootstrap:          nil,
		Timeout:            testTimeout,
	})
	assert.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, config.Close)

	assert.Len(t, config.Upstreams, 0)
	assert.Len(t, config.DomainReservedUpstreams, 2)

	u1 := config.DomainReservedUpstreams["example.com."][0]
	u2 := config.DomainReservedUpstreams["example.org."][0]

	// Check that the very same Upstream instance is used for both domains.
	assert.Same(t, u1, u2)
}
