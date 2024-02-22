package dnsproxytest_test

import (
	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
)

// type check
var _ upstream.Upstream = (*dnsproxytest.FakeUpstream)(nil)
