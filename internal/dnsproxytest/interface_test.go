package dnsproxytest_test

import (
	"github.com/AdguardTeam/dnsproxy/internal/dnsmsg"
	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
)

// type checks
var (
	_ upstream.Upstream         = (*dnsproxytest.FakeUpstream)(nil)
	_ dnsmsg.MessageConstructor = (*dnsproxytest.TestMessageConstructor)(nil)
)
