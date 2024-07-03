package proxy

import (
	"encoding"
	"fmt"
)

// UpstreamMode is an enumeration of upstream mode representations.
//
// TODO(d.kolyshev): Set uint8 as underlying type.
type UpstreamMode string

const (
	// UpstreamModeLoadBalance is the default upstream mode.  It balances the
	// upstreams load.
	UpstreamModeLoadBalance UpstreamMode = "load_balance"

	// UpstreamModeParallel makes server to query all configured upstream
	// servers in parallel.
	UpstreamModeParallel UpstreamMode = "parallel"

	// UpstreamModeFastestAddr controls whether the server should respond to A
	// or AAAA requests only with the fastest IP address detected by ICMP
	// response time or TCP connection time.
	UpstreamModeFastestAddr UpstreamMode = "fastest_addr"
)

// type check
var _ encoding.TextUnmarshaler = (*UpstreamMode)(nil)

// UnmarshalText implements [encoding.TextUnmarshaler] interface for
// *UpstreamMode.
func (m *UpstreamMode) UnmarshalText(b []byte) (err error) {
	switch um := UpstreamMode(b); um {
	case
		UpstreamModeLoadBalance,
		UpstreamModeParallel,
		UpstreamModeFastestAddr:
		*m = um
	default:
		return fmt.Errorf(
			"invalid upstream mode %q, supported: %q, %q, %q",
			b,
			UpstreamModeLoadBalance,
			UpstreamModeParallel,
			UpstreamModeFastestAddr,
		)
	}

	return nil
}

// type check
var _ encoding.TextMarshaler = UpstreamMode("")

// MarshalText implements [encoding.TextMarshaler] interface for UpstreamMode.
func (m UpstreamMode) MarshalText() (text []byte, err error) {
	return []byte(m), nil
}
