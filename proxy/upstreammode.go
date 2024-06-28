package proxy

import (
	"encoding"
	"fmt"
)

// UpstreamMode is an enumeration of upstream mode representations.
type UpstreamMode string

const (
	UpstreamModeLoadBalance UpstreamMode = "load_balance"
	UpstreamModeParallel    UpstreamMode = "parallel"
	UpstreamModeFastestAddr UpstreamMode = "fastest_addr"
)

// type check
var _ encoding.TextUnmarshaler = (*UpstreamMode)(nil)

// UnmarshalText implements [encoding.TextUnmarshaler] interface for
// *UpstreamMode.
func (m *UpstreamMode) UnmarshalText(b []byte) (err error) {
	switch string(b) {
	case "load_balance":
		*m = UpstreamModeLoadBalance
	case "parallel":
		*m = UpstreamModeParallel
	case "fastest_addr":
		*m = UpstreamModeFastestAddr
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
var _ encoding.TextMarshaler = (*UpstreamMode)(nil)

// MarshalText implements [encoding.TextMarshaler] interface for *UpstreamMode.
func (m *UpstreamMode) MarshalText() (text []byte, err error) {
	return []byte(*m), nil
}
