package ratelimit

import (
	"log/slog"
	"net/netip"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/validate"
)

// Config is the configuration for the ratelimit middleware.
type Config struct {
	// Logger is used for logging in the ratelimit middleware. It must not be
	// nil.
	Logger *slog.Logger

	// AllowlistAddrs is a list of IP addresses excluded from rate limiting.
	AllowlistAddrs []netip.Addr

	// Ratelimit is a maximum number of requests per second from a given IP (0
	// to disable).
	Ratelimit uint

	// SubnetLenIPv4 is a subnet length for IPv4 addresses used for rate
	// limiting requests.
	SubnetLenIPv4 uint

	// SubnetLenIPv6 is a subnet length for IPv6 addresses used for rate
	// limiting requests.
	SubnetLenIPv6 uint
}

// type check
var _ validate.Interface = (*Config)(nil)

// Validate implements the [validate.Interface] interface for *Config.
func (c *Config) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	if c.Ratelimit == 0 {
		return nil
	}

	return errors.Join(
		validate.NotNil("Logger", c.Logger),
		validate.LessThan("SubnetLenIPv4", c.SubnetLenIPv4, netutil.IPv4BitLen),
		validate.LessThan("SubnetLenIPv4", c.SubnetLenIPv6, netutil.IPv6BitLen),
	)
}
