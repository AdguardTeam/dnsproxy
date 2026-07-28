package ratelimit

import (
	"log/slog"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/validate"
)

// Config is the configuration for the ratelimit middleware.
type Config struct {
	// Logger is used for logging in the ratelimit middleware. It must not be
	// nil.
	Logger *slog.Logger

	// AllowlistAddrs is a slice of IP addresses excluded from rate limiting.
	AllowlistAddrs netutil.SliceSubnetSet

	// Ratelimit is a maximum number of requests per second from a given IP.  It
	// must be positive.
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

	return errors.Join(
		validate.Positive("Ratelimit", c.Ratelimit),
		validate.NotNil("Logger", c.Logger),
		validate.NoGreaterThan("SubnetLenIPv4", c.SubnetLenIPv4, netutil.IPv4BitLen),
		validate.NoGreaterThan("SubnetLenIPv4", c.SubnetLenIPv6, netutil.IPv6BitLen),
	)
}
