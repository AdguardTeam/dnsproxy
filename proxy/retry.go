package proxy

import (
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/errors"
)

// BindRetryConfig contains configuration for the listeners binding retry
// mechanism.
type BindRetryConfig struct {
	// Enabled indicates whether the binding should be retried.
	Enabled bool

	// Limit is the maximum number of retries, which don't include the first
	// attempt.
	Limit uint

	// Interval is the minimum time to wait between retries.  It must not be
	// negative if retrying is enabled.
	Interval time.Duration
}

// withRetry calls f until it returns no error or the retries limit is reached,
// sleeping for ivl between attempts.  retries is the number of attempts after
// the first one.
func withRetry[T any](
	f func() (res T, err error),
	ivl time.Duration,
	retries uint,
) (res T, err error) {
	res, err = f()
	if err == nil {
		return res, nil
	}

	errs := []error{
		fmt.Errorf("attempt 1: %w", err),
	}

	for attempt := uint(1); attempt <= retries; attempt++ {
		time.Sleep(ivl)

		res, err = f()
		if err == nil {
			return res, nil
		}

		errs = append(errs, fmt.Errorf("attempt %d: %w", attempt+1, err))
	}

	return res, errors.Join(errs...)
}
