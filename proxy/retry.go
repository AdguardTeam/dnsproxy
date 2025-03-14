package proxy

import (
	"context"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// BindRetryConfig contains configuration for the listeners binding retry
// mechanism.
type BindRetryConfig struct {
	// Enabled indicates whether the binding should be retried.
	Enabled bool

	// Count is the maximum number of retries after the first attempt.
	Count uint

	// Interval is the minimum time to wait after the latest failure.  It must
	// not be negative if Enabled is true.
	Interval time.Duration
}

// bindWithRetry calls f until it returns no error or the retries limit is
// reached, sleeping for configured interval between attempts.  bindFunc should
// carry the result of the binding operation itself.
func (p *Proxy) bindWithRetry(ctx context.Context, bindFunc func() (err error)) (err error) {
	err = bindFunc()
	if err == nil {
		return nil
	}

	p.logger.WarnContext(ctx, "binding", "attempt", 1, slogutil.KeyError, err)

	for attempt := uint(1); attempt <= p.bindRetryNum; attempt++ {
		time.Sleep(p.bindRetryIvl)

		retryErr := bindFunc()
		if retryErr == nil {
			return nil
		}

		p.logger.WarnContext(ctx, "binding", "attempt", attempt+1, slogutil.KeyError, retryErr)
	}

	return err
}
