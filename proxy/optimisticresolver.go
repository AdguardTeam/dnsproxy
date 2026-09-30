package proxy

import (
	"context"
	"encoding/hex"
	"log/slog"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/syncutil"
)

// cachingResolver is the DNS resolver that is also able to cache responses.
type cachingResolver interface {
	// replyFromUpstream returns true if the request from dctx is successfully
	// resolved and the response may be cached.
	//
	// TODO(e.burkov):  Find out when ok can be false with nil err.
	replyFromUpstream(ctx context.Context, dctx *DNSContext) (ok bool, err error)

	// cacheResp caches the response from dctx.
	cacheResp(dctx *DNSContext)
}

// type check
var _ cachingResolver = (*Proxy)(nil)

// unit is a convenient alias for struct{}.
type unit = struct{}

// optimisticResolver is used to eventually resolve expired cached requests.
type optimisticResolver struct {
	reqs *syncutil.Map[string, unit]
	cr   cachingResolver
}

// newOptimisticResolver returns the new resolver for expired cached requests.
// cr must not be nil.
func newOptimisticResolver(cr cachingResolver) (s *optimisticResolver) {
	return &optimisticResolver{
		reqs: syncutil.NewMap[string, unit](),
		cr:   cr,
	}
}

// resolveOnce tries to resolve the request from dctx but only a single request
// with the same key at the same period of time.  It runs in a separate
// goroutine.  Do not pass the *DNSContext which is used elsewhere since it
// isn't intended to be used concurrently.
func (s *optimisticResolver) resolveOnce(
	ctx context.Context,
	dctx *DNSContext,
	key []byte,
	l *slog.Logger,
) {
	defer slogutil.RecoverAndLog(ctx, l)

	keyHexed := hex.EncodeToString(key)
	if _, ok := s.reqs.LoadOrStore(keyHexed, unit{}); ok {
		return
	}
	defer s.reqs.Delete(keyHexed)

	// NOTE: Discard the context deadline to prevent cancellation during
	// refresh.
	ok, err := s.cr.replyFromUpstream(context.WithoutCancel(ctx), dctx)
	if err != nil {
		l.DebugContext(ctx, "resolving request for optimistic cache", slogutil.KeyError, err)
	}

	if ok {
		s.cr.cacheResp(dctx)
	}
}
