package proxy

import (
	"context"
	"encoding/hex"
	"log/slog"
	"sync"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// cachingResolver is the DNS resolver that is also able to cache responses.
type cachingResolver interface {
	// replyFromUpstream returns true if the request from dctx is successfully
	// resolved and the response may be cached.
	//
	// TODO(e.burkov):  Find out when ok can be false with nil err.
	replyFromUpstream(dctx *DNSContext) (ok bool, err error)

	// cacheResp caches the response from dctx.
	cacheResp(dctx *DNSContext)
}

// type check
var _ cachingResolver = (*Proxy)(nil)

// optimisticResolver is used to eventually resolve expired cached requests.
type optimisticResolver struct {
	reqs *sync.Map
	cr   cachingResolver
}

// newOptimisticResolver returns the new resolver for expired cached requests.
// cr must not be nil.
func newOptimisticResolver(cr cachingResolver) (s *optimisticResolver) {
	return &optimisticResolver{
		reqs: &sync.Map{},
		cr:   cr,
	}
}

// unit is a convenient alias for struct{}.
type unit = struct{}

// resolveOnce tries to resolve the request from dctx but only a single request
// with the same key at the same period of time.  It runs in a separate
// goroutine.  Do not pass the *DNSContext which is used elsewhere since it
// isn't intended to be used concurrently.
func (s *optimisticResolver) resolveOnce(dctx *DNSContext, key []byte, l *slog.Logger) {
	defer slogutil.RecoverAndLog(context.TODO(), l)

	keyHexed := hex.EncodeToString(key)
	if _, ok := s.reqs.LoadOrStore(keyHexed, unit{}); ok {
		return
	}
	defer s.reqs.Delete(keyHexed)

	ok, err := s.cr.replyFromUpstream(dctx)
	if err != nil {
		l.Debug("resolving request for optimistic cache", slogutil.KeyError, err)
	}

	if ok {
		s.cr.cacheResp(dctx)
	}
}
