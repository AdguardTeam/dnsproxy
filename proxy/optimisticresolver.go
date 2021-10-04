package proxy

import (
	"encoding/hex"
	"sync"

	"github.com/AdguardTeam/golibs/log"
)

// resolveFunc is the signature of a method to resolve expired cached requests.
// This is exactly the signature of Proxy.replyFromUpstream.
type resolveFunc func(dctx *DNSContext) (ok bool, err error)

// setFunc is the signature of a method to cache response.  This is exactly the
// signature of Proxy.setInCache method.
type setFunc func(dctx *DNSContext)

// deleteFunc is the signature of a method to remove the response from cache.
type deleteFunc func(key []byte)

// optimisticResolver is used to eventually resolve expired cached requests.
//
// TODO(e.burkov):  Think about generalizing all function-fields into a single
// interface.
type optimisticResolver struct {
	reqs    *sync.Map
	resolve resolveFunc
	set     setFunc
	delete  deleteFunc
}

// newOptimisticResolver returns the new resolver for expired cached requests.
func newOptimisticResolver(rf resolveFunc, sf setFunc, df deleteFunc) (s *optimisticResolver) {
	return &optimisticResolver{
		reqs:    &sync.Map{},
		resolve: rf,
		set:     sf,
		delete:  df,
	}
}

// unit is a convenient alias for struct{}.
type unit = struct{}

// ResolveOnce tries to resolve the request from dctx but only a single request
// with the same key at the same period of time.  It runs in a separate
// goroutine.  Do not pass the *DNSContext which is used elsewhere since it
// isn't intended to be used concurrently.
func (s *optimisticResolver) ResolveOnce(dctx *DNSContext, key []byte) {
	defer log.OnPanic("optimistic resolver")

	keyHexed := hex.EncodeToString(key)
	if _, ok := s.reqs.LoadOrStore(keyHexed, unit{}); ok {
		return
	}
	defer s.reqs.Delete(keyHexed)

	ok, err := s.resolve(dctx)
	if err != nil {
		log.Debug("resolving request for optimistic cache: %s", err)
	}

	if ok {
		s.set(dctx)
	} else {
		s.delete(key)
	}
}
