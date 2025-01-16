package proxy

import (
	"fmt"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

// upstreamWithStats is a wrapper around the [upstream.Upstream] interface that
// gathers statistics.
type upstreamWithStats struct {
	// upstream is the upstream DNS resolver.
	upstream upstream.Upstream

	// mu protects err and queryDuration.
	mu *sync.Mutex

	// err is the DNS lookup error, if any.
	err error

	// queryDuration is the duration of the successful DNS lookup.
	queryDuration time.Duration

	// isFallback indicates whether the upstream is a fallback upstream.
	isFallback bool
}

// newUpstreamWithStats returns a new initialized *upstreamWithStats.
func newUpstreamWithStats(upstream upstream.Upstream, isFallback bool) (u *upstreamWithStats) {
	return &upstreamWithStats{
		upstream:   upstream,
		mu:         &sync.Mutex{},
		isFallback: isFallback,
	}
}

// stats returns the stored statistics.
func (u *upstreamWithStats) stats() (dur time.Duration, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	return u.queryDuration, u.err
}

// type check
var _ upstream.Upstream = (*upstreamWithStats)(nil)

// Exchange implements the [upstream.Upstream] for *upstreamWithStats.
func (u *upstreamWithStats) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	start := time.Now()
	resp, err = u.upstream.Exchange(req)
	dur := time.Since(start)

	u.mu.Lock()
	defer u.mu.Unlock()

	u.err = err
	u.queryDuration = dur

	return resp, err
}

// Address implements the [upstream.Upstream] for *upstreamWithStats.
func (u *upstreamWithStats) Address() (addr string) {
	return u.upstream.Address()
}

// Close implements the [upstream.Upstream] for *upstreamWithStats.
func (u *upstreamWithStats) Close() (err error) {
	return u.upstream.Close()
}

// upstreamsWithStats takes a list of upstreams, wraps each upstream with
// [upstreamWithStats] to gather statistics, and returns the wrapped upstreams.
func upstreamsWithStats(
	upstreams []upstream.Upstream,
	isFallback bool,
) (wrapped []upstream.Upstream) {
	wrapped = make([]upstream.Upstream, 0, len(upstreams))
	for _, u := range upstreams {
		w := newUpstreamWithStats(u, isFallback)
		wrapped = append(wrapped, w)
	}

	return wrapped
}

// QueryStatistics contains the DNS query statistics for both the upstream and
// fallback DNS servers.
type QueryStatistics struct {
	main     []*UpstreamStatistics
	fallback []*UpstreamStatistics
}

// cachedQueryStatistics returns the DNS query statistics for cached queries.
func cachedQueryStatistics(addr string) (s *QueryStatistics) {
	return &QueryStatistics{
		main: []*UpstreamStatistics{{
			Address:  addr,
			IsCached: true,
		}},
	}
}

// Main returns the DNS query statistics for the upstream DNS servers.
func (s *QueryStatistics) Main() (us []*UpstreamStatistics) {
	return s.main
}

// Fallback returns the DNS query statistics for the fallback DNS servers.
func (s *QueryStatistics) Fallback() (us []*UpstreamStatistics) {
	return s.fallback
}

// collectQueryStats gathers the statistics from the wrapped upstreams,
// considering the upstream mode.  resolver is an upstream DNS resolver that
// successfully resolved the request, and it will be unwrapped.  If resolver is
// nil (i.e. the DNS query was not resolved) or upstream mode is
// [UpstreamModeFastestAddr], the function returns the gathered statistics for
// both the upstream and fallback DNS servers.  If resolver is fallback, it also
// gathers the statistics for the upstreams.  Otherwise, it returns the query
// statistics specifically for upstream resolver.  Provided upstreams must be of
// type *upstreamWithStats.
func collectQueryStats(
	mode UpstreamMode,
	resolver upstream.Upstream,
	upstreams []upstream.Upstream,
	fallbacks []upstream.Upstream,
) (unwrapped upstream.Upstream, stats *QueryStatistics) {
	var wrapped *upstreamWithStats
	if resolver != nil {
		var ok bool
		wrapped, ok = resolver.(*upstreamWithStats)
		if !ok {
			// Should never happen.
			err := fmt.Errorf("unexpected type %T", resolver)
			panic(err)
		}

		unwrapped = wrapped.upstream
	}

	if wrapped == nil || mode == UpstreamModeFastestAddr {
		return unwrapped, &QueryStatistics{
			main:     collectUpstreamStats(upstreams),
			fallback: collectUpstreamStats(fallbacks),
		}
	}

	return unwrapped, collectResolverQueryStats(upstreams, wrapped)
}

// collectResolverQueryStats gathers the statistics from an upstream DNS
// resolver that successfully resolved the request.  If resolver is the fallback
// DNS resolver, it also gathers the statistics for the upstream DNS resolvers.
// resolver must be not nil.
func collectResolverQueryStats(
	upstreams []upstream.Upstream,
	resolver *upstreamWithStats,
) (stats *QueryStatistics) {
	dur, err := resolver.stats()
	s := &UpstreamStatistics{
		Address:       resolver.upstream.Address(),
		Error:         err,
		QueryDuration: dur,
	}

	if resolver.isFallback {
		return &QueryStatistics{
			main:     collectUpstreamStats(upstreams),
			fallback: []*UpstreamStatistics{s},
		}
	}

	return &QueryStatistics{
		main: []*UpstreamStatistics{s},
	}
}

// UpstreamStatistics contains the DNS query statistics.
type UpstreamStatistics struct {
	// Error is the DNS lookup error, if any.
	Error error

	// Address is the address of the upstream DNS resolver.
	//
	// TODO(s.chzhen):  Use [upstream.Upstream] when [cacheItem] starts to
	// contain one.
	Address string

	// QueryDuration is the duration of the successful DNS lookup.
	QueryDuration time.Duration

	// IsCached indicates whether the response was served from a cache.
	IsCached bool
}

// collectUpstreamStats gathers the upstream statistics from the list of wrapped
// upstreams.  upstreams must be of type *upstreamWithStats.
func collectUpstreamStats(upstreams []upstream.Upstream) (stats []*UpstreamStatistics) {
	stats = make([]*UpstreamStatistics, 0, len(upstreams))

	for _, u := range upstreams {
		w, ok := u.(*upstreamWithStats)
		if !ok {
			// Should never happen.
			err := fmt.Errorf("unexpected type %T", u)
			panic(err)
		}

		dur, err := w.stats()
		stats = append(stats, &UpstreamStatistics{
			Error:         err,
			Address:       w.Address(),
			QueryDuration: dur,
		})
	}

	return stats
}
