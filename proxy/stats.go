package proxy

import (
	"fmt"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

// upstreamWithStats is a wrapper around the [upstream.Upstream] interface that
// gathers statistics.
type upstreamWithStats struct {
	// upstream is the upstream DNS resolver.
	upstream upstream.Upstream

	// err is the DNS lookup error, if any.
	err error

	// queryDuration is the duration of the successful DNS lookup.
	queryDuration time.Duration
}

// type check
var _ upstream.Upstream = (*upstreamWithStats)(nil)

// Exchange implements the [upstream.Upstream] for *upstreamWithStats.
func (u *upstreamWithStats) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	start := time.Now()
	resp, err = u.upstream.Exchange(req)
	u.err = err
	u.queryDuration = time.Since(start)

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
func upstreamsWithStats(upstreams []upstream.Upstream) (wrapped []upstream.Upstream) {
	wrapped = make([]upstream.Upstream, 0, len(upstreams))
	for _, u := range upstreams {
		wrapped = append(wrapped, &upstreamWithStats{upstream: u})
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

// collectQueryStats gathers the statistics from the wrapped upstreams.
// resolver is an upstream DNS resolver that successfully resolved the request,
// if any.  Provided upstreams must be of type [*upstreamWithStats].  unwrapped
// is the unwrapped resolver, see [upstreamWithStats.upstream].  The returned
// statistics depend on whether the DNS request was successfully resolved and
// the upstream mode, see [DNSContext.QueryStatistics].
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
			panic(fmt.Errorf("unexpected type %T", resolver))
		}

		unwrapped = wrapped.upstream
	}

	// The DNS query was not resolved.
	if wrapped == nil {
		return nil, &QueryStatistics{
			main:     collectUpstreamStats(upstreams...),
			fallback: collectUpstreamStats(fallbacks...),
		}
	}

	// The DNS query was successfully resolved by main resolver and the upstream
	// mode is [UpstreamModeFastestAddr].
	if mode == UpstreamModeFastestAddr && len(fallbacks) == 0 {
		return unwrapped, &QueryStatistics{
			main: collectUpstreamStats(upstreams...),
		}
	}

	// The DNS query was resolved by fallback resolver.
	if len(fallbacks) > 0 {
		return unwrapped, &QueryStatistics{
			main:     collectUpstreamStats(upstreams...),
			fallback: collectUpstreamStats(wrapped),
		}
	}

	// The DNS query was successfully resolved by main resolver.
	return unwrapped, &QueryStatistics{
		main: collectUpstreamStats(wrapped),
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
func collectUpstreamStats(upstreams ...upstream.Upstream) (stats []*UpstreamStatistics) {
	stats = make([]*UpstreamStatistics, 0, len(upstreams))

	for _, u := range upstreams {
		w, ok := u.(*upstreamWithStats)
		if !ok {
			// Should never happen.
			panic(fmt.Errorf("unexpected type %T", u))
		}

		stats = append(stats, &UpstreamStatistics{
			Error:         w.err,
			Address:       w.Address(),
			QueryDuration: w.queryDuration,
		})
	}

	return stats
}
