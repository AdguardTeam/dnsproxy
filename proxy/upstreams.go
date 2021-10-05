package proxy

import (
	"fmt"
	"strings"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"

	"github.com/AdguardTeam/dnsproxy/upstream"
)

// UpstreamConfig is a wrapper for list of default upstreams and map of reserved domains and corresponding upstreams
type UpstreamConfig struct {
	Upstreams               []upstream.Upstream            // list of default upstreams
	DomainReservedUpstreams map[string][]upstream.Upstream // map of reserved domains and lists of corresponding upstreams
}

// ParseUpstreamsConfig returns UpstreamConfig and error if upstreams configuration is invalid
// default upstream syntax: <upstreamString>
// reserved upstream syntax: [/domain1/../domainN/]<upstreamString>
// More specific domains take priority over less specific domains,
// To exclude more specific domains from reserved upstreams querying you should use the following syntax: [/domain1/../domainN/]#
// So the following config: ["[/host.com/]1.2.3.4", "[/www.host.com/]2.3.4.5", "[/maps.host.com/]#", "3.4.5.6"]
// will send queries for *.host.com to 1.2.3.4, except for *.www.host.com, which will go to 2.3.4.5 and *.maps.host.com,
// which will go to default server 3.4.5.6 with all other domains
func ParseUpstreamsConfig(upstreamConfig []string, options *upstream.Options) (*UpstreamConfig, error) {
	if options == nil {
		options = &upstream.Options{}
	}

	var upstreams []upstream.Upstream
	domainReservedUpstreams := map[string][]upstream.Upstream{}

	if len(options.Bootstrap) > 0 {
		log.Debug("Bootstraps: %v", options.Bootstrap)
	}

	// We use this index to avoid creating duplicates of upstreams
	upstreamsIndex := map[string]upstream.Upstream{}

	for i, l := range upstreamConfig {
		u, hosts, err := parseUpstreamLine(l)
		if err != nil {
			return &UpstreamConfig{}, err
		}

		// # excludes more specific domain from reserved upstreams querying
		if u == "#" && len(hosts) > 0 {
			for _, host := range hosts {
				domainReservedUpstreams[host] = nil
			}
		} else {
			dnsUpstream, ok := upstreamsIndex[u]
			if !ok {
				// create an upstream
				dnsUpstream, err = upstream.AddressToUpstream(
					u,
					&upstream.Options{
						Bootstrap:          options.Bootstrap,
						Timeout:            options.Timeout,
						InsecureSkipVerify: options.InsecureSkipVerify,
						TLSClientConfig:    options.TLSClientConfig.Clone(), //TODO Verify i we need an if
						TLSClient:          options.TLSClient,
					})
				if err != nil {
					err = fmt.Errorf("cannot prepare the upstream %s (%s): %s", l, options.Bootstrap, err)
					return &UpstreamConfig{}, err
				}

				// save to the index
				upstreamsIndex[u] = dnsUpstream
			}

			if len(hosts) > 0 {
				for _, host := range hosts {
					_, ok := domainReservedUpstreams[host]
					if !ok {
						domainReservedUpstreams[host] = []upstream.Upstream{}
					}
					domainReservedUpstreams[host] = append(domainReservedUpstreams[host], dnsUpstream)
				}
				log.Debug("Upstream %d: %s is reserved for next domains: %s",
					i, dnsUpstream.Address(), strings.Join(hosts, ", "))
			} else {
				log.Debug("Upstream %d: %s", i, dnsUpstream.Address())
				upstreams = append(upstreams, dnsUpstream)
			}
		}
	}

	return &UpstreamConfig{
		Upstreams:               upstreams,
		DomainReservedUpstreams: domainReservedUpstreams,
	}, nil
}

// parseUpstreamLine - parses upstream line and returns the following:
// upstream address
// list of domains for which this upstream is reserved (may be nil)
// error if something went wrong
func parseUpstreamLine(l string) (string, []string, error) {
	var hosts []string
	u := l

	if strings.HasPrefix(l, "[/") {
		// split domains and upstream string
		domainsAndUpstream := strings.Split(strings.TrimPrefix(l, "[/"), "/]")
		if len(domainsAndUpstream) != 2 {
			return "", nil, fmt.Errorf("wrong upstream specification: %s", l)
		}

		// split domains list
		for _, host := range strings.Split(domainsAndUpstream[0], "/") {
			if host != "" {
				if err := netutil.ValidateDomainName(host); err != nil {
					return "", nil, err
				}
				hosts = append(hosts, strings.ToLower(host+"."))
			} else {
				// empty domain specification means `unqualified names only`
				hosts = append(hosts, UnqualifiedNames)
			}
		}
		u = domainsAndUpstream[1]
	}

	return u, hosts, nil
}

// getUpstreamsForDomain looks for a domain in reserved domains map and returns a list of corresponding upstreams.
// returns default upstreams list if domain isn't found. More specific domains take priority over less specific domains.
// For example, map contains the following keys: host.com and www.host.com
// If we are looking for domain mail.host.com, this method will return value of host.com key
// If we are looking for domain www.host.com, this method will return value of www.host.com key
// If more specific domain value is nil, it means that domain was excluded and should be exchanged with default upstreams
func (uc *UpstreamConfig) getUpstreamsForDomain(host string) (ups []upstream.Upstream) {
	if len(uc.DomainReservedUpstreams) == 0 {
		return uc.Upstreams
	}

	dotsCount := strings.Count(host, ".")
	if dotsCount < 2 {
		host = UnqualifiedNames
	} else {
		host = strings.ToLower(host)
	}

	for i := 1; i <= dotsCount; i++ {
		h := strings.SplitAfterN(host, ".", i)
		name := h[i-1]

		var ok bool
		ups, ok = uc.DomainReservedUpstreams[name]
		if !ok {
			continue
		}

		if len(ups) == 0 {
			// The domain has been excluded from reserved upstreams
			// querying.
			return uc.Upstreams
		}

		return ups
	}

	return uc.Upstreams
}
