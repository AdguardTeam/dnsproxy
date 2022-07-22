package proxy

import (
	"fmt"
	"strings"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/stringutil"

	"github.com/AdguardTeam/dnsproxy/upstream"
)

// UpstreamConfig is a wrapper for list of default upstreams and map of reserved domains and corresponding upstreams
type UpstreamConfig struct {
	Upstreams                []upstream.Upstream            // list of default upstreams
	DomainReservedUpstreams  map[string][]upstream.Upstream // map of reserved domains and lists of corresponding upstreams
	SpecifiedDomainUpstreams map[string][]upstream.Upstream // map of excluded domains and lists of corresponding upstreams
	SubdomainExclusions      *stringutil.Set                // set of domains with sub-domains exclusions
}

// ParseUpstreamsConfig returns UpstreamConfig and error if upstreams configuration is invalid
// default upstream syntax: <upstreamString>
// reserved upstream syntax: [/domain1/../domainN/]<upstreamString>
// subdomains only upstream syntax: [/*.domain1/../*.domainN]<upstreamString>
// More specific domains take priority over less specific domains,
// To exclude more specific domains from reserved upstreams querying you should use the following syntax: [/domain1/../domainN/]#
// So the following config: ["[/host.com/]1.2.3.4", "[/www.host.com/]2.3.4.5", "[/maps.host.com/]#", "3.4.5.6"]
// will send queries for *.host.com to 1.2.3.4, except for *.www.host.com, which will go to 2.3.4.5 and *.maps.host.com,
// which will go to default server 3.4.5.6 with all other domains.
// To exclude top level domain from reserved upstreams querying you could use the following: [/*.domain.com/]<upstreamString>
// So the following config: ["[/*.domain.com/]1.2.3.4", "3.4.5.6"] will send queries for all subdomains *.domain.com to 1.2.3.4,
// but domain.com query will be sent to default server 3.4.5.6 as every other query.
func ParseUpstreamsConfig(upstreamConfig []string, options *upstream.Options) (*UpstreamConfig, error) {
	if options == nil {
		options = &upstream.Options{}
	}

	if len(options.Bootstrap) > 0 {
		log.Debug("Bootstraps: %v", options.Bootstrap)
	}

	var upstreams []upstream.Upstream
	// We use this index to avoid creating duplicates of upstreams
	upstreamsIndex := map[string]upstream.Upstream{}

	domainReservedUpstreams := map[string][]upstream.Upstream{}
	specifiedDomainUpstreams := map[string][]upstream.Upstream{}
	subdomainsOnlyUpstreams := map[string][]upstream.Upstream{}
	subdomainsOnlyExclusions := stringutil.NewSet()

	for i, l := range upstreamConfig {
		u, hosts, err := parseUpstreamLine(l)
		if err != nil {
			return &UpstreamConfig{}, err
		}

		// # excludes more specific domain from reserved upstreams querying
		if u == "#" && len(hosts) > 0 {
			for _, host := range hosts {
				if strings.HasPrefix(host, "*.") {
					host = host[len("*."):]

					subdomainsOnlyExclusions.Add(host)
					subdomainsOnlyUpstreams[host] = nil
				} else if strings.HasPrefix(host, "*-") {
					subdomainsOnlyUpstreams[host[len("*"):]] = nil

					host = host[len("*-"):]
					subdomainsOnlyExclusions.Add(host)
				} else {
					domainReservedUpstreams[host] = nil
					specifiedDomainUpstreams[host] = nil
				}
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
					})

				if err != nil {
					err = fmt.Errorf("cannot prepare the upstream %s (%s): %s", l, options.Bootstrap, err)

					return &UpstreamConfig{}, err
				}

				// save to the index
				upstreamsIndex[u] = dnsUpstream
			}

			if len(hosts) == 0 {
				log.Debug("Upstream %d: %s", i, dnsUpstream.Address())
				upstreams = append(upstreams, dnsUpstream)

				continue
			}

			for _, host := range hosts {
				if strings.HasPrefix(host, "*.") {
					host = host[len("*."):]

					subdomainsOnlyExclusions.Add(host)
					log.Debug("domain %s is added to exclusions list", host)

					subdomainsOnlyUpstreams[host] = append(subdomainsOnlyUpstreams[host], dnsUpstream)
				} else if strings.HasPrefix(host, "*-") {
					subdomainsOnlyExclusions.Add(host[len("*-"):])
					log.Debug("domain %s is added to exclusions list", host[len("*-"):])

					host = host[len("*"):]
					subdomainsOnlyUpstreams[host] = append(subdomainsOnlyUpstreams[host], dnsUpstream)
				} else {
					specifiedDomainUpstreams[host] = append(specifiedDomainUpstreams[host], dnsUpstream)
				}

				domainReservedUpstreams[host] = append(domainReservedUpstreams[host], dnsUpstream)
			}

			log.Debug("Upstream %d: %s is reserved for next domains: %s",
				i, dnsUpstream.Address(), strings.Join(hosts, ", "))
		}
	}

	for host, ups := range subdomainsOnlyUpstreams {
		// Rewrite ups for wildcard subdomains to remove upper level domains specs.
		domainReservedUpstreams[host] = ups
	}

	return &UpstreamConfig{
		Upstreams:                upstreams,
		DomainReservedUpstreams:  domainReservedUpstreams,
		SpecifiedDomainUpstreams: specifiedDomainUpstreams,
		SubdomainExclusions:      subdomainsOnlyExclusions,
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
		for _, confHost := range strings.Split(domainsAndUpstream[0], "/") {
			if confHost != "" {
				host := confHost
				host = strings.TrimPrefix(host, "*.")
				host = strings.TrimPrefix(host, "*-")
				if err := netutil.ValidateDomainName(host); err != nil {
					return "", nil, err
				}

				hosts = append(hosts, strings.ToLower(confHost+"."))
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

		if uc.SubdomainExclusions.Has(host) {
			ups, ok := uc.SpecifiedDomainUpstreams[host]
			if ok && len(ups) > 0 {
				return ups
			}

			// Check if there is a spec for upper level domain.
			h := strings.SplitAfterN(host, ".", 2)
			ups, ok = uc.DomainReservedUpstreams[h[1]]
			if ok && len(ups) > 0 {
				return ups
			}

			return uc.Upstreams
		}
	}

	for i := 1; i <= dotsCount; i++ {
		h := strings.SplitAfterN(host, ".", i)
		name := h[i-1]

		var ok bool

		if i := strings.Index(name, "-"); i >= 0 {
			ups, ok = uc.DomainReservedUpstreams[name[i:]]
			if ok && len(ups) > 0 {
				return ups
			}
		}

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
