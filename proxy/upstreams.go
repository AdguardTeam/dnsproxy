package proxy

import (
	"fmt"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/utils"

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
func ParseUpstreamsConfig(upstreamConfig, bootstrapDNS []string, timeout time.Duration) (UpstreamConfig, error) {
	var upstreams []upstream.Upstream
	domainReservedUpstreams := map[string][]upstream.Upstream{}

	if len(bootstrapDNS) > 0 {
		for i, b := range bootstrapDNS {
			log.Info("Bootstrap %d: %s", i, b)
		}
	}

	for i, u := range upstreamConfig {
		hosts := []string{}
		if strings.HasPrefix(u, "[/") {
			// split domains and upstream string
			domainsAndUpstream := strings.Split(strings.TrimPrefix(u, "[/"), "/]")
			if len(domainsAndUpstream) != 2 {
				return UpstreamConfig{}, fmt.Errorf("wrong upstream specification: %s", u)
			}

			// split domains list
			for _, host := range strings.Split(domainsAndUpstream[0], "/") {
				if host != "" {
					if err := utils.IsValidHostname(host); err != nil {
						return UpstreamConfig{}, err
					}
					hosts = append(hosts, strings.ToLower(host+"."))
				} else {
					// empty domain specification means `unqualified names only`
					hosts = append(hosts, UnqualifiedNames)
				}
			}
			u = domainsAndUpstream[1]
		}

		// # excludes more specific domain from reserved upstreams querying
		if u == "#" && len(hosts) > 0 {
			for _, host := range hosts {
				domainReservedUpstreams[host] = nil
			}
			continue
		}

		// create an upstream
		dnsUpstream, err := upstream.AddressToUpstream(u, upstream.Options{Bootstrap: bootstrapDNS, Timeout: timeout})
		if err != nil {
			return UpstreamConfig{}, fmt.Errorf("cannot prepare the upstream %s (%s): %s", u, bootstrapDNS, err)
		}

		if len(hosts) > 0 {
			for _, host := range hosts {
				_, ok := domainReservedUpstreams[host]
				if !ok {
					domainReservedUpstreams[host] = []upstream.Upstream{}
				}
				domainReservedUpstreams[host] = append(domainReservedUpstreams[host], dnsUpstream)
			}
			log.Printf("Upstream %d: %s is reserved for next domains: %s", i, dnsUpstream.Address(), strings.Join(hosts, ", "))
		} else {
			log.Printf("Upstream %d: %s", i, dnsUpstream.Address())
			upstreams = append(upstreams, dnsUpstream)
		}
	}
	return UpstreamConfig{Upstreams: upstreams, DomainReservedUpstreams: domainReservedUpstreams}, nil
}

// getUpstreamsForDomain looks for a domain in reserved domains map and returns a list of corresponding upstreams.
// returns default upstreams list if domain isn't found. More specific domains take priority over less specific domains.
// For example, map contains the following keys: host.com and www.host.com
// If we are looking for domain mail.host.com, this method will return value of host.com key
// If we are looking for domain www.host.com, this method will return value of www.host.com key
// If more specific domain value is nil, it means that domain was excluded and should be exchanged with default upstreams
func (uc *UpstreamConfig) getUpstreamsForDomain(host string) []upstream.Upstream {
	if len(uc.DomainReservedUpstreams) == 0 {
		return uc.Upstreams
	}

	dotsCount := strings.Count(host, ".")
	if dotsCount < 2 {
		return uc.DomainReservedUpstreams[UnqualifiedNames]
	}

	for i := 1; i <= dotsCount; i++ {
		h := strings.SplitAfterN(host, ".", i)
		name := h[i-1]
		if u, ok := uc.DomainReservedUpstreams[strings.ToLower(name)]; ok {
			if u == nil {
				// domain was excluded from reserved upstreams querying
				return uc.Upstreams
			}
			return u
		}
	}

	return uc.Upstreams
}
