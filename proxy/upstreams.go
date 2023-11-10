package proxy

import (
	"fmt"
	"io"
	"strings"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/stringutil"
	"golang.org/x/exp/slices"
)

// UpstreamConfig is a wrapper for a list of default upstreams, a map of
// reserved domains and corresponding upstreams.
type UpstreamConfig struct {
	// DomainReservedUpstreams is a map of reserved domains and lists of
	// corresponding upstreams.
	DomainReservedUpstreams map[string][]upstream.Upstream

	// SpecifiedDomainUpstreams is a map of excluded domains and lists of
	// corresponding upstreams.
	SpecifiedDomainUpstreams map[string][]upstream.Upstream

	// SubdomainExclusions is set of domains with subdomains exclusions.
	SubdomainExclusions *stringutil.Set

	// Upstreams is a list of default upstreams.
	Upstreams []upstream.Upstream
}

// type check
var _ io.Closer = (*UpstreamConfig)(nil)

// ParseUpstreamsConfig returns UpstreamConfig and error if upstreams
// configuration is invalid.
//
// # Simple upstreams
//
// Single upstream per line.  For example:
//
//	1.2.3.4
//	3.4.5.6
//
// # Domain specific upstreams
//
//   - reserved upstreams: [/domain1/../domainN/]<upstreamString>
//   - subdomains only upstreams: [/*.domain1/../*.domainN]<upstreamString>
//
// Where <upstreamString> is one or many upstreams separated by space (e.g.
// `1.1.1.1` or `1.1.1.1 2.2.2.2`).
//
// More specific domains take priority over less specific domains.  To exclude
// more specific domains from reserved upstreams querying you should use the
// following syntax:
//
//	[/domain1/../domainN/]#
//
// So the following config:
//
//	[/host.com/]1.2.3.4
//	[/www.host.com/]2.3.4.5"
//	[/maps.host.com/news.host.com/]#
//	3.4.5.6
//
// will send queries for *.host.com to 1.2.3.4.  Except for *.www.host.com,
// which will go to 2.3.4.5.  And *.maps.host.com or *.news.host.com, which
// will go to default server 3.4.5.6 with all other domains.
//
// To exclude top level domain from reserved upstreams querying you could use
// the following:
//
//	'[/*.domain.com/]<upstreamString>'
//
// So the following config:
//
//	[/*.domain.com/]1.2.3.4
//	3.4.5.6
//
// will send queries for all subdomains *.domain.com to 1.2.3.4, but domain.com
// query will be sent to default server 3.4.5.6 as every other query.
//
// TODO(e.burkov):  Consider supporting multiple upstreams in a single line for
// default upstream syntax.
func ParseUpstreamsConfig(upstreamConfig []string, options *upstream.Options) (*UpstreamConfig, error) {
	if options == nil {
		options = &upstream.Options{}
	}

	p := &configParser{
		options:                  options,
		upstreamsIndex:           map[string]upstream.Upstream{},
		domainReservedUpstreams:  map[string][]upstream.Upstream{},
		specifiedDomainUpstreams: map[string][]upstream.Upstream{},
		subdomainsOnlyUpstreams:  map[string][]upstream.Upstream{},
		subdomainsOnlyExclusions: stringutil.NewSet(),
	}

	return p.parse(upstreamConfig)
}

// configParser collects the results of parsing an upstream config.
type configParser struct {
	// options contains upstream properties.
	options *upstream.Options

	// upstreamsIndex is used to avoid creating duplicates of upstreams.
	upstreamsIndex map[string]upstream.Upstream

	// domainReservedUpstreams is a map of reserved domains and lists of
	// corresponding upstreams.
	domainReservedUpstreams map[string][]upstream.Upstream

	// specifiedDomainUpstreams is a map of excluded domains and lists of
	// corresponding upstreams.
	specifiedDomainUpstreams map[string][]upstream.Upstream

	// subdomainsOnlyUpstreams is a map of wildcard subdomains and lists of
	// corresponding upstreams.
	subdomainsOnlyUpstreams map[string][]upstream.Upstream

	// subdomainsOnlyExclusions is set of domains with subdomains exclusions.
	subdomainsOnlyExclusions *stringutil.Set

	// upstreams is a list of default upstreams.
	upstreams []upstream.Upstream
}

// parse returns UpstreamConfig and error if upstreams configuration is invalid.
func (p *configParser) parse(conf []string) (c *UpstreamConfig, err error) {
	for i, l := range conf {
		if err = p.parseLine(i, l); err != nil {
			return nil, err
		}
	}

	for host, ups := range p.subdomainsOnlyUpstreams {
		// Rewrite ups for wildcard subdomains to remove upper level domains
		// specs.
		p.domainReservedUpstreams[host] = ups
	}

	return &UpstreamConfig{
		Upstreams:                p.upstreams,
		DomainReservedUpstreams:  p.domainReservedUpstreams,
		SpecifiedDomainUpstreams: p.specifiedDomainUpstreams,
		SubdomainExclusions:      p.subdomainsOnlyExclusions,
	}, nil
}

// parseLine returns an error if upstream configuration line is invalid.
func (p *configParser) parseLine(idx int, confLine string) (err error) {
	upstreams, domains, err := splitConfigLine(idx, confLine)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	if upstreams[0] == "#" && len(domains) > 0 {
		p.excludeFromReserved(domains)

		return nil
	}

	for _, u := range upstreams {
		err = p.specifyUpstream(domains, u, idx, confLine)
		if err != nil {
			// Don't wrap the error since it's informative enough as is.
			return err
		}
	}

	return nil
}

// splitConfigLine parses upstream configuration line and returns list upstream
// addresses (one or many), list of domains for which this upstream is reserved
// (may be nil) or error if something went wrong.
func splitConfigLine(idx int, confLine string) (upstreams, domains []string, err error) {
	if !strings.HasPrefix(confLine, "[/") {
		return []string{confLine}, nil, nil
	}

	domainsLine, upstreamsLine, found := strings.Cut(confLine[len("[/"):], "/]")
	if !found || upstreamsLine == "" {
		return nil, nil, fmt.Errorf("wrong upstream specification %d %q", idx, confLine)
	}

	// split domains list
	for _, confHost := range strings.Split(domainsLine, "/") {
		if confHost == "" {
			// empty domain specification means `unqualified names only`
			domains = append(domains, UnqualifiedNames)

			continue
		}

		host := strings.TrimPrefix(confHost, "*.")
		if err = netutil.ValidateDomainName(host); err != nil {
			return nil, nil, err
		}

		domains = append(domains, strings.ToLower(confHost+"."))
	}

	return strings.Fields(upstreamsLine), domains, nil
}

// specifyUpstream specifies the upstream for domains.
func (p *configParser) specifyUpstream(
	domains []string,
	u string,
	idx int,
	confLine string,
) (err error) {
	dnsUpstream, ok := p.upstreamsIndex[u]
	// TODO(e.burkov):  Improve identifying duplicate upstreams.
	if !ok {
		// create an upstream
		dnsUpstream, err = upstream.AddressToUpstream(u, p.options.Clone())
		if err != nil {
			return fmt.Errorf("cannot prepare the upstream %d %q (%s): %s",
				idx, confLine, p.options.Bootstrap, err)
		}

		// save to the index
		p.upstreamsIndex[u] = dnsUpstream
	}

	addr := dnsUpstream.Address()
	if len(domains) == 0 {
		log.Debug("dnsproxy: upstream at index %d: %s", idx, addr)
		p.upstreams = append(p.upstreams, dnsUpstream)
	} else {
		log.Debug("dnsproxy: upstream at index %d: %s is reserved for %s", idx, addr, domains)
		p.includeToReserved(dnsUpstream, domains)
	}

	return nil
}

// excludeFromReserved excludes more specific domains from reserved upstreams
// querying.
func (p *configParser) excludeFromReserved(domains []string) {
	for _, host := range domains {
		if trimmed := strings.TrimPrefix(host, "*."); trimmed != host {
			p.subdomainsOnlyExclusions.Add(trimmed)
			p.subdomainsOnlyUpstreams[trimmed] = nil

			continue
		}

		p.domainReservedUpstreams[host] = nil
		p.specifiedDomainUpstreams[host] = nil
	}
}

// includeToReserved includes domains to reserved upstreams querying.
func (p *configParser) includeToReserved(dnsUpstream upstream.Upstream, domains []string) {
	for _, host := range domains {
		if strings.HasPrefix(host, "*.") {
			host = host[len("*."):]

			p.subdomainsOnlyExclusions.Add(host)
			log.Debug("domain %q is added to exclusions list", host)

			p.subdomainsOnlyUpstreams[host] = append(p.subdomainsOnlyUpstreams[host], dnsUpstream)
		} else {
			p.specifiedDomainUpstreams[host] = append(p.specifiedDomainUpstreams[host], dnsUpstream)
		}

		p.domainReservedUpstreams[host] = append(p.domainReservedUpstreams[host], dnsUpstream)
	}
}

// errNoDefaultUpstreams is returned when no default upstreams specified within
// a [Config.UpstreamConfig].
const errNoDefaultUpstreams errors.Error = "no default upstreams specified"

// validate returns an error if the upstreams aren't configured properly.  c
// considered valid if it contains at least a single default upstream.  Nil c,
// as well as c with no default upstreams causes [ErrNoDefaultUpstreams].  Empty
// c causes [upstream.ErrNoUpstreams].
func (uc *UpstreamConfig) validate() (err error) {
	switch {
	case uc == nil:
		return fmt.Errorf("%w; uc is nil", errNoDefaultUpstreams)
	case len(uc.Upstreams) > 0:
		return nil
	case len(uc.DomainReservedUpstreams) == 0 && len(uc.SpecifiedDomainUpstreams) == 0:
		return upstream.ErrNoUpstreams
	default:
		return errNoDefaultUpstreams
	}
}

// getUpstreamsForDomain looks for a domain in the reserved domains map and
// returns a list of corresponding upstreams.  It returns default upstreams list
// if the domain was not found in the map.  More specific domains take priority
// over less specific domains.  For example, take a map that contains the
// following keys: host.com and www.host.com.  If we are looking for domain
// mail.host.com, this method will return value of host.com key.  If we are
// looking for domain www.host.com, this method will return value of the
// www.host.com key.  If a more specific domain value is nil, it means that the
// domain was excluded and should be exchanged with default upstreams.
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
			return uc.lookupSubdomainExclusion(host)
		}
	}

	for host != "" {
		var ok bool
		if ups, ok = uc.lookupUpstreams(host); ok {
			return ups
		}

		_, host, _ = strings.Cut(host, ".")
	}

	return uc.Upstreams
}

// getUpstreamsForDS is like [getUpstreamsForDomain], but intended for DS
// queries only, so that it matches the host without the first label.
//
// A DS RRset SHOULD be present at a delegation point when the child zone is
// signed.  The DS RRset MAY contain multiple records, each referencing a public
// key in the child zone used to verify the RRSIGs in that zone.  All DS RRsets
// in a zone MUST be signed, and DS RRsets MUST NOT appear at a zone's apex.
//
// See https://datatracker.ietf.org/doc/html/rfc4035#section-2.4
func (uc *UpstreamConfig) getUpstreamsForDS(host string) (ups []upstream.Upstream) {
	_, host, found := strings.Cut(host, ".")
	if !found {
		return uc.Upstreams
	}

	return uc.getUpstreamsForDomain(host)
}

// lookupSubdomainExclusion returns upstreams for the host from subdomain
// exclusions list.
func (uc *UpstreamConfig) lookupSubdomainExclusion(host string) (u []upstream.Upstream) {
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

// lookupUpstreams returns upstreams for a domain name.  Returns default
// upstream list for domain name excluded by domain reserved upstreams.
func (uc *UpstreamConfig) lookupUpstreams(name string) (ups []upstream.Upstream, ok bool) {
	ups, ok = uc.DomainReservedUpstreams[name]
	if !ok {
		return ups, false
	}

	if len(ups) == 0 {
		// The domain has been excluded from reserved upstreams querying.
		ups = uc.Upstreams
	}

	return ups, true
}

// Close implements the io.Closer interface for *UpstreamConfig.
func (uc *UpstreamConfig) Close() (err error) {
	closeErrs := closeAll(nil, uc.Upstreams...)

	for _, specUps := range []map[string][]upstream.Upstream{
		uc.DomainReservedUpstreams,
		uc.SpecifiedDomainUpstreams,
	} {
		domains := make([]string, 0, len(specUps))
		for domain := range specUps {
			domains = append(domains, domain)
		}

		slices.SortStableFunc(domains, strings.Compare)

		for _, domain := range domains {
			closeErrs = closeAll(closeErrs, specUps[domain]...)
		}
	}

	if len(closeErrs) > 0 {
		return errors.List("failed to close some upstreams", closeErrs...)
	}

	return nil
}
