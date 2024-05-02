package proxy

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/mapsutil"
	"github.com/AdguardTeam/golibs/netutil"
)

// UnqualifiedNames is a key for [UpstreamConfig.DomainReservedUpstreams] map to
// specify the upstreams only used for resolving domain names consisting of a
// single label.
const UnqualifiedNames = "unqualified_names"

// UpstreamConfig maps domain names to upstreams.
type UpstreamConfig struct {
	// DomainReservedUpstreams maps the domains to the upstreams.
	DomainReservedUpstreams map[string][]upstream.Upstream

	// SpecifiedDomainUpstreams maps the specific domain names to the upstreams.
	SpecifiedDomainUpstreams map[string][]upstream.Upstream

	// SubdomainExclusions is set of domains with subdomains exclusions.
	SubdomainExclusions *container.MapSet[string]

	// Upstreams is a list of default upstreams.
	Upstreams []upstream.Upstream
}

// type check
var _ io.Closer = (*UpstreamConfig)(nil)

// ParseUpstreamsConfig returns an UpstreamConfig and nil error if the upstream
// configuration is valid.  Otherwise returns a partially filled UpstreamConfig
// and wrapped error containing lines with errors.  It also skips empty lines
// and comments (lines starting with "#").
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
func ParseUpstreamsConfig(
	lines []string,
	opts *upstream.Options,
) (conf *UpstreamConfig, err error) {
	if opts == nil {
		opts = &upstream.Options{}
	}

	p := &configParser{
		options:                  opts,
		upstreamsIndex:           map[string]upstream.Upstream{},
		domainReservedUpstreams:  map[string][]upstream.Upstream{},
		specifiedDomainUpstreams: map[string][]upstream.Upstream{},
		subdomainsOnlyUpstreams:  map[string][]upstream.Upstream{},
		subdomainsOnlyExclusions: container.NewMapSet[string](),
	}

	return p.parse(lines)
}

// ParseError is an error which contains an index of the line of the upstream
// list.
type ParseError struct {
	// err is the original error.
	err error

	// Idx is an index of the lines.  See [ParseUpstreamsConfig].
	Idx int
}

// type check
var _ error = (*ParseError)(nil)

// Error implements the [error] interface for *ParseError.
func (e *ParseError) Error() (msg string) {
	return fmt.Sprintf("parsing error at index %d: %s", e.Idx, e.err)
}

// type check
var _ errors.Wrapper = (*ParseError)(nil)

// Unwrap implements the [errors.Wrapper] interface for *ParseError.
func (e *ParseError) Unwrap() (unwrapped error) { return e.err }

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
	subdomainsOnlyExclusions *container.MapSet[string]

	// upstreams is a list of default upstreams.
	upstreams []upstream.Upstream
}

// parse returns UpstreamConfig and error if upstreams configuration is invalid.
func (p *configParser) parse(lines []string) (c *UpstreamConfig, err error) {
	var errs []error
	for i, l := range lines {
		if err = p.parseLine(i, l); err != nil {
			errs = append(errs, &ParseError{Idx: i, err: err})
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
	}, errors.Join(errs...)
}

// parseLine returns an error if upstream configuration line is invalid.
func (p *configParser) parseLine(idx int, confLine string) (err error) {
	if len(confLine) == 0 || confLine[0] == '#' {
		return nil
	}

	upstreams, domains, err := splitConfigLine(confLine)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	if upstreams[0] == "#" && len(domains) > 0 {
		p.excludeFromReserved(domains)

		return nil
	}

	for _, u := range upstreams {
		err = p.specifyUpstream(domains, u, idx)
		if err != nil {
			// Don't wrap the error since it's informative enough as is.
			return err
		}
	}

	return nil
}

// splitConfigLine parses upstream configuration line and returns list upstream
// addresses (one or many), list of domains for which this upstream is reserved
// (may be nil).  It returns an error if the upstream format is incorrect.
func splitConfigLine(confLine string) (upstreams, domains []string, err error) {
	if !strings.HasPrefix(confLine, "[/") {
		return []string{confLine}, nil, nil
	}

	domainsLine, upstreamsLine, found := strings.Cut(confLine[len("[/"):], "/]")
	if !found || upstreamsLine == "" {
		return nil, nil, errors.Error("wrong upstream format")
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
func (p *configParser) specifyUpstream(domains []string, u string, idx int) (err error) {
	dnsUpstream, ok := p.upstreamsIndex[u]
	// TODO(e.burkov):  Improve identifying duplicate upstreams.
	if !ok {
		// create an upstream
		dnsUpstream, err = upstream.AddressToUpstream(u, p.options.Clone())
		if err != nil {
			return fmt.Errorf("cannot prepare the upstream: %s", err)
		}

		// save to the index
		p.upstreamsIndex[u] = dnsUpstream
	}

	addr := dnsUpstream.Address()
	if len(domains) == 0 {
		// TODO(s.chzhen):  Handle duplicates.
		p.upstreams = append(p.upstreams, dnsUpstream)

		// TODO(s.chzhen):  Logs without index.
		log.Debug("dnsproxy: upstream at index %d: %s", idx, addr)
	} else {
		p.includeToReserved(dnsUpstream, domains)

		log.Debug("dnsproxy: upstream at index %d: %s is reserved for %d domains",
			idx,
			addr,
			len(domains),
		)
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

// validate returns an error if the upstreams aren't configured properly.  c
// considered valid if it contains at least a single default upstream.  Empty c
// causes [upstream.ErrNoUpstreams].
func (uc *UpstreamConfig) validate() (err error) {
	const (
		errNilConf   errors.Error = "upstream config is nil"
		errNoDefault errors.Error = "no default upstreams specified"
	)

	switch {
	case uc == nil:
		return errNilConf
	case len(uc.Upstreams) > 0:
		return nil
	case len(uc.DomainReservedUpstreams) == 0 && len(uc.SpecifiedDomainUpstreams) == 0:
		return upstream.ErrNoUpstreams
	default:
		return errNoDefault
	}
}

// ValidatePrivateConfig returns an error if uc isn't valid, or, treated as
// private upstreams configuration, contains specifications for invalid domains.
func ValidatePrivateConfig(uc *UpstreamConfig, privateSubnets netutil.SubnetSet) (err error) {
	if err = uc.validate(); err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	var errs []error
	rangeFunc := func(domain string, _ []upstream.Upstream) (ok bool) {
		pref, extErr := netutil.ExtractReversedAddr(domain)
		switch {
		case extErr != nil:
			// Don't wrap the error since it's informative enough as is.
			errs = append(errs, extErr)
		case pref.Bits() == 0:
			// Allow private subnets for subdomains of the root domain.
		case !privateSubnets.Contains(pref.Addr()):
			errs = append(errs, fmt.Errorf("reversed subnet in %q is not private", domain))
		default:
			// Go on.
		}

		return true
	}

	mapsutil.SortedRange(uc.DomainReservedUpstreams, rangeFunc)

	return errors.Join(errs...)
}

// getUpstreamsForDomain returns the upstreams specified for resolving fqdn.  It
// always returns the default set of upstreams if the domain is not reserved for
// any other upstreams.
//
// More specific domains take priority over less specific ones.  For example, if
// the upstreams specified for the following domains:
//
//   - host.com
//   - www.host.com
//
// The request for mail.host.com will be resolved using the upstreams specified
// for host.com.
func (uc *UpstreamConfig) getUpstreamsForDomain(fqdn string) (ups []upstream.Upstream) {
	if len(uc.DomainReservedUpstreams) == 0 {
		return uc.Upstreams
	}

	fqdn = strings.ToLower(fqdn)
	if uc.SubdomainExclusions.Has(fqdn) {
		return uc.lookupSubdomainExclusion(fqdn)
	}

	ups, ok := uc.lookupUpstreams(fqdn)
	if ok {
		return ups
	}

	if _, fqdn, _ = strings.Cut(fqdn, "."); fqdn == "" {
		fqdn = UnqualifiedNames
	}

	for fqdn != "" {
		if ups, ok = uc.lookupUpstreams(fqdn); ok {
			return ups
		}

		_, fqdn, _ = strings.Cut(fqdn, ".")
	}

	return uc.Upstreams
}

// getUpstreamsForDS is like [getUpstreamsForDomain], but intended for DS
// queries only, so that it matches fqdn without the first label.
//
// A DS RRset SHOULD be present at a delegation point when the child zone is
// signed.  The DS RRset MAY contain multiple records, each referencing a public
// key in the child zone used to verify the RRSIGs in that zone.  All DS RRsets
// in a zone MUST be signed, and DS RRsets MUST NOT appear at a zone's apex.
//
// See https://datatracker.ietf.org/doc/html/rfc4035#section-2.4
func (uc *UpstreamConfig) getUpstreamsForDS(fqdn string) (ups []upstream.Upstream) {
	_, fqdn, _ = strings.Cut(fqdn, ".")
	if fqdn == "" {
		return uc.Upstreams
	}

	return uc.getUpstreamsForDomain(fqdn)
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

// lookupUpstreams returns upstreams for a domain name.  It returns default
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
		return fmt.Errorf("failed to close some upstreams: %w", errors.Join(closeErrs...))
	}

	return nil
}
