package proxy

import (
	"fmt"
	"strings"

	"github.com/AdguardTeam/dnsproxy/ipset"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/utils"
)

// IPSetConfig is a wrapper for map of domains and corresponding set
type IPSetConfig struct {
	ipsets map[string]*ipset.IPSet
}

// ParseIPSetsConfig returns IPSetConfig and error if IP set configuration is invalid
// IP set syntax: [/domain1/../domainN/]<SetNameString>
// More specific domains take priority over less specific domains,
// To exclude more specific domains from querying you should use the following syntax: [/domain1/../domainN/]#
// So the following config: ["[/host.com/]blacklist", "[/www.host.com/]whitelist", "[/maps.host.com/]#"]
// will send IP address for *.host.com to blacklist, except for *.www.host.com, which will go to whitelist and *.maps.host.com,
// which will do nothing
func ParseIPSetsConfig(ipsetConfig []string) (*IPSetConfig, error) {
	var set *ipset.IPSet
	var ok bool

	ipsetsIndex := map[string]*ipset.IPSet{}

	ipsets := map[string]*ipset.IPSet{}

	for i, l := range ipsetConfig {
		name, family, hosts, err := parseIPSetLine(l)
		if err != nil {
			return nil, err
		}

		// # excludes more specific domain
		if name == "#" {
			for _, host := range hosts {
				if _, ok = ipsets[host]; ok {
					ipsets[host] = nil
				}
			}
			continue
		}

		if len(hosts) > 0 {
			set, ok = ipsetsIndex[name]
			if !ok {
				// create an IP set
				set, err = ipset.New(
					name,
					&ipset.Options{
						HashType:   "hash:ip",
						HashFamily: family,
					},
				)
				if err != nil {
					err = fmt.Errorf("cannot prepare the ipset %s: %s", l, err)
					return nil, err
				}

				// save to the index
				ipsetsIndex[name] = set
			}

			for _, host := range hosts {
				if _, ok = ipsets[host]; !ok {
					ipsets[host] = set
				}
			}

			log.Debug("IPSet %d: %s is created for next domains: %s", i, name, strings.Join(hosts, ", "))
		}
	}

	return &IPSetConfig{ipsets}, nil
}

// parseIPSetLine - parses IP set line and returns the following:
// IP set name
// list of domains for which this IP set is handling (may be nil)
// error if something went wrong
func parseIPSetLine(l string) (string, string, []string, error) {
	var hosts []string

	var err error

	name := l
	family := "inet"

	if strings.HasPrefix(l, "[/") {
		// split domains and upstream string
		domainsAndIPSet := strings.Split(strings.TrimPrefix(l, "[/"), "/]")
		if len(domainsAndIPSet) != 2 {
			return "", "", nil, fmt.Errorf("wrong upstream specification: %s", l)
		}

		// split domains list
		for _, host := range strings.Split(domainsAndIPSet[0], "/") {
			if host != "" {
				if err = utils.IsValidHostname(host); err != nil {
					return "", "", nil, err
				}
				hosts = append(hosts, strings.ToLower(host+"."))
			} else {
				// empty domain specification means `unqualified names only`
				hosts = append(hosts, UnqualifiedNames)
			}
		}

		params := strings.Split(domainsAndIPSet[1], ",")
		if len(params) > 1 {
			name = params[0]
			family = params[1]
		} else {
			name = domainsAndIPSet[1]
			family = "inet"
		}
	}

	return name, family, hosts, nil
}

func (ic *IPSetConfig) GetUpstreamsForDomain(host string) *ipset.IPSet {
	if ipset, ok := ic.ipsets[host]; ok {
		return ipset
	}
	return nil
}
