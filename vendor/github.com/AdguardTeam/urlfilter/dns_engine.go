package urlfilter

import (
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

// DNSEngine combines host rules and network rules and is supposed to quickly find
// matching rules for hostnames.
// First, it looks over network rules and returns first rule found.
// Then, if nothing found, it looks up the host rules.
type DNSEngine struct {
	RulesCount    int                // count of rules loaded to the engine
	networkEngine *NetworkEngine     // networkEngine is constructed from the network rules
	lookupTable   map[uint32][]int64 // map for hosts hashes mapped to the list of rule indexes
	rulesStorage  *filterlist.RuleStorage
}

// NewDNSEngine parses the specified filter lists and returns a DNSEngine built from them.
// key of the map is the filter list ID, value is the raw content of the filter list.
func NewDNSEngine(s *filterlist.RuleStorage) *DNSEngine {
	// At first, we count rules in the rule storage so that we could pre-allocate lookup tables
	// Surprisingly, this helps us save a lot on allocations
	var hostRulesCount, networkRulesCount int
	scan := s.NewRuleStorageScanner()
	for scan.Scan() {
		f, _ := scan.Rule()
		if hostRule, ok := f.(*rules.HostRule); ok {
			hostRulesCount += len(hostRule.Hostnames)
		} else if _, ok := f.(*rules.NetworkRule); ok {
			networkRulesCount++
		}
	}

	// Initialize the DNSEngine using these newly acquired numbers
	d := DNSEngine{
		rulesStorage: s,
		lookupTable:  make(map[uint32][]int64, hostRulesCount),
		RulesCount:   0,
	}

	networkEngine := &NetworkEngine{
		ruleStorage:          s,
		domainsLookupTable:   make(map[uint32][]int64, 0),
		shortcutsLookupTable: make(map[uint32][]int64, networkRulesCount),
		shortcutsHistogram:   make(map[uint32]int, 0),
	}

	// Go through all rules in the storage and add them to the lookup tables
	scanner := s.NewRuleStorageScanner()
	for scanner.Scan() {
		f, idx := scanner.Rule()

		if hostRule, ok := f.(*rules.HostRule); ok {
			d.addRule(hostRule, idx)
		} else if networkRule, ok := f.(*rules.NetworkRule); ok {
			if networkRule.IsHostLevelNetworkRule() {
				networkEngine.addRule(networkRule, idx)
			}
		}
	}

	d.RulesCount += networkEngine.RulesCount
	d.networkEngine = networkEngine
	return &d
}

// Match finds a matching rule for the specified hostname.
// It returns true and the list of rules found or false and nil.
// The list of rules can be found when there're multiple host rules matching the same domain.
// For instance:
// 192.168.0.1 example.local
// 2000::1 example.local
func (d *DNSEngine) Match(hostname string) ([]rules.Rule, bool) {
	if hostname == "" {
		return nil, false
	}

	r := rules.NewRequestForHostname(hostname)
	networkRule, ok := d.networkEngine.Match(r)
	if ok {
		// Network rules always have higher priority
		return []rules.Rule{networkRule}, true
	}

	return d.matchLookupTable(hostname)
}

// matchLookupTable looks for matching rules in the d.lookupTable
func (d *DNSEngine) matchLookupTable(hostname string) ([]rules.Rule, bool) {
	hash := fastHash(hostname)
	rulesIndexes, ok := d.lookupTable[hash]
	if !ok {
		return nil, false
	}

	var rules []rules.Rule
	for _, idx := range rulesIndexes {
		rule := d.rulesStorage.RetrieveHostRule(idx)
		if rule != nil && rule.Match(hostname) {
			rules = append(rules, rule)
		}
	}

	return rules, len(rules) > 0
}

// addRule adds rule to the index
func (d *DNSEngine) addRule(hostRule *rules.HostRule, storageIdx int64) {
	for _, hostname := range hostRule.Hostnames {
		hash := fastHash(hostname)
		rulesIndexes, _ := d.lookupTable[hash]
		d.lookupTable[hash] = append(rulesIndexes, storageIdx)
	}

	d.RulesCount++
}
