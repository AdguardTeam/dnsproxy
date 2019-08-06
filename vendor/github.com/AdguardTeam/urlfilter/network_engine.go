package urlfilter

import (
	"math"
	"strings"
)

const (
	shortcutLength = 5
)

// NetworkEngine is the engine that supports quick search over network rules
type NetworkEngine struct {
	RulesCount int // RulesCount -- count of rules added to the engine

	ruleStorage *RuleStorage // Storage for the network filtering rules

	// Domain lookup table. Key is the domain name hash.
	domainsLookupTable map[uint32][]int64

	shortcutsLookupTable map[uint32][]int64 // Shortcuts lookup table. Key is the shortcut hash.
	shortcutsHistogram   map[uint32]int     // Shortcuts histogram helps us choose the best shortcut for the shortcuts lookup table.

	// Rules for which we could not find a shortcut and could not place it to the shortcuts lookup table.
	otherRules []*NetworkRule
}

// NewNetworkEngine builds an instance of the network engine
func NewNetworkEngine(s *RuleStorage) *NetworkEngine {
	engine := NetworkEngine{
		ruleStorage:          s,
		domainsLookupTable:   map[uint32][]int64{},
		shortcutsLookupTable: map[uint32][]int64{},
		shortcutsHistogram:   map[uint32]int{},
	}

	scanner := s.NewRuleStorageScanner()

	for scanner.Scan() {
		f, idx := scanner.Rule()
		rule, ok := f.(*NetworkRule)
		if ok {
			engine.addRule(rule, idx)
		}
	}

	return &engine
}

// Match searches over all filtering rules loaded to the engine
// It returns true if a match was found alongside the matching rule
func (n *NetworkEngine) Match(r *Request) (*NetworkRule, bool) {
	rules := n.MatchAll(r)

	if len(rules) == 0 {
		return nil, false
	}

	var resultRule *NetworkRule

	for i := range rules {
		rule := rules[i]

		if resultRule == nil || rule.isHigherPriority(resultRule) {
			resultRule = rule
		}
	}

	return resultRule, true
}

// MatchAll finds all rules matching the specified request regardless of the rule types
// It will find both whitelist and blacklist rules
func (n *NetworkEngine) MatchAll(r *Request) []*NetworkRule {
	// First check by shortcuts
	result := n.matchShortcutsLookupTable(r)

	for _, rule := range n.matchDomainsLookupTable(r) {
		result = append(result, rule)
	}

	// Now check other rules
	for i := range n.otherRules {
		rule := n.otherRules[i]
		if rule.Match(r) {
			result = append(result, rule)
		}
	}

	return result
}

// matchShortcutsLookupTable finds all matching rules from the shortcuts lookup table
func (n *NetworkEngine) matchShortcutsLookupTable(r *Request) []*NetworkRule {
	var result []*NetworkRule
	for i := 0; i <= len(r.URLLowerCase)-shortcutLength; i++ {
		hash := fastHashBetween(r.URLLowerCase, i, i+shortcutLength)
		if rules, ok := n.shortcutsLookupTable[hash]; ok {
			for i := range rules {
				ruleIdx := rules[i]
				rule := n.ruleStorage.RetrieveNetworkRule(ruleIdx)
				if rule != nil && rule.Match(r) {
					result = append(result, rule)
				}
			}
		}
	}

	return result
}

// matchDomainsLookupTable finds all matching rules from the domains lookup table
func (n *NetworkEngine) matchDomainsLookupTable(r *Request) []*NetworkRule {
	var result []*NetworkRule

	if r.SourceHostname == "" {
		return result
	}

	domains := getSubdomains(r.SourceHostname)
	for _, domain := range domains {
		hash := fastHash(domain)
		if rules, ok := n.domainsLookupTable[hash]; ok {
			for i := range rules {
				ruleIdx := rules[i]
				rule := n.ruleStorage.RetrieveNetworkRule(ruleIdx)
				if rule != nil && rule.Match(r) {
					result = append(result, rule)
				}
			}
		}
	}
	return result
}

// addRule adds rule to the network engine
func (n *NetworkEngine) addRule(f *NetworkRule, storageIdx int64) {
	if !n.addRuleToShortcutsTable(f, storageIdx) {
		if !n.addRuleToDomainsTable(f, storageIdx) {
			if !containsRule(n.otherRules, f) {
				n.otherRules = append(n.otherRules, f)
			}
		}
	}
	n.RulesCount++
}

// addRuleToDomainsTable tries to add the rule to the domains lookup table.
// returns true if it was added (the domain
func (n *NetworkEngine) addRuleToDomainsTable(f *NetworkRule, storageIdx int64) bool {
	if len(f.permittedDomains) == 0 {
		return false
	}

	for _, domain := range f.permittedDomains {
		hash := fastHash(domain)

		// Add the rule to the lookup table
		rulesIndexes := n.domainsLookupTable[hash]
		rulesIndexes = append(rulesIndexes, storageIdx)
		n.domainsLookupTable[hash] = rulesIndexes
	}

	return true
}

// addRuleToShortcutsTable tries to add the rule to the shortcuts table.
// returns true if it was added or false if the shortcut is too short
func (n *NetworkEngine) addRuleToShortcutsTable(f *NetworkRule, storageIdx int64) bool {
	shortcuts := getRuleShortcuts(f)
	if len(shortcuts) == 0 {
		return false
	}

	// Find the applicable shortcut (the least used)
	var shortcutHash uint32
	var minCount = math.MaxInt32
	for _, shortcutToCheck := range shortcuts {
		hash := fastHash(shortcutToCheck)
		count, ok := n.shortcutsHistogram[hash]
		if !ok {
			count = 0
		}
		if count < minCount {
			minCount = count
			shortcutHash = hash
		}
	}

	// Increment the histogram
	n.shortcutsHistogram[shortcutHash] = minCount + 1

	// Add the rule to the lookup table
	rulesIndexes, _ := n.shortcutsLookupTable[shortcutHash]
	rulesIndexes = append(rulesIndexes, storageIdx)
	n.shortcutsLookupTable[shortcutHash] = rulesIndexes

	return true
}

// getRuleShortcuts returns a list of shortcuts that can be used for the lookup table
func getRuleShortcuts(f *NetworkRule) []string {
	if len(f.Shortcut) < shortcutLength {
		return nil
	}

	if isAnyURLShortcut(f) {
		return nil
	}

	var shortcuts []string
	for i := 0; i <= len(f.Shortcut)-shortcutLength; i++ {
		shortcut := f.Shortcut[i : i+shortcutLength]
		shortcuts = append(shortcuts, shortcut)
	}

	return shortcuts
}

// isAnyURLShortcut checks if the rule potentially matches too many URLs.
// We'd better use another type of lookup table for this kind of rules.
func isAnyURLShortcut(f *NetworkRule) bool {
	// Sorry for magic numbers
	// The numbers are basically ("PROTO://".length + 1)

	if len(f.Shortcut) < 6 && strings.Index(f.Shortcut, "ws:") == 0 {
		return true
	}

	if len(f.Shortcut) < 7 && strings.Index(f.Shortcut, "|ws") == 0 {
		return true
	}

	if len(f.Shortcut) < 9 && strings.Index(f.Shortcut, "http") == 0 {
		return true
	}

	if len(f.Shortcut) < 10 && strings.Index(f.Shortcut, "|http") == 0 {
		return true
	}

	return false
}

// djb2 hash algorithm
func fastHashBetween(str string, begin int, end int) uint32 {
	hash := uint32(5381)
	for i := begin; i < end; i++ {
		hash = (hash * 33) ^ uint32(str[i])
	}
	return hash
}

// djb2 hash algorithm
func fastHash(str string) uint32 {
	if str == "" {
		return 0
	}
	return fastHashBetween(str, 0, len(str))
}

// helper function that checks if the specified rule is already in the array
func containsRule(rules []*NetworkRule, r *NetworkRule) bool {
	if rules == nil {
		return false
	}

	for _, rule := range rules {
		// Already added
		if rule.RuleText == r.RuleText {
			return true
		}
	}

	return false
}
