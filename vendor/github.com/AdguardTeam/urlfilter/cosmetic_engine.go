package urlfilter

// CosmeticEngine combines all the cosmetic rules and allows to quickly
// find all rules matching this or that hostname
type CosmeticEngine struct {
	lookupTables map[CosmeticRuleType]*cosmeticLookupTable
}

// NewCosmeticEngine builds a new cosmetic engine from the specified rule storage
func NewCosmeticEngine(s *RuleStorage) *CosmeticEngine {
	engine := CosmeticEngine{
		lookupTables: map[CosmeticRuleType]*cosmeticLookupTable{
			CosmeticElementHiding: newCosmeticLookupTable(),
			CosmeticCSS:           newCosmeticLookupTable(),
			CosmeticJS:            newCosmeticLookupTable(),
		},
	}

	scanner := s.NewRuleStorageScanner()
	for scanner.Scan() {
		f, _ := scanner.Rule()
		rule, ok := f.(*CosmeticRule)
		if ok {
			engine.addRule(rule)
		}
	}

	return &engine
}

// addRule adds a new cosmetic rule to one of the lookup tables
func (e *CosmeticEngine) addRule(rule *CosmeticRule) {
	switch rule.Type {
	case CosmeticElementHiding:
		e.lookupTables[CosmeticElementHiding].addRule(rule)
	default:
		// TODO: Implement
		// ignore
	}
}

// StylesResult contains either element hiding or CSS rules
type StylesResult struct {
	Generic        []string `json:"generic"`
	Specific       []string `json:"specific"`
	GenericExtCSS  []string `json:"genericExtCss"`
	SpecificExtCSS []string `json:"specificExtCss"`
}

func (s *StylesResult) append(r *CosmeticRule) {
	if r.IsGeneric() {
		if r.ExtendedCSS {
			s.GenericExtCSS = append(s.GenericExtCSS, r.Content)
		} else {
			s.Generic = append(s.Generic, r.Content)
		}
	} else {
		if r.ExtendedCSS {
			s.SpecificExtCSS = append(s.SpecificExtCSS, r.Content)
		} else {
			s.Specific = append(s.Specific, r.Content)
		}
	}
}

// ScriptsResult contains scripts to be executed on a page
type ScriptsResult struct {
	Generic  []string
	Specific []string
}

// CosmeticResult represents all scripts and styles that needs to be injected into the page
type CosmeticResult struct {
	ElementHiding StylesResult
	CSS           StylesResult
	JS            ScriptsResult
}

// Match builds scripts and styles that needs to be injected into the specified page
// hostname is the page hostname
// includeCSS defines if we should inject any CSS and element hiding rules (see $elemhide)
// includeJS defines if we should inject JS into the page (see $jsinject)
// includeGenericCSS defines if we should inject generic CSS and element hiding rules (see $generichide)
// TODO: Additionally, we should provide a method that writes result to an io.Writer
func (e *CosmeticEngine) Match(hostname string, includeCSS bool, includeJS bool, includeGenericCSS bool) CosmeticResult {
	r := CosmeticResult{
		ElementHiding: StylesResult{},
		CSS:           StylesResult{},
		JS:            ScriptsResult{},
	}

	if includeCSS {
		c := e.lookupTables[CosmeticElementHiding]
		if includeGenericCSS {
			for _, rule := range c.genericRules {
				if !c.isWhitelisted(hostname, rule) && rule.Match(hostname) {
					r.ElementHiding.append(rule)
				}
			}
		}

		rules := c.findByHostname(hostname)
		if len(rules) > 0 {
			for _, rule := range rules {
				r.ElementHiding.append(rule)
			}
		}
	}

	// TODO: Implement CosmeticCSS and CosmeticJS

	return r
}

// cosmeticLookupTable is a helper structure to speed up cosmetic rules matching
type cosmeticLookupTable struct {
	byHostname   map[string][]*CosmeticRule // map with rules grouped by the permitted domains names
	genericRules []*CosmeticRule            // list of generic rules
	whitelist    map[string][]*CosmeticRule // map with whitelist rules. key is the rule content
}

// newCosmeticLookupTable creates a new empty instance of the lookup table
func newCosmeticLookupTable() *cosmeticLookupTable {
	return &cosmeticLookupTable{
		byHostname:   map[string][]*CosmeticRule{},
		genericRules: []*CosmeticRule{},
		whitelist:    map[string][]*CosmeticRule{},
	}
}

// addRule adds the specified rule to the lookup table
func (c *cosmeticLookupTable) addRule(f *CosmeticRule) {
	if f.Whitelist {
		rules := c.whitelist[f.Content]
		rules = append(rules, f)
		c.whitelist[f.Content] = rules
		return
	}

	if f.IsGeneric() {
		c.genericRules = append(c.genericRules, f)
		return
	}

	for _, hostname := range f.permittedDomains {
		rules := c.byHostname[hostname]
		rules = append(rules, f)
		c.byHostname[hostname] = rules
	}
}

// findByHostname looks for matching domain-specific rules
// Returns nil if nothing found
func (c *cosmeticLookupTable) findByHostname(hostname string) []*CosmeticRule {
	var rules []*CosmeticRule

	rulesByHostname, found := c.byHostname[hostname]
	if !found {
		return rules
	}

	for _, rule := range rulesByHostname {
		if !c.isWhitelisted(hostname, rule) {
			rules = append(rules, rule)
		}
	}

	return rules
}

// isWhitelisted checks if this cosmetic rule is whitelisted on the specified hostname
func (c *cosmeticLookupTable) isWhitelisted(hostname string, f *CosmeticRule) bool {
	list, found := c.whitelist[f.Content]
	if !found {
		return false
	}

	for _, rule := range list {
		if rule.Match(hostname) {
			return true
		}
	}

	return false
}
