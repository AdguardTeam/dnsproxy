package urlfilter

// CosmeticEngine combines all the cosmetic rules and allows to quickly
// find all rules matching this or that hostname
type CosmeticEngine struct {
	lookupTables map[CosmeticRuleType]*cosmeticLookupTable
}

// NewCosmeticEngine builds a new cosmetic engine from the list of rules
func NewCosmeticEngine(rules []*CosmeticRule) *CosmeticEngine {
	engine := CosmeticEngine{
		lookupTables: map[CosmeticRuleType]*cosmeticLookupTable{
			CosmeticElementHiding: newCosmeticLookupTable(),
			CosmeticCSS:           newCosmeticLookupTable(),
			CosmeticJS:            newCosmeticLookupTable(),
		},
	}

	for _, rule := range rules {
		switch rule.Type {
		case CosmeticElementHiding:
			engine.lookupTables[CosmeticElementHiding].addRule(rule)
		default:
			// TODO: Implement
			// ignore
		}
	}

	return &engine
}

// CosmeticResult represents all scripts and styles that needs to be injected into the page
type CosmeticResult struct {
	StylesSpecific       []string // Styles specific to the hostname
	StylesGeneric        []string // Styles combined of generic cosmetic rules
	StylesSpecificExtCSS []string // ExtCSS styles specific to the hostname
	StylesGenericExtCSS  []string // ExtCSS styles combined of generic rules
	Scripts              []string // Scripts to inject
}

// Match builds scripts and styles that needs to be injected into the specified page
// hostname is the page hostname
// includeCSS defines if we should inject any CSS and element hiding rules (see $elemhide)
// includeGenericCSS defines if we should inject generic CSS and element hiding rules (see $generichide)
// includeJS defines if we should inject JS into the page (see $jsinject)
func (e *CosmeticEngine) Match(hostname string, includeCSS bool, includeGenericCSS bool, includeJS bool) *CosmeticResult {
	r := &CosmeticResult{}

	// TODO: Build result
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

// buildResult adds data to the cosmetic result instance
func (c *cosmeticLookupTable) buildResult(hostname string, r *CosmeticResult) {
	// TODO: Implement
}

// findByHostname looks for matching domain-specific rules
func (c *cosmeticLookupTable) findByHostname(hostname string) []*CosmeticRule {
	var rules []*CosmeticRule
	// TODO: Implement
	return rules
}
