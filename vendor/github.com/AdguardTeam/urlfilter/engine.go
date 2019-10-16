package urlfilter

// Engine represents the filtering engine with all the loaded rules
type Engine struct {
	networkEngine  *NetworkEngine
	cosmeticEngine *CosmeticEngine
}

// NewEngine parses the filtering rules and creates a filtering engine of them
func NewEngine(s *RuleStorage) *Engine {
	return &Engine{
		networkEngine:  NewNetworkEngine(s),
		cosmeticEngine: NewCosmeticEngine(s),
	}
}

// MatchRequest - matches the specified request against the filtering engine
// and returns the matching result.
func (e *Engine) MatchRequest(r *Request) MatchingResult {
	var rules []*NetworkRule
	var sourceRules []*NetworkRule

	rules = e.networkEngine.MatchAll(r)
	if r.SourceURL != "" {
		sourceRequest := NewRequest(r.SourceURL, "", TypeDocument)
		sourceRules = e.networkEngine.MatchAll(sourceRequest)
	}

	return NewMatchingResult(rules, sourceRules)
}

// GetCosmeticResult gets cosmetic result for the specified hostname and cosmetic options
func (e *Engine) GetCosmeticResult(hostname string, option CosmeticOption) CosmeticResult {
	includeCSS := option&CosmeticOptionCSS == CosmeticOptionCSS
	includeGenericCSS := option&CosmeticOptionGenericCSS == CosmeticOptionGenericCSS
	includeJS := option&CosmeticOptionJS == CosmeticOptionJS
	return e.cosmeticEngine.Match(hostname, includeCSS, includeJS, includeGenericCSS)
}
