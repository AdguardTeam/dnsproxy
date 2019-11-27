package urlfilter

import (
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

// Engine represents the filtering engine with all the loaded rules
type Engine struct {
	networkEngine  *NetworkEngine
	cosmeticEngine *CosmeticEngine
}

// NewEngine parses the filtering rules and creates a filtering engine of them
func NewEngine(s *filterlist.RuleStorage) *Engine {
	return &Engine{
		networkEngine:  NewNetworkEngine(s),
		cosmeticEngine: NewCosmeticEngine(s),
	}
}

// MatchRequest - matches the specified request against the filtering engine
// and returns the matching result.
func (e *Engine) MatchRequest(r *rules.Request) rules.MatchingResult {
	var networkRules []*rules.NetworkRule
	var sourceRules []*rules.NetworkRule

	networkRules = e.networkEngine.MatchAll(r)
	if r.SourceURL != "" {
		sourceRequest := rules.NewRequest(r.SourceURL, "", rules.TypeDocument)
		sourceRules = e.networkEngine.MatchAll(sourceRequest)
	}

	return rules.NewMatchingResult(networkRules, sourceRules)
}

// GetCosmeticResult gets cosmetic result for the specified hostname and cosmetic options
func (e *Engine) GetCosmeticResult(hostname string, option rules.CosmeticOption) CosmeticResult {
	includeCSS := option&rules.CosmeticOptionCSS == rules.CosmeticOptionCSS
	includeGenericCSS := option&rules.CosmeticOptionGenericCSS == rules.CosmeticOptionGenericCSS
	includeJS := option&rules.CosmeticOptionJS == rules.CosmeticOptionJS
	return e.cosmeticEngine.Match(hostname, includeCSS, includeJS, includeGenericCSS)
}
