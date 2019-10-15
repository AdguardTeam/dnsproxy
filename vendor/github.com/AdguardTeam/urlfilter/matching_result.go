package urlfilter

// CosmeticOption is the enumeration of various content script options.
// Depending on the set of enabled flags the content script will contain different set of settings.
type CosmeticOption uint32

// CosmeticOption enumeration
const (
	// CosmeticOptionGenericCSS - if generic elemhide and CSS rules are enabled.
	// Can be disabled by a $generichide rule.
	CosmeticOptionGenericCSS CosmeticOption = 1 << iota
	// CosmeticOptionCSS - if elemhide and CSS rules are enabled.
	// Can be disabled by an $elemhide rule.
	CosmeticOptionCSS
	// CosmeticOptionJS - if JS rules and scriptlets are enabled.
	// Can be disabled by a $jsinject rule.
	CosmeticOptionJS

	// TODO: Add support for these flags
	// They are useful when content script is injected into an iframe
	// In this case we can check what flags were applied to the top-level frame
	CosmeticOptionSourceGenericCSS
	CosmeticOptionSourceCSS
	CosmeticOptionSourceJS

	// CosmeticOptionAll - everything is enabled
	CosmeticOptionAll = CosmeticOptionGenericCSS | CosmeticOptionCSS | CosmeticOptionJS

	// CosmeticOptionNone - everything is disabled
	CosmeticOptionNone = CosmeticOption(0)
)

// MatchingResult contains all the rules matching a web request, and provides methods
// that define how a web request should be processed
type MatchingResult struct {
	// BasicRule - a rule matching the request.
	// It could lead to one of the following:
	// * block the request
	// * unblock the request (a regular whitelist rule or a document-level whitelist rule)
	// * modify the way cosmetic rules work for this request
	// * modify the response (see $redirect rules)
	BasicRule *NetworkRule

	// DocumentRule - a rule matching the request's referrer and having on of the following modifiers:
	// * $document -- this one basically disables everything
	// * $urlblock -- disables network-level rules (not cosmetic)
	// * $genericblock -- disables generic network-level rules
	//
	// Other document-level modifiers like $jsinject or $content will be ignored here
	// as they don't do anything
	DocumentRule *NetworkRule

	// CspRules - a set of rules modifying the response's content-security-policy
	// See $csp modifier
	CspRules []*NetworkRule

	// CookieRules - a set of rules modifying the request's and response's cookies
	// See $cookie modifier
	CookieRules []*NetworkRule

	// ReplaceRules -- a set of rules modifying the response's content
	// See $replace modifier
	ReplaceRules []*NetworkRule

	// StealthRule - this is a whitelist rule that negates stealth mode features
	// Note that the stealth rule can be be received from both rules and sourceRules
	// https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#stealth-modifier
	StealthRule *NetworkRule
}

// NewMatchingResult creates an instance of the MatchingResult struct and fills it with the rules.
// rules - a set of rules matching the request URL
// sourceRules - a set of rules matching the referrer
// nolint:gocyclo
func NewMatchingResult(rules []*NetworkRule, sourceRules []*NetworkRule) MatchingResult {
	rules = removeBadfilterRules(rules)
	sourceRules = removeBadfilterRules(sourceRules)

	result := MatchingResult{}

	// First of all, find document-level whitelist rules
	for _, rule := range sourceRules {
		if rule.isDocumentWhitelistRule() {
			if result.DocumentRule == nil || rule.isHigherPriority(result.DocumentRule) {
				result.DocumentRule = rule
			}
		}

		if rule.IsOptionEnabled(OptionStealth) {
			result.StealthRule = rule
		}
	}

	// Second - check if blocking rules (generic or all of them) are allowed
	// generic blocking rules are allowed by default
	genericAllowed := true
	// basic blocking rules are allowed by default
	basicAllowed := true
	if result.DocumentRule != nil {
		if result.DocumentRule.IsOptionEnabled(OptionUrlblock) {
			basicAllowed = false
		} else if result.DocumentRule.IsOptionEnabled(OptionGenericblock) {
			genericAllowed = false
		}
	}

	// Iterate through the list of rules and fill the MatchingResult struct
	for _, rule := range rules {
		switch {
		case rule.IsOptionEnabled(OptionCookie):
			result.CookieRules = append(result.CookieRules, rule)
		case rule.IsOptionEnabled(OptionReplace):
			result.ReplaceRules = append(result.ReplaceRules, rule)
		case rule.IsOptionEnabled(OptionCsp):
			result.CspRules = append(result.CspRules, rule)
		case rule.IsOptionEnabled(OptionStealth):
			result.StealthRule = rule
		default:
			// Check blocking rules against $genericblock / $urlblock
			if !rule.Whitelist {
				if !basicAllowed {
					continue
				}
				if !genericAllowed && rule.isGeneric() {
					continue
				}
			}

			if result.BasicRule == nil || rule.isHigherPriority(result.BasicRule) {
				result.BasicRule = rule
			}
		}
	}

	return result
}

// GetBasicResult returns a rule that should be applied to the web request.
//
// Possible outcomes are:
// * returns nil -- bypass the request.
// * returns a whitelist rule -- bypass the request.
// * returns a blocking rule -- block the request.
func (m *MatchingResult) GetBasicResult() *NetworkRule {
	// https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#replace-modifier
	// 1. $replace rules have a higher priority than other basic rules (including exception rules).
	//    So if a request corresponds to two different rules one of which has the $replace modifier, this rule will be applied.
	// 2. Document-level exception rules with $content or $document modifiers do disable $replace rules for requests matching them.
	if m.ReplaceRules != nil {
		// TODO: implement the $replace selection algorithm
		// 1. check that ReplaceRules aren't negated by themselves (for instance, that there's no @@||example.org^$replace rule)
		// 2. check that they aren't disabled by a document-level exception (check both DocumentRule and BasicRule)
		// 3. return nil if that is so
		return nil
	}

	if m.BasicRule == nil {
		return m.DocumentRule
	}

	return m.BasicRule
}

// GetCosmeticOption returns a bit-flag with the list of cosmetic options
func (m *MatchingResult) GetCosmeticOption() CosmeticOption {
	if m.BasicRule == nil || !m.BasicRule.Whitelist {
		return CosmeticOptionAll
	}

	option := CosmeticOptionAll

	if m.BasicRule.IsOptionEnabled(OptionElemhide) {
		option = option ^ CosmeticOptionCSS
		option = option ^ CosmeticOptionGenericCSS
	}

	if m.BasicRule.IsOptionEnabled(OptionGenerichide) {
		option = option ^ CosmeticOptionGenericCSS
	}

	if m.BasicRule.IsOptionEnabled(OptionJsinject) {
		option = option ^ CosmeticOptionJS
	}

	return option
}

// removeBadfilterRules looks if there are any matching $badfilter rules and removes
// matching bad filters from the array (see the $badfilter description for more info)
func removeBadfilterRules(rules []*NetworkRule) []*NetworkRule {
	var badfilterRules []*NetworkRule

	for _, badfilter := range rules {
		if badfilter.IsOptionEnabled(OptionBadfilter) {
			// lazily create the badfilterRules array
			if badfilterRules == nil {
				badfilterRules = []*NetworkRule{}
			}
			badfilterRules = append(badfilterRules, badfilter)
		}
	}

	if len(badfilterRules) > 0 {
		filteredRules := []*NetworkRule{}
		for _, badfilter := range badfilterRules {
			for _, rule := range rules {
				if !badfilter.negatesBadfilter(rule) && !rule.IsOptionEnabled(OptionBadfilter) {
					filteredRules = append(filteredRules, rule)
				}
			}
		}
		return filteredRules
	}

	return rules
}
