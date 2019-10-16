package urlfilter

import (
	"bytes"
	"sort"
	"strings"
)

// CosmeticRuleType is the enumeration of different cosmetic rules
type CosmeticRuleType uint

// CosmeticRuleType enumeration
const (
	CosmeticElementHiding CosmeticRuleType = iota // ## rules (https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#cosmetic-elemhide-rules)
	CosmeticCSS                                   // #$# rules (https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#cosmetic-css-rules)
	CosmeticJS                                    // #%# rules (https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#javascript-rules)

	// TODO: Move HTML filtering rules to a different file/structure
	CosmeticHTML // $$ rules (https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#html-filtering-rules)
)

// cosmeticRuleMarker is a special marker that defines what type of cosmetic rule we are dealing with
type cosmeticRuleMarker string

// cosmeticRuleMarker enumeration
const (
	// https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#cosmetic-elemhide-rules
	markerElementHiding                cosmeticRuleMarker = "##"
	markerElementHidingException       cosmeticRuleMarker = "#@#"
	markerElementHidingExtCSS          cosmeticRuleMarker = "#?#"
	markerElementHidingExtCSSException cosmeticRuleMarker = "#@?#"

	// https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#cosmetic-css-rules
	markerCSS                cosmeticRuleMarker = "#$#"
	markerCSSException       cosmeticRuleMarker = "#@$#"
	markerCSSExtCSS          cosmeticRuleMarker = "#$?#"
	markerCSSExtCSSException cosmeticRuleMarker = "#@$?#"

	// https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#javascript-rules
	markerJS          cosmeticRuleMarker = "#%#"
	markerJSException cosmeticRuleMarker = "#@%#"

	// https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#html-filtering-rules
	markerHTML          cosmeticRuleMarker = "$$"
	markerHTMLException cosmeticRuleMarker = "$@$"
)

// contains all possible cosmetic rule markers
var cosmeticRulesMarkers = []string{
	string(markerElementHiding), string(markerElementHidingException),
	string(markerElementHidingExtCSS), string(markerElementHidingExtCSSException),
	string(markerCSS), string(markerCSSException),
	string(markerCSSExtCSS), string(markerCSSExtCSSException),
	string(markerJS), string(markerJSException),
	string(markerHTML), string(markerHTMLException),
}

// necessary for findCosmeticRuleMarker function. Initialized in the init() function
var cosmeticRuleMarkersFirstChars []byte

func init() {
	// This is important for "findCosmeticRuleMarker" function to sort markers in this order
	sort.Sort(sort.Reverse(byLength(cosmeticRulesMarkers)))

	for _, marker := range cosmeticRulesMarkers {
		if bytes.IndexByte(cosmeticRuleMarkersFirstChars, marker[0]) == -1 {
			cosmeticRuleMarkersFirstChars = append(cosmeticRuleMarkersFirstChars, marker[0])
		}
	}
}

// CosmeticRule represents a cosmetic rule (element hiding, CSS, scriptlet)
type CosmeticRule struct {
	RuleText     string           // RuleText is the original rule text
	FilterListID int              // Filter list identifier
	Type         CosmeticRuleType // Type of the rule

	permittedDomains  []string // a list of permitted domains for this rule
	restrictedDomains []string // a list of restricted domains for this rule

	// Content meaning depends on the rule type.
	// Element hiding: content is just a selector
	// CSS: content is a selector + style definition
	// JS: text of the script to be injected
	Content string

	// Whitelist means that this rule is meant to disable rules with the same content on the specified domains
	// For instance, https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#elemhide-exceptions
	Whitelist bool

	// ExtendedCSS means that this rule is supposed to be applied by the javascript library
	// https://github.com/AdguardTeam/ExtendedCss
	ExtendedCSS bool
}

// NewCosmeticRule parses the rule text and creates a
func NewCosmeticRule(ruleText string, filterListID int) (*CosmeticRule, error) {
	f := CosmeticRule{
		RuleText:     ruleText,
		FilterListID: filterListID,
	}

	index, m := findCosmeticRuleMarker(ruleText)
	if index == -1 {
		return nil, &RuleSyntaxError{msg: "cannot find cosmetic marker", ruleText: ruleText}
	}

	if index > 0 {
		// This means that the marker is preceded by the list of domains
		// Now it's a good time to parse them.
		domains := ruleText[:index]
		permitted, restricted, err := loadDomains(domains, ",")
		if err != nil {
			return nil, &RuleSyntaxError{msg: "cannot load domains", ruleText: ruleText}
		}
		f.permittedDomains = permitted
		f.restrictedDomains = restricted
	}

	f.Content = strings.TrimSpace(ruleText[index+len(m):])
	if f.Content == "" {
		return nil, &RuleSyntaxError{msg: "empty rule content", ruleText: ruleText}
	}

	switch cosmeticRuleMarker(m) {
	case markerElementHiding:
		f.Type = CosmeticElementHiding
	case markerElementHidingException:
		f.Type = CosmeticElementHiding
		f.Whitelist = true
	default:
		return nil, ErrUnsupportedRule
	}

	if f.Whitelist && len(f.permittedDomains) == 0 {
		return nil, &RuleSyntaxError{msg: "whitelist rule must have at least one domain specified", ruleText: ruleText}
	}

	// TODO: validate content
	// TODO: detect ExtCSS pseudo-classes

	return &f, nil
}

// Text returns the original rule text
// Implements the `Rule` interface
func (f *CosmeticRule) Text() string {
	return f.RuleText
}

// GetFilterListID returns ID of the filter list this rule belongs to
func (f *CosmeticRule) GetFilterListID() int {
	return f.FilterListID
}

// String returns original rule text
func (f *CosmeticRule) String() string {
	return f.RuleText
}

// IsGeneric returns true if rule can be considered generic (is not limited to a specific domain)
func (f *CosmeticRule) IsGeneric() bool {
	return len(f.permittedDomains) == 0
}

// Match returns true if this rule can be used on the specified hostname
func (f *CosmeticRule) Match(hostname string) bool {
	// TODO: Improve hosts matching, start using a better approach (token-based maps)

	if len(f.permittedDomains) == 0 && len(f.restrictedDomains) == 0 {
		return true
	}

	if len(f.restrictedDomains) > 0 {
		if isDomainOrSubdomainOfAny(hostname, f.restrictedDomains) {
			// Domain or host is restricted
			// i.e. $domain=~example.org
			return false
		}
	}

	if len(f.permittedDomains) > 0 {
		if !isDomainOrSubdomainOfAny(hostname, f.permittedDomains) {
			// Domain is not among permitted
			// i.e. $domain=example.org and we're checking example.com
			return false
		}
	}

	return true
}

// isCosmetic checks if this is a cosmetic filtering rule
func isCosmetic(line string) bool {
	index, _ := findCosmeticRuleMarker(line)
	return index != -1
}

// findCosmeticRuleMarker looks for a cosmetic rule marker in the
// rule text and returns the start index and the marker found.
// if nothing found, it returns -1.
func findCosmeticRuleMarker(ruleText string) (int, string) {
	for _, firstMarkerChar := range cosmeticRuleMarkersFirstChars {
		startIndex := strings.IndexByte(ruleText, firstMarkerChar)
		if startIndex == -1 {
			continue
		}

		// Handling false positives while looking for cosmetic rules in host files.
		//
		// For instance, it could look like this:
		// 0.0.0.0 jackbootedroom.com  ## phishing
		if startIndex > 0 && ruleText[startIndex-1] == ' ' {
			continue
		}

		for _, marker := range cosmeticRulesMarkers {
			if startsAtIndexWith(ruleText, startIndex, marker) {
				return startIndex, marker
			}
		}
	}

	return -1, ""
}

// startsAtIndexWith checks if the specified string starts with a substr at the specified index
// str is the string to check
// startIndex is the index to start checking from
// substr is the substring to check
func startsAtIndexWith(str string, startIndex int, substr string) bool {
	if len(str)-startIndex < len(substr) {
		return false
	}

	for i := 0; i < len(substr); i++ {
		if str[startIndex+i] != substr[i] {
			return false
		}
	}

	return true
}
