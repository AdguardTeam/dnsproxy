package urlfilter

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

const (
	maskWhiteList    = "@@"
	maskRegexRule    = "/"
	replaceOption    = "replace"
	optionsDelimiter = '$'
	escapeCharacter  = '\\'
)

var (
	reEscapedOptionsDelimiter = regexp.MustCompile(regexp.QuoteMeta("\\$"))
	reRegexpBrackets1         = regexp.MustCompile("([^\\\\])\\(.*[^\\\\]\\)")
	reRegexpBrackets2         = regexp.MustCompile("([^\\\\])\\{.*[^\\\\]\\}")
	reRegexpBrackets3         = regexp.MustCompile("([^\\\\])\\[.*[^\\\\]\\]")
	reRegexpEscapedCharacters = regexp.MustCompile("([^\\\\])\\[a-zA-Z]")
	reRegexpSpecialCharacters = regexp.MustCompile("[\\\\^$*+?.()|[\\]{}]")
)

// NetworkRuleOption is the enumeration of various rule options
// In order to save memory, we store some options as a flag
type NetworkRuleOption uint

// NetworkRuleOption enumeration
const (
	OptionThirdParty NetworkRuleOption = 1 << iota // $third-party modifier
	OptionMatchCase                                // $match-case modifier
	OptionImportant                                // $important modifier

	// Whitelist rules modifiers
	// Each of them can disable part of the functionality

	OptionElemhide     // $elemhide modifier
	OptionGenerichide  // $generichide modifier
	OptionGenericblock // $genericblock modifier
	OptionJsinject     // $jsinject modifier
	OptionUrlblock     // $urlblock modifier
	OptionContent      // $content modifier
	OptionExtension    // $extension modifier

	// Whitelist -- specific to Stealth mode
	OptionStealth // $stealth

	// Content-modifying
	OptionEmpty // $empty
	OptionMp4   // $mp4

	// Blocking
	OptionPopup // $popup

	// Other
	OptionCsp     // $csp
	OptionReplace // $replace
	OptionCookie  // $cookie

	// Blacklist-only options
	OptionBlacklistOnly = OptionPopup | OptionEmpty | OptionMp4

	// Whitelist-only options
	OptionWhitelistOnly = OptionElemhide | OptionGenericblock | OptionGenerichide |
		OptionJsinject | OptionUrlblock | OptionContent | OptionExtension |
		OptionStealth
)

// NetworkRule is a basic filtering rule
// https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#basic-rules
type NetworkRule struct {
	RuleText     string // RuleText is the original rule text
	Whitelist    bool   // true if this is an exception rule
	FilterListID int    // Filter list identifier
	Shortcut     string // the longest substring of the rule pattern with no special characters

	permittedDomains  []string // a list of permitted domains from the $domain modifier
	restrictedDomains []string // a list of restricted domains from the $domain modifier

	enabledOptions  NetworkRuleOption // Flag with all enabled rule options
	disabledOptions NetworkRuleOption // Flag with all disabled rule options

	permittedRequestTypes  RequestType // Flag with all permitted request types. 0 means ALL.
	restrictedRequestTypes RequestType // Flag with all restricted request types. 0 means NONE.

	pattern string         // Pattern is the basic rule pattern ready to be compiled to regex
	regex   *regexp.Regexp // Regex is the regular expression compiled from the pattern
	invalid bool           // Marker that the rule is invalid. Match will always return false in this case

	sync.Mutex
}

// NewNetworkRule parses the rule text and returns a filter rule
func NewNetworkRule(ruleText string, filterListID int) (*NetworkRule, error) {
	// split rule into pattern and options
	pattern, options, whitelist, err := parseRuleText(ruleText)

	if err != nil {
		return nil, err
	}

	rule := NetworkRule{
		RuleText:     ruleText,
		Whitelist:    whitelist,
		FilterListID: filterListID,
		pattern:      pattern,
	}

	// parse options
	err = rule.loadOptions(options)
	if err != nil {
		return nil, err
	}

	// validate rule
	if pattern == MaskStartURL || pattern == MaskPipe ||
		pattern == MaskAnyCharacter || pattern == "" ||
		len(pattern) < 3 {
		if len(rule.permittedDomains) == 0 {
			// Rule matches too much and does not have any domain restriction
			// We should not allow this kind of rules
			return nil, fmt.Errorf("the rule is too wide, add domain restriction or make it more specific")
		}
	}

	rule.loadShortcut()
	return &rule, nil
}

// Text returns the original rule text
// Implements the `Rule` interface
func (f *NetworkRule) Text() string {
	return f.RuleText
}

// GetFilterListID returns ID of the filter list this rule belongs to
func (f *NetworkRule) GetFilterListID() int {
	return f.FilterListID
}

// String returns original rule text
func (f *NetworkRule) String() string {
	return f.RuleText
}

// Match checks if this filtering rule matches the specified request
func (f *NetworkRule) Match(r *Request) bool {
	if !f.matchShortcut(r) {
		return false
	}

	if f.IsOptionEnabled(OptionThirdParty) && !r.ThirdParty {
		return false
	}

	if f.IsOptionDisabled(OptionThirdParty) && r.ThirdParty {
		return false
	}

	if !f.matchRequestType(r.RequestType) {
		return false
	}

	if !f.matchDomain(r.SourceHostname) {
		return false
	}

	return f.matchPattern(r)
}

// IsOptionEnabled returns true if the specified option is enabled
func (f *NetworkRule) IsOptionEnabled(option NetworkRuleOption) bool {
	return (f.enabledOptions & option) == option
}

// IsOptionDisabled returns true if the specified option is disabled
func (f *NetworkRule) IsOptionDisabled(option NetworkRuleOption) bool {
	return (f.disabledOptions & option) == option
}

// isRegexRule returns true if rule's pattern is a regular expression
func (f *NetworkRule) isRegexRule() bool {
	if strings.HasPrefix(f.pattern, maskRegexRule) &&
		strings.HasSuffix(f.pattern, maskRegexRule) {
		return true
	}
	return false
}

// isHigherPriority checks if the rule has higher priority that the specified rule
// whitelist + $important > $important > whitelist > basic rules
func (f *NetworkRule) isHigherPriority(r *NetworkRule) bool {
	// TODO: Rules with more modifiers have higher priority

	important := f.IsOptionEnabled(OptionImportant)
	rImportant := r.IsOptionEnabled(OptionImportant)

	if (f.Whitelist && important) && !(r.Whitelist && rImportant) {
		return true
	}

	if important && !rImportant {
		return true
	}

	if f.Whitelist && !rImportant && !r.Whitelist {
		return true
	}

	return false
}

// matchPattern uses the regex pattern to match the request URL
func (f *NetworkRule) matchPattern(r *Request) bool {
	f.Lock()
	if f.regex == nil {
		if f.invalid {
			f.Unlock()
			return false
		}

		pattern := patternToRegexp(f.pattern)
		if !f.IsOptionEnabled(OptionMatchCase) {
			pattern = "(?i)" + pattern
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			f.invalid = true
			f.Unlock()
			return false
		}
		f.regex = re
	}
	f.Unlock()

	if r.IsHostnameRequest && !strings.HasPrefix(f.pattern, MaskStartURL) {
		return f.regex.MatchString(r.Hostname)
	}
	return f.regex.MatchString(r.URL)
}

// matchShortcut simply checks if shortcut is a substring of the URL
func (f *NetworkRule) matchShortcut(r *Request) bool {
	return strings.Index(r.URLLowerCase, f.Shortcut) != -1
}

// matchDomain checks if the specified filtering rule is allowed on this domain
func (f *NetworkRule) matchDomain(domain string) bool {
	if len(f.permittedDomains) == 0 && len(f.restrictedDomains) == 0 {
		return true
	}

	if len(f.restrictedDomains) > 0 {
		if isDomainOrSubdomainOfAny(domain, f.restrictedDomains) {
			// Domain or host is restricted
			// i.e. $domain=~example.org
			return false
		}
	}

	if len(f.permittedDomains) > 0 {
		if !isDomainOrSubdomainOfAny(domain, f.permittedDomains) {
			// Domain is not among permitted
			// i.e. $domain=example.org and we're checking example.com
			return false
		}
	}

	return true
}

// matchRequestType checks if the specified request type matches the rule properties
func (f *NetworkRule) matchRequestType(requestType RequestType) bool {
	if f.permittedRequestTypes != 0 {
		if (f.permittedRequestTypes & requestType) != requestType {
			return false
		}
	}

	if f.restrictedRequestTypes != 0 {
		if (f.restrictedRequestTypes & requestType) == requestType {
			return false
		}
	}

	return true
}

// setRequestType permits or forbids the specified request type
func (f *NetworkRule) setRequestType(requestType RequestType, permitted bool) {
	if permitted {
		f.permittedRequestTypes |= requestType
	} else {
		f.restrictedRequestTypes |= requestType
	}
}

// setOptionEnabled enables or disables the specified option
// it can return error if this option cannot be used with this type of rules
func (f *NetworkRule) setOptionEnabled(option NetworkRuleOption, enabled bool) error {
	if f.Whitelist && (option&OptionBlacklistOnly) == option {
		return fmt.Errorf("modifier cannot be used in a whitelist rule: %v", option)
	}

	if !f.Whitelist && (option&OptionWhitelistOnly) == option {
		return fmt.Errorf("modifier cannot be used in a blacklist rule: %v", option)
	}

	if enabled {
		f.enabledOptions |= option
	} else {
		f.disabledOptions |= option
	}

	return nil
}

// loadOptions loads all the filtering rule options
// read the details on each here: https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#basic-rules
func (f *NetworkRule) loadOptions(options string) error {
	if options == "" {
		return nil
	}

	optionsParts := splitWithEscapeCharacter(options, ',', '\\', false)
	for i := 0; i < len(optionsParts); i++ {
		option := optionsParts[i]
		valueIndex := strings.Index(option, "=")
		optionName := option
		optionValue := ""
		if valueIndex > 0 {
			optionName = option[:valueIndex]
			optionValue = option[valueIndex+1:]
		}

		err := f.loadOption(optionName, optionValue)
		if err != nil {
			return err
		}
	}

	// Rules of these types can be applied to documents only
	// $jsinject, $elemhide, $urlblock, $genericblock, $generichide and $content for whitelist rules.
	// $popup - for url blocking
	if f.IsOptionEnabled(OptionJsinject) || f.IsOptionEnabled(OptionElemhide) ||
		f.IsOptionEnabled(OptionContent) || f.IsOptionEnabled(OptionUrlblock) ||
		f.IsOptionEnabled(OptionGenericblock) || f.IsOptionEnabled(OptionGenerichide) ||
		f.IsOptionEnabled(OptionExtension) || f.IsOptionEnabled(OptionPopup) {
		f.permittedRequestTypes = TypeDocument
	}

	return nil
}

// loadOption loads specified option with its value (optional)
// nolint:gocyclo
func (f *NetworkRule) loadOption(name string, value string) error {
	switch name {
	// General options
	case "third-party", "~first-party":
		return f.setOptionEnabled(OptionThirdParty, true)
	case "~third-party", "first-party":
		return f.setOptionEnabled(OptionThirdParty, false)
	case "match-case":
		return f.setOptionEnabled(OptionMatchCase, true)
	case "~match-case":
		return f.setOptionEnabled(OptionMatchCase, false)
	case "important":
		return f.setOptionEnabled(OptionImportant, true)

	case "domain":
		permitted, restricted, err := loadDomains(value, "|")
		f.permittedDomains = permitted
		f.restrictedDomains = restricted
		return err

	// Document-level whitelist rules
	case "elemhide":
		return f.setOptionEnabled(OptionElemhide, true)
	case "generichide":
		return f.setOptionEnabled(OptionGenerichide, true)
	case "genericblock":
		return f.setOptionEnabled(OptionGenericblock, true)
	case "jsinject":
		return f.setOptionEnabled(OptionJsinject, true)
	case "urlblock":
		return f.setOptionEnabled(OptionUrlblock, true)
	case "content":
		return f.setOptionEnabled(OptionContent, true)

	// $extension can be also disabled
	case "extension":
		return f.setOptionEnabled(OptionExtension, true)
	case "~extension":
		// $document must be specified before ~extension
		// TODO: Depends on options order, this is not good
		f.enabledOptions = f.enabledOptions ^ OptionExtension
		return nil

	// $document
	case "document":
		err := f.setOptionEnabled(OptionElemhide, true)
		// Ignore others
		_ = f.setOptionEnabled(OptionJsinject, true)
		_ = f.setOptionEnabled(OptionUrlblock, true)
		_ = f.setOptionEnabled(OptionContent, true)
		_ = f.setOptionEnabled(OptionExtension, true)
		return err

	// Stealth mode
	case "stealth":
		return f.setOptionEnabled(OptionStealth, true)

	// $popup blocking options
	case "popup":
		return f.setOptionEnabled(OptionPopup, true)

	// $empty and $mp4
	// TODO: Deprecate in favor of $redirect
	case "empty":
		return f.setOptionEnabled(OptionEmpty, true)
	case "mp4":
		return f.setOptionEnabled(OptionMp4, true)

	// Content type options
	case "script":
		f.setRequestType(TypeScript, true)
		return nil
	case "~script":
		f.setRequestType(TypeScript, false)
		return nil
	case "stylesheet":
		f.setRequestType(TypeStylesheet, true)
		return nil
	case "~stylesheet":
		f.setRequestType(TypeStylesheet, false)
		return nil
	case "subdocument":
		f.setRequestType(TypeSubdocument, true)
		return nil
	case "~subdocument":
		f.setRequestType(TypeSubdocument, false)
		return nil
	case "object":
		f.setRequestType(TypeObject, true)
		return nil
	case "~object":
		f.setRequestType(TypeObject, false)
		return nil
	case "image":
		f.setRequestType(TypeImage, true)
		return nil
	case "~image":
		f.setRequestType(TypeImage, false)
		return nil
	case "xmlhttprequest":
		f.setRequestType(TypeXmlhttprequest, true)
		return nil
	case "~xmlhttprequest":
		f.setRequestType(TypeXmlhttprequest, false)
		return nil
	case "object-subrequest":
		f.setRequestType(TypeObjectSubrequest, true)
		return nil
	case "~object-subrequest":
		f.setRequestType(TypeObjectSubrequest, false)
		return nil
	case "media":
		f.setRequestType(TypeMedia, true)
		return nil
	case "~media":
		f.setRequestType(TypeMedia, false)
		return nil
	case "font":
		f.setRequestType(TypeFont, true)
		return nil
	case "~font":
		f.setRequestType(TypeFont, false)
		return nil
	case "websocket":
		f.setRequestType(TypeWebsocket, true)
		return nil
	case "~websocket":
		f.setRequestType(TypeWebsocket, false)
		return nil
	case "other":
		f.setRequestType(TypeOther, true)
		return nil
	case "~other":
		f.setRequestType(TypeOther, false)
		return nil
	}

	return fmt.Errorf("unknown filter modifier: %s=%s", name, value)
}

// loadShortcut extracts a shortcut from the pattern.
// shortcut is the longest substring of the pattern that does not contain
// any special characters
func (f *NetworkRule) loadShortcut() {
	var shortcut string
	if f.isRegexRule() {
		shortcut = findRegexpShortcut(f.pattern)
	} else {
		shortcut = findShortcut(f.pattern)
	}

	// shortcut needs to be at least longer than 1 character
	if len(shortcut) > 1 {
		f.Shortcut = shortcut
	}
}

// findShortcut searches for the longest substring of the pattern that
// does not contain any special characters: *,^,|.
func findShortcut(pattern string) string {
	longest := ""
	parts := strings.FieldsFunc(pattern, func(r rune) bool {
		switch r {
		case '*', '^', '|':
			return true
		}
		return false
	})
	for _, part := range parts {
		if len(part) > len(longest) {
			longest = part
		}
	}
	return strings.ToLower(longest)
}

// findRegexpShortcut searches for a shortcut inside of a regexp pattern.
// Shortcut in this case is a longest string with no REGEX special characters
// Also, we discard complicated regexps right away.
func findRegexpShortcut(pattern string) string {
	// strip backslashes
	pattern = pattern[1 : len(pattern)-1]

	if strings.Index(pattern, "?") != -1 {
		// Do not mess with complex expressions which use lookahead
		// And with those using ? special character: https://github.com/AdguardTeam/AdguardBrowserExtension/issues/978
		return ""
	}

	// placeholder for a special character
	specialCharacter := "..."

	// (Dirty) prepend specialCharacter for the following replace calls to work properly
	pattern = specialCharacter + pattern

	//// Strip all types of brackets
	pattern = reRegexpBrackets1.ReplaceAllString(pattern, "$1"+specialCharacter)
	pattern = reRegexpBrackets2.ReplaceAllString(pattern, "$1"+specialCharacter)
	pattern = reRegexpBrackets3.ReplaceAllString(pattern, "$1"+specialCharacter)

	// Strip some escaped characters
	pattern = reRegexpEscapedCharacters.ReplaceAllString(pattern, "$1"+specialCharacter)

	// Split by special characters
	parts := reRegexpSpecialCharacters.Split(pattern, -1)
	longest := ""
	for _, part := range parts {
		if len(part) > len(longest) {
			longest = part
		}
	}

	return strings.ToLower(longest)
}

// isDomainOrSubdomainOfAny checks if "domain" is domain or subdomain or any of the "domains"
func isDomainOrSubdomainOfAny(domain string, domains []string) bool {
	for _, d := range domains {
		if domain == d ||
			(strings.HasSuffix(domain, d) &&
				strings.HasSuffix(domain, "."+d)) {
			return true
		}
	}
	return false
}

// parseRuleText splits the rule text in multiple parts:
// pattern -- a basic rule pattern (which can be easily converted into a regex)
// options -- a string with all rule options
// whitelist -- indicates if rule is "whitelist" (e.g. it should unblock requests, not block them)
func parseRuleText(ruleText string) (pattern string, options string, whitelist bool, err error) {
	startIndex := 0
	if strings.HasPrefix(ruleText, maskWhiteList) {
		whitelist = true
		startIndex = len(maskWhiteList)
	}

	if len(ruleText) <= startIndex {
		err = fmt.Errorf("the rule is too short: %s", ruleText)
		return
	}

	// Avoid parsing options inside of a regex rule
	if strings.HasPrefix(ruleText, maskRegexRule) &&
		strings.HasSuffix(ruleText, maskRegexRule) &&
		!strings.Contains(ruleText, replaceOption+"=") {
		pattern = ruleText
		return
	}

	// Setting pattern to rule text (for the case of empty options)
	pattern = ruleText[startIndex:]

	foundEscaped := false
	for i := len(ruleText) - 2; i >= startIndex; i-- {
		c := ruleText[i]

		if c == optionsDelimiter {
			if i > startIndex && ruleText[i-1] == escapeCharacter {
				foundEscaped = true
			} else {
				pattern = ruleText[startIndex:i]
				options = ruleText[i+1:]

				if foundEscaped {
					options = reEscapedOptionsDelimiter.ReplaceAllString(options, string(optionsDelimiter))
				}

				// Options delimiter was found, exiting loop
				break
			}
		}
	}

	return
}
