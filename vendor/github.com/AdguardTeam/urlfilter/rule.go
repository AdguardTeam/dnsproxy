package urlfilter

import (
	"errors"
	"fmt"
	"strings"

	"github.com/asaskevich/govalidator"
)

// RuleSyntaxError represents an error while parsing a filtering rule
type RuleSyntaxError struct {
	msg      string
	ruleText string
}

func (e *RuleSyntaxError) Error() string {
	return fmt.Sprintf("syntax error: %s, rule: %s", e.msg, e.ruleText)
}

var (
	// ErrUnsupportedRule signals that this might be a valid rule type,
	// but it is not yet supported by this library
	ErrUnsupportedRule = errors.New("this type of rules is unsupported")

	// ErrRuleRetrieval signals that the rule cannot be retrieved by RuleList
	// by the the specified index
	ErrRuleRetrieval = errors.New("cannot retrieve the rule")
)

// Rule is a base interface for all filtering rules
type Rule interface {
	// Text returns the original rule text
	Text() string

	// GetFilterListID returns ID of the filter list this rule belongs to
	GetFilterListID() int
}

// NewRule creates a new filtering rule from the specified line
// It returns nil if the line is empty or if it is a comment
func NewRule(line string, filterListID int) (Rule, error) {
	line = strings.TrimSpace(line)

	if line == "" || isComment(line) {
		return nil, nil
	}

	if isCosmetic(line) {
		return NewCosmeticRule(line, filterListID)
	}

	f, err := NewHostRule(line, filterListID)
	if err == nil {
		return f, nil
	}

	return NewNetworkRule(line, filterListID)
}

// isComment checks if the line is a comment
func isComment(line string) bool {
	if len(line) == 0 {
		return false
	}

	if line[0] == '!' {
		return true
	}

	if line[0] == '#' {
		if len(line) == 1 {
			return true
		}

		// Now we should check that this is not a cosmetic rule
		for _, marker := range cosmeticRulesMarkers {
			if startsAtIndexWith(line, 0, marker) {
				return false
			}
		}

		return true
	}

	return false
}

// loadDomains loads $domain modifier or cosmetic rules domains
// domains is the list of domains
// sep is the separator character. for network rules it is '|', for cosmetic it is ','.
func loadDomains(domains string, sep string) (permittedDomains []string, restrictedDomains []string, err error) {
	if domains == "" {
		err = errors.New("no domains specified")
		return
	}

	list := strings.Split(domains, sep)
	for i := 0; i < len(list); i++ {
		d := list[i]
		restricted := false
		if strings.HasPrefix(d, "~") {
			restricted = true
			d = d[1:]
		}

		if !govalidator.IsDNSName(d) {
			err = fmt.Errorf("invalid domain specified: %s", domains)
			return
		}

		if restricted {
			restrictedDomains = append(restrictedDomains, d)
		} else {
			permittedDomains = append(permittedDomains, d)
		}
	}

	return
}
