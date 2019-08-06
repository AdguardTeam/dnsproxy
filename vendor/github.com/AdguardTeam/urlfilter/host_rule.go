package urlfilter

import (
	"net"
	"strings"

	"github.com/asaskevich/govalidator"
)

// HostRule is a structure for simple host-level rules (i.e. /etc/hosts syntax).
// http://man7.org/linux/man-pages/man5/hosts.5.html
// It also supports "just domain" syntax. In this case, the IP will be set to 0.0.0.0.
type HostRule struct {
	RuleText     string   // RuleText is the original rule text
	FilterListID int      // Filter list identifier
	Hostnames    []string // Hostnames is the list of hostnames that is configured
	IP           net.IP   // ip address
}

// NewHostRule parses the rule and creates a new HostRule instance
// The format is:
// IP_address canonical_hostname [aliases...]
func NewHostRule(ruleText string, filterListID int) (*HostRule, error) {
	h := HostRule{
		RuleText:     ruleText,
		FilterListID: filterListID,
	}

	// Strip comment
	commentIndex := strings.IndexByte(ruleText, '#')
	if commentIndex > 0 {
		ruleText = ruleText[0 : commentIndex-1]
	}

	parts := strings.Fields(strings.TrimSpace(ruleText))
	var ip net.IP
	var hostnames []string

	if len(parts) >= 2 {
		for i, part := range parts {
			if i == 0 {
				ip = net.ParseIP(parts[0])
				if ip == nil {
					return nil, &RuleSyntaxError{msg: "cannot parse IP", ruleText: ruleText}
				}
			} else {
				hostnames = append(hostnames, part)
			}
		}
	} else if len(parts) == 1 && govalidator.IsDNSName(parts[0]) {
		hostnames = append(hostnames, parts[0])
		ip = net.IPv4(0, 0, 0, 0)
	} else {
		return nil, &RuleSyntaxError{msg: "invalid syntax", ruleText: ruleText}
	}

	h.Hostnames = hostnames
	h.IP = ip
	return &h, nil
}

// Text returns the original rule text
// Implements the `Rule` interface
func (f *HostRule) Text() string {
	return f.RuleText
}

// GetFilterListID returns ID of the filter list this rule belongs to
func (f *HostRule) GetFilterListID() int {
	return f.FilterListID
}

// String returns original rule text
func (f *HostRule) String() string {
	return f.RuleText
}

// Match checks if this filtering rule matches the specified hostname
func (f *HostRule) Match(hostname string) bool {
	if len(f.Hostnames) == 1 && hostname == f.Hostnames[0] {
		return true
	}

	for _, h := range f.Hostnames {
		if h == hostname {
			return true
		}
	}

	return false
}
