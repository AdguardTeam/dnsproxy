package urlfilter

import (
	"regexp"
	"strings"
)

const (
	// MaskStartURL definition:
	// Matching the beginning of an address. With this character you don't
	// have to specify a particular protocol and subdomain in address mask.
	// It means, || stands for http://*., https://*., ws://*., wss://*. at once.
	MaskStartURL = "||"

	// MaskPipe definition:
	// A pointer to the beginning or the end of address. The value depends on the
	// character placement in the mask. For example, a rule swf| corresponds
	// to http://example.com/annoyingflash.swf , but not to http://example.com/swf/index.html.
	// |http://example.org corresponds to http://example.org, but not to http://domain.com?url=http://example.org.
	MaskPipe = "|"

	// MaskSeparator definition:
	// Separator character mark. Separator character is any character,
	// but a letter, a digit, or one of the following: _ - .
	MaskSeparator = "^"

	// MaskAnyCharacter is a wildcard character. It is used to represent "any set of characters".
	// This can also be an empty string or a string of any length.
	MaskAnyCharacter = "*"

	// RegexAnyCharacter corresponds to MaskAnyCharacter.
	RegexAnyCharacter = ".*"

	// RegexSeparator corresponds to MaskSeparator.
	RegexSeparator = "([^ a-zA-Z0-9.%]|$)"

	// RegexStartURL corresponds to MaskStartURL.
	RegexStartURL = "^(http|https|ws|wss)://([a-z0-9-_.]+\\.)?"

	// RegexEndString corresponds to MaskPipe if it is in the end of a pattern.
	RegexEndString = "$"

	// RegexStartString corresponds to MaskPipe if it is in the beginning of a pattern.
	RegexStartString = "^"
)

// https://developer.mozilla.org/en/JavaScript/Reference/Global_Objects/regexp
// should be escaped . * + ? ^ $ { } ( ) | [ ] / \
// except of * | ^
var (
	specialCharacters      = []string{".", "+", "?", "$", "{", "}", "(", ")", "[", "]", "/", "\\"}
	reSpecialCharacters, _ = regexp.Compile("[" + strings.Join(specialCharacters, "\\") + "]")
)

// patternToRegexp is a helper method for creating regular expressions from the simple
// wildcard-based syntax which is used in basic filters
// https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#basic-rules
func patternToRegexp(pattern string) string {
	if pattern == MaskStartURL || pattern == MaskPipe ||
		pattern == MaskAnyCharacter || pattern == "" {
		return RegexAnyCharacter
	}

	if strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") {
		return pattern[1 : len(pattern)-1]
	}

	// example.org/* -> example.org^
	if strings.HasSuffix(pattern, "/*") {
		pattern = pattern[:len(pattern)-len("/*")] + "^"
	}

	// Escape special characters except of * | ^
	regex := reSpecialCharacters.ReplaceAllString(pattern, "\\$0")

	// Now escape "|" characters but avoid escaping them in the special places
	if strings.HasPrefix(regex, MaskStartURL) {
		regex = regex[:len(MaskStartURL)] +
			strings.Replace(regex[len(MaskStartURL):len(regex)-1], MaskPipe, "\\"+MaskPipe, -1) +
			regex[len(regex)-1:]
	} else {
		regex = regex[:len(MaskPipe)] +
			strings.Replace(regex[len(MaskPipe):len(regex)-1], MaskPipe, "\\"+MaskPipe, -1) +
			regex[len(regex)-1:]
	}

	// Replace special URL masks
	regex = strings.Replace(regex, MaskAnyCharacter, RegexAnyCharacter, -1)
	regex = strings.Replace(regex, MaskSeparator, RegexSeparator, -1)

	// Replace start URL and pipes
	if strings.HasPrefix(regex, MaskStartURL) {
		regex = RegexStartURL + regex[len(MaskStartURL):]
	} else if strings.HasPrefix(regex, MaskPipe) {
		regex = RegexStartString + regex[len(MaskPipe):]
	}

	if strings.HasSuffix(regex, MaskPipe) {
		regex = regex[:len(regex)-1] + RegexEndString
	}

	return regex
}
