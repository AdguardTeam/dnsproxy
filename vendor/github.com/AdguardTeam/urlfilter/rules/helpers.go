package rules

import "strings"

// splitWithEscapeCharacter splits string by the specified separator if it is not escaped
func splitWithEscapeCharacter(str string, sep byte, escapeCharacter byte, preserveAllTokens bool) []string {
	parts := make([]string, 0)

	if str == "" {
		return parts
	}

	var sb strings.Builder
	escaped := false
	for i := 0; i < len(str); i++ {
		c := str[i]

		if c == escapeCharacter {
			escaped = true
		} else if c == sep {
			if escaped {
				sb.WriteByte(c)
				escaped = false
			} else {
				if preserveAllTokens || sb.Len() > 0 {
					parts = append(parts, sb.String())
					sb.Reset()
				}
			}
		} else {
			if escaped {
				escaped = false
				sb.WriteByte(escapeCharacter)
			}
			sb.WriteByte(c)
		}
	}

	if preserveAllTokens || sb.Len() > 0 {
		parts = append(parts, sb.String())
	}

	return parts
}

// stringArraysEquals checks if arrays are equal
func stringArraysEquals(l []string, r []string) bool {
	if len(l) != len(r) {
		return false
	}

	for i := 0; i < len(l); i++ {
		if l[i] != r[i] {
			return false
		}
	}

	return true
}

// sort.Interface
type byLength []string

func (s byLength) Len() int {
	return len(s)
}
func (s byLength) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s byLength) Less(i, j int) bool {
	return len(s[i]) < len(s[j])
}
