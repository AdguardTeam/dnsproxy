package urlfilter

import (
	"bytes"
	"io"
	"strings"
)

// On Linux the size of the data block is usually 4KB
// So it makes sense to use 4KB.
const readerBufferSize = 4 * 1024

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

// getSubdomains splits the specified hostname and returns all subdomains (including the hostname itself)
func getSubdomains(hostname string) []string {
	parts := strings.Split(hostname, ".")
	var subdomains []string
	var domain = ""
	for i := len(parts) - 1; i >= 0; i-- {
		if domain == "" {
			domain = parts[i]
		} else {
			domain = parts[i] + "." + domain
		}
		subdomains = append(subdomains, domain)
	}
	return subdomains
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

// readLine reads from the reader until '\n'
// r - reader to read from
// b - buffer to use (the idea is to reuse the same buffer when it's possible)
func readLine(r io.Reader, b []byte) (string, error) {
	line := ""

	for {
		n, err := r.Read(b)
		if n > 0 {
			idx := bytes.IndexByte(b[:n], '\n')
			if idx == -1 {
				line += string(b[:n])
			} else {
				line += string(b[:idx])
				return line, err
			}
		} else {
			return line, err
		}
	}
}
