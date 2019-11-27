package filterutil

import "strings"

// ExtractHostname -- quickly retrieves hostname from an URL
func ExtractHostname(url string) string {
	if url == "" {
		return ""
	}

	firstIdx := strings.Index(url, "//")
	if firstIdx == -1 {
		// This is a non hierarchical structured URL (e.g. stun: or turn:)
		// https://tools.ietf.org/html/rfc4395#section-2.2
		// https://tools.ietf.org/html/draft-nandakumar-rtcweb-stun-uri-08#appendix-B
		firstIdx = strings.Index(url, ":")
		if firstIdx == -1 {
			return ""
		}
		firstIdx = firstIdx - 1
	} else {
		firstIdx = firstIdx + 2
	}

	nextIdx := 0
	for i := firstIdx; i < len(url); i++ {
		c := url[i]
		if c == '/' || c == ':' || c == '?' {
			nextIdx = i
			break
		}
	}

	if nextIdx == 0 {
		nextIdx = len(url)
	}

	if nextIdx <= firstIdx {
		return ""
	}

	return url[firstIdx:nextIdx]
}
