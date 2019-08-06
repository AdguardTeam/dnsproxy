package urlfilter

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// RequestType is the request types enumeration
type RequestType int

const (
	// TypeDocument (main frame)
	TypeDocument RequestType = 1 << iota
	// TypeSubdocument (iframe) $subdocument
	TypeSubdocument
	// TypeScript (javascript, etc) $script
	TypeScript
	// TypeStylesheet (css) $stylesheet
	TypeStylesheet
	// TypeObject (flash, etc) $object
	TypeObject
	// TypeImage (any image) $image
	TypeImage
	// TypeXmlhttprequest (ajax/fetch) $xmlhttprequest
	TypeXmlhttprequest
	// TypeObjectSubrequest - a request sent from inside of an object (flash) $object-subrequest
	TypeObjectSubrequest
	// TypeMedia (video/music) $media
	TypeMedia
	// TypeFont (any custom font) $font
	TypeFont
	// TypeWebsocket (a websocket connection) $websocket
	TypeWebsocket
	// TypeOther - any other request type
	TypeOther

	// TypeAllRequestTypes combines all other request type flags
	TypeAllRequestTypes = TypeDocument | TypeSubdocument | TypeScript | TypeStylesheet |
		TypeObject | TypeImage | TypeXmlhttprequest | TypeObjectSubrequest | TypeMedia |
		TypeFont | TypeWebsocket | TypeOther
)

// Request represents a web request with all it's necessary properties
type Request struct {
	RequestType RequestType // request type
	ThirdParty  bool        // true if request is third-party

	URL          string // Request URL
	URLLowerCase string // Request URL in lower case
	Hostname     string // Request hostname
	Domain       string // Request domain (eTLD+1)

	SourceURL      string // Source URL
	SourceHostname string // Source hostname
	SourceDomain   string // Source domain (eTLD+1)
}

// NewRequest creates a new instance of "Request" and populates it's fields
func NewRequest(url string, sourceURL string, requestType RequestType) *Request {
	r := Request{
		RequestType: requestType,

		URL:          url,
		URLLowerCase: strings.ToLower(url),
		Hostname:     extractHostname(url),

		SourceURL:      sourceURL,
		SourceHostname: extractHostname(sourceURL),
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(r.Hostname)
	if err == nil && domain != "" {
		r.Domain = domain
	} else {
		r.Domain = r.Hostname
	}

	sourceDomain, err := publicsuffix.EffectiveTLDPlusOne(r.SourceHostname)
	if err == nil && sourceDomain != "" {
		r.SourceDomain = sourceDomain
	} else {
		r.SourceDomain = r.SourceHostname
	}

	if r.SourceDomain != "" && r.SourceDomain != r.Domain {
		r.ThirdParty = true
	}

	return &r
}

// NewRequestForHostname creates a new instance of "Request" for matching hostname.
// It uses "http://" as a protocol and TypeDocument as a request type.
func NewRequestForHostname(hostname string) *Request {
	r := Request{
		RequestType:  TypeDocument,
		URL:          "http://" + hostname,
		URLLowerCase: "http://" + hostname,
		Hostname:     hostname,
		ThirdParty:   false,
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(r.Hostname)
	if err == nil && domain != "" {
		r.Domain = domain
	} else {
		r.Domain = r.Hostname
	}

	return &r
}

func extractHostname(url string) string {
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
