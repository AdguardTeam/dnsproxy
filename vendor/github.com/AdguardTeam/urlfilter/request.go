package urlfilter

import (
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// RequestType is the request types enumeration
type RequestType uint32

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
	// TypeMedia (video/music) $media
	TypeMedia
	// TypeFont (any custom font) $font
	TypeFont
	// TypeWebsocket (a websocket connection) $websocket
	TypeWebsocket
	// TypeOther - any other request type
	TypeOther
)

// Count returns count of the enabled flags
func (t RequestType) Count() int {
	if t == 0 {
		return 0
	}

	flags := uint32(t)
	count := 0
	var i uint
	for i = 0; i < 32; i++ {
		mask := uint32(1 << i)
		if (flags & mask) == mask {
			count++
		}
	}
	return count
}

// Request represents a web request with all it's necessary properties
type Request struct {
	RequestType RequestType // request type
	ThirdParty  bool        // true if request is third-party

	// IsHostnameRequest means that the request is for a given Hostname,
	//  and not for a URL, and we don't really know what protocol it is.
	// This can be true for DNS requests, or for HTTP CONNECT, or SNI matching.
	IsHostnameRequest bool

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
		RequestType:       TypeDocument,
		URL:               "http://" + hostname + "/",
		URLLowerCase:      "http://" + hostname + "/",
		Hostname:          hostname,
		ThirdParty:        false,
		IsHostnameRequest: true,
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

// assumeRequestType assumes request type from what we know at this point.
// req -- HTTP request
// res -- HTTP response or null if we don't know it at the moment
func assumeRequestType(req *http.Request, res *http.Response) RequestType {
	if res != nil {
		contentType := res.Header.Get("Content-Type")
		mediaType, _, _ := mime.ParseMediaType(contentType)
		return assumeRequestTypeFromMediaType(mediaType)
	}

	acceptHeader := req.Header.Get("Accept")
	requestType := assumeRequestTypeFromMediaType(acceptHeader)

	if requestType == TypeOther {
		// Try to get it from the URL
		requestType = assumeRequestTypeFromURL(req.URL)
	}

	return requestType
}

// assumeRequestTypeFromMediaType tries to detect the content type from the specified media type
func assumeRequestTypeFromMediaType(mediaType string) RequestType {
	switch {
	// $document
	case strings.Index(mediaType, "application/xhtml") == 0:
		return TypeDocument
	// We should recognize m3u file as html (in terms of filtering), because m3u play list can contains refs to video ads.
	// So if we recognize it as html we can filter it and in particular apply replace rules
	// for more details see https://github.com/AdguardTeam/AdguardForWindows/issues/1428
	// TODO: Change this -- save media type to session parameters
	case strings.Index(mediaType, "audio/x-mpegURL") == 0:
		return TypeDocument
	case strings.Index(mediaType, "text/html") == 0:
		return TypeDocument
	// $stylesheet
	case strings.Index(mediaType, "text/css") == 0:
		return TypeStylesheet
	// $script
	case strings.Index(mediaType, "application/javascript") == 0:
		return TypeScript
	case strings.Index(mediaType, "application/x-javascript") == 0:
		return TypeScript
	case strings.Index(mediaType, "text/javascript") == 0:
		return TypeScript
	// $image
	case strings.Index(mediaType, "image/") == 0:
		return TypeImage
	// $object
	case strings.Index(mediaType, "application/x-shockwave-flash") == 0:
		return TypeObject
	// $font
	case strings.Index(mediaType, "application/font") == 0:
		return TypeFont
	case strings.Index(mediaType, "application/vnd.ms-fontobject") == 0:
		return TypeFont
	case strings.Index(mediaType, "application/x-font-") == 0:
		return TypeFont
	case strings.Index(mediaType, "font/") == 0:
		return TypeFont
	// $media
	case strings.Index(mediaType, "audio/") == 0:
		return TypeMedia
	case strings.Index(mediaType, "video/") == 0:
		return TypeMedia
	// $json
	case strings.Index(mediaType, "application/json") == 0:
		return TypeXmlhttprequest
	}

	return TypeOther
}

var fileExtensions = map[string]RequestType{
	// $script
	".js":     TypeScript,
	".vbs":    TypeScript,
	".coffee": TypeScript,
	// $image
	".jpg":  TypeImage,
	".jpeg": TypeImage,
	".gif":  TypeImage,
	".png":  TypeImage,
	".tiff": TypeImage,
	".psd":  TypeImage,
	".ico":  TypeImage,
	// $stylesheet
	".css":  TypeStylesheet,
	".less": TypeStylesheet,
	// $object
	".jar": TypeObject,
	".swf": TypeObject,
	// $media
	".wav":   TypeMedia,
	".mp3":   TypeMedia,
	".mp4":   TypeMedia,
	".avi":   TypeMedia,
	".flv":   TypeMedia,
	".m3u":   TypeMedia,
	".webm":  TypeMedia,
	".mpeg":  TypeMedia,
	".3gp":   TypeMedia,
	".3g2":   TypeMedia,
	".3gpp":  TypeMedia,
	".3gpp2": TypeMedia,
	".ogg":   TypeMedia,
	".mov":   TypeMedia,
	".qt":    TypeMedia,
	".vbm":   TypeMedia,
	".mkv":   TypeMedia,
	".gifv":  TypeMedia,
	// $font
	".ttf":   TypeFont,
	".otf":   TypeFont,
	".woff":  TypeFont,
	".woff2": TypeFont,
	".eot":   TypeFont,
	// $xmlhttprequest
	".json": TypeXmlhttprequest,
}

// assumeRequestTypeFromURL assumes the request type from the file extension
func assumeRequestTypeFromURL(url *url.URL) RequestType {
	ext := path.Ext(url.Path)

	requestType, ok := fileExtensions[ext]
	if !ok {
		return TypeOther
	}

	return requestType
}
