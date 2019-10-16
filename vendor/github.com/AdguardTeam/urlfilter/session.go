package urlfilter

import (
	"mime"
	"net/http"
)

// Session contains all the necessary data to filter requests and responses.
// It also contains the current state of the request.
// Throughout the HTTP request lifetime, session data is updated with new information.
//
// There are two main stages of the HTTP request lifetime:
// 1. Received the HTTP request headers.
//    At this point, we can find all the rules matching the request using what we know.
//    We assume the resource type by URL and "Accept" headers and look for matching rules.
//    If there's a match, and the request should be blocked, we simply block it.
//    Otherwise, we continue the HTTP request execution.
// 2. Received the HTTP response headers.
//    At this point we've got the content-type header so we know for sure what type
//    of resource we're dealing with. We are looking for matching rules again, and
//    update them.
//    The possible outcomes are:
// 2.1. The request must be blocked.
// 2.2. The response must be modified (with a $replace or a $csp rule, for instance).
// 2.3. This is an HTML response so we need to filter the response body and apply cosmetic filters.
// 2.4. We should continue execution and do nothing with the response.
type Session struct {
	ID      int64    // Session identifier
	Request *Request // Request data

	HTTPRequest  *http.Request  // HTTP request data
	HTTPResponse *http.Response // HTTP response data

	MediaType string // Mime media type
	Charset   string // Response charset (if it's possible to parse it from content-type)

	Result MatchingResult // Filtering engine result
}

// NewSession creates a new instance of the Session struct and initializes it.
// id -- unique session identifier
// req -- HTTP request data
func NewSession(id int64, req *http.Request) *Session {
	requestType := assumeRequestType(req, nil)

	s := Session{
		ID:          id,
		Request:     NewRequest(req.URL.String(), req.Referer(), requestType),
		HTTPRequest: req,
	}

	return &s
}

// SetResponse sets the response of this session
// This can also end in changing the request type
func (s *Session) SetResponse(res *http.Response) {
	s.HTTPResponse = res

	// Re-calculate RequestType once we have the response headers
	s.Request.RequestType = assumeRequestType(s.HTTPRequest, s.HTTPResponse)

	contentType := res.Header.Get("Content-Type")
	mediaType, params, _ := mime.ParseMediaType(contentType)

	s.MediaType = mediaType
	if charset, ok := params["charset"]; ok {
		s.Charset = charset
	}
}
