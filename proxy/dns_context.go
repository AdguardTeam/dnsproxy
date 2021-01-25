package proxy

import (
	"net"
	"net/http"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
)

// DNSContext represents a DNS request message context
type DNSContext struct {
	Proto     string            // "udp", "tcp", "tls", "https", "quic"
	Req       *dns.Msg          // DNS request
	Res       *dns.Msg          // DNS response from an upstream
	Addr      net.Addr          // client address.
	StartTime time.Time         // processing start time
	Upstream  upstream.Upstream // upstream that resolved DNS request

	// CustomUpstreamConfig -- custom upstream servers configuration
	// to use for this request only.
	// If set, Resolve() uses it instead of default servers
	CustomUpstreamConfig *UpstreamConfig

	// Conn is the underlying client connection.  It is nil if Proto is
	// ProtoDNSCrypt, ProtoHTTPS, or ProtoQUIC.
	Conn net.Conn

	// localIP - local IP address (for UDP socket to call udpMakeOOBWithSrc)
	localIP net.IP

	// HTTPRequest - HTTP request (for DOH only)
	HTTPRequest *http.Request
	// HTTPResponseWriter - HTTP response writer (for DOH only)
	HTTPResponseWriter http.ResponseWriter

	// DNSCryptResponseWriter - necessary to respond to a DNSCrypt query
	DNSCryptResponseWriter dnscrypt.ResponseWriter

	// QUICStream is the QUIC stream from which we got the query.  For
	// ProtoQUIC only.
	QUICStream quic.Stream

	// QUICSession is the QUIC session from which we got the query.  For
	// ProtoQUIC only.
	QUICSession quic.Session

	ecsReqIP   net.IP // ECS IP used in request
	ecsReqMask uint8  // ECS mask used in request
}

// scrub - prepares the d.Res to be written (truncates if necessary)
func (ctx *DNSContext) scrub() {
	if ctx.Res == nil || ctx.Req == nil {
		return
	}

	ctx.Res.Truncate(proxyutil.DNSSize(ctx.Proto, ctx.Req))
	ctx.Res.Compress = true // some devices require DNS message compression
}
