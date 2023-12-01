package proxy

import (
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/mathutil"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// DNSContext represents a DNS request message context
type DNSContext struct {
	// Conn is the underlying client connection.  It is nil if Proto is
	// ProtoDNSCrypt, ProtoHTTPS, or ProtoQUIC.
	Conn net.Conn

	// QUICConnection is the QUIC session from which we got the query.  For
	// ProtoQUIC only.
	QUICConnection quic.Connection

	// QUICStream is the QUIC stream from which we got the query.  For
	// ProtoQUIC only.
	QUICStream quic.Stream

	// Addr is the address of the client.
	Addr netip.AddrPort

	// Upstream is the upstream that resolved the request.  In case of cached
	// response it's nil.
	Upstream upstream.Upstream

	// DNSCryptResponseWriter - necessary to respond to a DNSCrypt query
	DNSCryptResponseWriter dnscrypt.ResponseWriter

	// HTTPResponseWriter - HTTP response writer (for DoH only)
	HTTPResponseWriter http.ResponseWriter

	// HTTPRequest - HTTP request (for DoH only)
	HTTPRequest *http.Request

	// ReqECS is the EDNS Client Subnet used in the request.
	ReqECS *net.IPNet

	// CustomUpstreamConfig is the upstreams configuration used only for current
	// request.  The Resolve method of Proxy uses it instead of the default
	// servers if it's not nil.
	CustomUpstreamConfig *CustomUpstreamConfig

	// Req is the request message.
	Req *dns.Msg
	// Res is the response message.
	Res *dns.Msg

	Proto Proto

	// CachedUpstreamAddr is the address of the upstream which the answer was
	// cached with.  It's empty for responses resolved by the upstream server.
	CachedUpstreamAddr string

	// localIP - local IP address (for UDP socket to call udpMakeOOBWithSrc)
	localIP netip.Addr

	// QueryDuration is the duration of a successful query to an upstream
	// server or, if the upstream server is unavailable, to a fallback server.
	QueryDuration time.Duration

	// DoQVersion is the DoQ protocol version. It can (and should) be read from
	// ALPN, but in the current version we also use the way DNS messages are
	// encoded as a signal.
	DoQVersion DoQVersion

	// RequestID is an opaque numerical identifier of this request that is
	// guaranteed to be unique across requests processed by a single Proxy
	// instance.
	RequestID uint64

	// udpSize is the UDP buffer size from request's EDNS0 RR if presented,
	// or default otherwise.
	udpSize uint16

	// adBit is the authenticated data flag from the request.
	adBit bool
	// hasEDNS0 reflects if the request has EDNS0 RRs.
	hasEDNS0 bool
	// doBit is the DNSSEC OK flag from request's EDNS0 RR if presented.
	doBit bool
}

// calcFlagsAndSize lazily calculates some values required for Resolve method.
func (dctx *DNSContext) calcFlagsAndSize() {
	if dctx.udpSize != 0 || dctx.Req == nil {
		return
	}

	dctx.adBit = dctx.Req.AuthenticatedData
	dctx.udpSize = defaultUDPBufSize
	if o := dctx.Req.IsEdns0(); o != nil {
		dctx.hasEDNS0 = true
		dctx.doBit = o.Do()
		dctx.udpSize = o.UDPSize()
	}
}

// scrub prepares the d.Res to be written.  Truncation is applied as well if
// necessary.
func (dctx *DNSContext) scrub() {
	if dctx.Res == nil || dctx.Req == nil {
		return
	}

	// We should guarantee that all the values we need are calculated.
	dctx.calcFlagsAndSize()

	// RFC-6891 (https://tools.ietf.org/html/rfc6891) states that response
	// mustn't contain an EDNS0 RR if the request doesn't include it.
	//
	// See https://github.com/AdguardTeam/dnsproxy/issues/132.
	if dctx.hasEDNS0 && dctx.Res.IsEdns0() == nil {
		dctx.Res.SetEdns0(dctx.udpSize, dctx.doBit)
	}

	dctx.Res.Truncate(dnsSize(dctx.Proto == ProtoUDP, dctx.Req))
	// Some devices require DNS message compression.
	dctx.Res.Compress = true
}

// dnsSize returns the buffer size advertised in the requests OPT record.  When
// the request is over TCP, it returns the maximum allowed size of 64KiB.
func dnsSize(isUDP bool, r *dns.Msg) (size int) {
	if !isUDP {
		return dns.MaxMsgSize
	}

	var size16 uint16
	if o := r.IsEdns0(); o != nil {
		size16 = o.UDPSize()
	}

	return int(mathutil.Max(dns.MinMsgSize, size16))
}

// DoQVersion is an enumeration with supported DoQ versions.
type DoQVersion int

const (
	// DoQv1Draft represents old DoQ draft versions that do not send a 2-octet
	// prefix with the DNS message length.
	//
	// TODO(ameshkov): remove in the end of 2024.
	DoQv1Draft DoQVersion = 0x00

	// DoQv1 represents DoQ v1.0: https://www.rfc-editor.org/rfc/rfc9250.html.
	DoQv1 DoQVersion = 0x01
)

// CustomUpstreamConfig contains upstreams configuration with an optional cache.
type CustomUpstreamConfig struct {
	// upstream is the upstream configuration.
	upstream *UpstreamConfig

	// cache is an optional cache for upstreams in the current configuration.
	// It is disabled if nil.
	//
	// TODO(d.kolyshev): Move this cache to [UpstreamConfig].
	cache *cache
}

// NewCustomUpstreamConfig returns new custom upstream configuration.
func NewCustomUpstreamConfig(
	u *UpstreamConfig,
	cacheEnabled bool,
	cacheSize int,
	enableEDNSClientSubnet bool,
) (c *CustomUpstreamConfig) {
	var customCache *cache
	if cacheEnabled {
		// TODO(d.kolyshev): Support optimistic with newOptimisticResolver.
		customCache = newCache(cacheSize, enableEDNSClientSubnet, false)
	}

	return &CustomUpstreamConfig{
		upstream: u,
		cache:    customCache,
	}
}

// Close closes the custom upstream config.
func (c *CustomUpstreamConfig) Close() (err error) {
	if c.upstream == nil {
		return nil
	}

	return c.upstream.Close()
}

// ClearCache removes all items from the cache.
func (c *CustomUpstreamConfig) ClearCache() {
	if c.cache == nil {
		return
	}

	c.cache.clearItems()
	c.cache.clearItemsWithSubnet()
}
