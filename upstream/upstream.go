package upstream

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ameshkov/dnscrypt"
	"github.com/ameshkov/dnsstamps"
	"github.com/hmage/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// Upstream is an interface for a DNS resolver
type Upstream interface {
	Exchange(m *dns.Msg) (*dns.Msg, error)
	Address() string
}

//
// plain DNS
//
type plainDNS struct {
	address   string
	timeout   time.Duration
	preferTCP bool
}

// Address returns the original address that we've put in initially, not resolved one
func (p *plainDNS) Address() string { return p.address }

func (p *plainDNS) Exchange(m *dns.Msg) (*dns.Msg, error) {
	if p.preferTCP {
		tcpClient := dns.Client{Net: "tcp", Timeout: p.timeout}
		reply, _, tcpErr := tcpClient.Exchange(m, p.address)
		return reply, tcpErr
	}

	client := dns.Client{Timeout: p.timeout, UDPSize: dns.MaxMsgSize}
	reply, _, err := client.Exchange(m, p.address)
	if reply != nil && reply.Truncated {
		log.Tracef("Truncated message was received, retrying over TCP, question: %s", m.Question[0].String())
		tcpClient := dns.Client{Net: "tcp", Timeout: p.timeout}
		reply, _, err = tcpClient.Exchange(m, p.address)
	}

	return reply, err
}

//
// DNS-over-TLS
//
type dnsOverTLS struct {
	boot bootstrapper
	pool *TLSPool

	sync.RWMutex // protects pool
}

func (p *dnsOverTLS) Address() string { return p.boot.address }

func (p *dnsOverTLS) Exchange(m *dns.Msg) (*dns.Msg, error) {
	var pool *TLSPool
	p.RLock()
	pool = p.pool
	p.RUnlock()
	if pool == nil {
		p.Lock()
		// lazy initialize it
		p.pool = &TLSPool{boot: &p.boot}
		p.Unlock()
	}

	p.RLock()
	poolConn, err := p.pool.Get()
	p.RUnlock()
	if err != nil {
		return nil, errorx.Decorate(err, "Failed to get a connection from TLSPool to %s", p.Address())
	}

	reply, err := p.exchangeConn(poolConn, m)
	if err != nil {
		// The pooled connection might have been closed already (see https://github.com/AdguardTeam/dnsproxy/issues/3)
		// So we're trying to re-connect right away here.
		// We are forcing creation of a new connection instead of calling Get() again
		// as there's no guarantee that other pooled connections are intact
		p.RLock()
		poolConn, err = p.pool.Create()
		p.RUnlock()
		if err != nil {
			return nil, errorx.Decorate(err, "Failed to create a new connection from TLSPool to %s", p.Address())
		}

		// Retry sending the DNS request
		reply, err = p.exchangeConn(poolConn, m)
	}

	if err == nil {
		p.RLock()
		p.pool.Put(poolConn)
		p.RUnlock()
	}
	return reply, err
}

func (p *dnsOverTLS) exchangeConn(poolConn net.Conn, m *dns.Msg) (*dns.Msg, error) {
	c := dns.Conn{Conn: poolConn}
	err := c.WriteMsg(m)
	if err != nil {
		poolConn.Close()
		return nil, errorx.Decorate(err, "Failed to send a request to %s", p.Address())
	}

	reply, err := c.ReadMsg()
	if err != nil {
		poolConn.Close()
		return nil, errorx.Decorate(err, "Failed to read a request from %s", p.Address())
	}
	return reply, err
}

//
// DNS-over-https
//
type dnsOverHTTPS struct {
	boot bootstrapper

	// transport is an http.Transport configured to use the bootstrapped IP address
	// Transports should be reused instead of created as needed.
	// Transports are safe for concurrent use by multiple goroutines.
	transport    *http.Transport
	sync.RWMutex // protects transport
}

func (p *dnsOverHTTPS) Address() string { return p.boot.address }

func (p *dnsOverHTTPS) Exchange(m *dns.Msg) (*dns.Msg, error) {
	transport, err := p.getTransport()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't initialize HTTP transport")
	}

	buf, err := m.Pack()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't pack request msg")
	}
	bb := bytes.NewBuffer(buf)

	req, err := http.NewRequest("POST", p.boot.address, bb)
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't create a HTTP request to %s", p.boot.address)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := http.Client{
		Transport: transport,
		Timeout:   p.boot.timeout,
	}
	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't do a POST request to '%s'", p.boot.address)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't read body contents for '%s'", p.boot.address)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got an unexpected HTTP status code %d from '%s'", resp.StatusCode, p.boot.address)
	}
	response := dns.Msg{}
	err = response.Unpack(body)
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't unpack DNS response from '%s': body is %s", p.boot.address, string(body))
	}
	return &response, nil
}

// getTransport gets or lazily initializes an HTTP transport that will be used specifically for this DOH resolver
// This HTTP transport ensures that the HTTP requests will be sent exactly to the IP address got from the bootstrap resolver
func (p *dnsOverHTTPS) getTransport() (*http.Transport, error) {
	p.Lock()
	defer p.Unlock()
	if p.transport != nil {
		return p.transport, nil
	}

	tlsConfig, dialContext, err := p.boot.get()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't bootstrap %s", p.boot.address)
	}

	transport := &http.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: true,
		DialContext:        dialContext,
	}
	// It appears that this is important to explicitly configure transport to use HTTP2
	// Relevant issue: https://github.com/AdguardTeam/dnsproxy/issues/11
	http2.ConfigureTransport(transport) // nolint

	// Save the transport for the future use
	p.transport = transport
	return transport, nil
}

//
// DNSCrypt
//
type dnsCrypt struct {
	boot       bootstrapper
	client     *dnscrypt.Client     // DNSCrypt client properties
	serverInfo *dnscrypt.ServerInfo // DNSCrypt server info

	sync.RWMutex // protects DNSCrypt client
}

func (p *dnsCrypt) Address() string { return p.boot.address }

func (p *dnsCrypt) Exchange(m *dns.Msg) (*dns.Msg, error) {
	var client *dnscrypt.Client
	var serverInfo *dnscrypt.ServerInfo

	p.RLock()
	client = p.client
	serverInfo = p.serverInfo
	p.RUnlock()

	now := uint32(time.Now().Unix())
	if client == nil || serverInfo == nil || (serverInfo != nil && serverInfo.ServerCert.NotAfter < now) {
		p.Lock()

		// Using "udp" for DNSCrypt upstreams by default
		client = &dnscrypt.Client{Timeout: p.boot.timeout, AdjustPayloadSize: true}
		si, _, err := client.Dial(p.boot.address)

		if err != nil {
			p.Unlock()
			return nil, errorx.Decorate(err, "failed to fetch certificate info from %s", p.Address())
		}

		p.client = client
		p.serverInfo = si
		serverInfo = si
		p.Unlock()
	}

	reply, _, err := client.Exchange(m, serverInfo)

	if reply != nil && reply.Truncated {
		log.Tracef("Truncated message was received, retrying over TCP, question: %s", m.Question[0].String())
		tcpClient := dnscrypt.Client{Timeout: p.boot.timeout, Proto: "tcp"}
		reply, _, err = tcpClient.Exchange(m, serverInfo)
	}

	if os.IsTimeout(err) {
		// If request times out, it is possible that the server configuration has been changed.
		// It is safe to assume that the key was rotated (for instance, as it is described here: https://dnscrypt.pl/2017/02/26/how-key-rotation-is-automated/).
		// We should re-fetch the server certificate info so that the new requests were not failing.
		p.Lock()
		p.client = nil
		p.serverInfo = nil
		p.Unlock()
	}

	return reply, err
}

// Options for AddressToUpstream func
// bootstrap is a plain DNS list to be used to resolve DoH/DoT hostnames (if any)
// timeout is a default upstream timeout. Also, it is used as a timeout for bootstrap DNS requests.
// timeout=0 means infinite timeout
type Options struct {
	Bootstrap []string
	Timeout   time.Duration
}

// AddressToUpstream converts the specified address to an Upstream instance
// * 8.8.8.8:53 -- plain DNS
// * tcp://8.8.8.8:53 -- plain DNS over TCP
// * tls://1.1.1.1 -- DNS-over-TLS
// * https://dns.adguard.com/dns-query -- DNS-over-HTTPS
// * sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
func AddressToUpstream(address string, opts Options) (Upstream, error) {
	if strings.Contains(address, "://") {
		upstreamURL, err := url.Parse(address)
		if err != nil {
			return nil, errorx.Decorate(err, "failed to parse %s", address)
		}
		return urlToUpstream(upstreamURL, opts)
	}

	// we don't have scheme in the url, so it's just a plain DNS host:port
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		// doesn't have port, default to 53
		address = net.JoinHostPort(address, "53")
	}
	return &plainDNS{address: address, timeout: opts.Timeout}, nil
}

// urlToUpstream converts a URL to an Upstream
func urlToUpstream(upstreamURL *url.URL, opts Options) (Upstream, error) {
	switch upstreamURL.Scheme {
	case "sdns":
		return stampToUpstream(upstreamURL.String(), opts)
	case "dns":
		return &plainDNS{address: getHostWithPort(upstreamURL, "53"), timeout: opts.Timeout}, nil
	case "tcp":
		return &plainDNS{address: getHostWithPort(upstreamURL, "53"), timeout: opts.Timeout, preferTCP: true}, nil
	case "tls":
		return &dnsOverTLS{boot: toBoot(getHostWithPort(upstreamURL, "853"), opts.Bootstrap, opts.Timeout)}, nil
	case "https":
		if upstreamURL.Port() == "" {
			upstreamURL.Host += ":443"
		}
		return &dnsOverHTTPS{boot: toBoot(upstreamURL.String(), opts.Bootstrap, opts.Timeout)}, nil
	default:
		// assume it's plain DNS
		return &plainDNS{address: getHostWithPort(upstreamURL, "53"), timeout: opts.Timeout}, nil
	}
}

// stampToUpstream converts a DNS stamp to an Upstream
func stampToUpstream(address string, opts Options) (Upstream, error) {
	stamp, err := dnsstamps.NewServerStampFromString(address)
	if err != nil {
		return nil, errorx.Decorate(err, "failed to parse %s", address)
	}

	switch stamp.Proto {
	case dnsstamps.StampProtoTypePlain:
		return &plainDNS{address: stamp.ServerAddrStr, timeout: opts.Timeout}, nil
	case dnsstamps.StampProtoTypeDNSCrypt:
		return &dnsCrypt{boot: toBoot(address, opts.Bootstrap, opts.Timeout)}, nil
	case dnsstamps.StampProtoTypeDoH:
		return AddressToUpstream(fmt.Sprintf("https://%s%s", stamp.ProviderName, stamp.Path), opts)
	case dnsstamps.StampProtoTypeTLS:
		return AddressToUpstream(fmt.Sprintf("tls://%s", stamp.ProviderName), opts)
	}

	return nil, fmt.Errorf("unsupported protocol %v in %s", stamp.Proto, address)
}

// getHostWithPort is a helper function that appends port if needed
func getHostWithPort(upstreamURL *url.URL, defaultPort string) string {
	if upstreamURL.Port() == "" {
		return upstreamURL.Host + ":" + defaultPort
	}
	return upstreamURL.Host
}
