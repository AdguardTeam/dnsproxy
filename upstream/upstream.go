package upstream

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/jedisct1/go-dnsstamps"

	"github.com/ameshkov/dnscrypt"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

const (
	defaultTimeout = time.Second * 10
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
	boot      bootstrapper
	preferTCP bool
}

var defaultUDPClient = dns.Client{
	Timeout: defaultTimeout,
	UDPSize: dns.MaxMsgSize,
}

var defaultTCPClient = dns.Client{
	Net:     "tcp",
	UDPSize: dns.MaxMsgSize,
	Timeout: defaultTimeout,
}

// Address returns the original address that we've put in initially, not resolved one
func (p *plainDNS) Address() string { return p.boot.address }

func (p *plainDNS) Exchange(m *dns.Msg) (*dns.Msg, error) {
	addr, _, err := p.boot.get()
	if err != nil {
		return nil, err
	}
	if p.preferTCP {
		reply, _, tcpErr := defaultTCPClient.Exchange(m, addr)
		return reply, tcpErr
	}

	reply, _, err := defaultUDPClient.Exchange(m, addr)
	if err != nil && reply != nil && reply.Truncated {
		log.Printf("Truncated message was received, retrying over TCP, question: %s", m.Question[0].String())
		reply, _, err = defaultTCPClient.Exchange(m, addr)
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
	c := dns.Conn{Conn: poolConn}
	err = c.WriteMsg(m)
	if err != nil {
		poolConn.Close()
		return nil, errorx.Decorate(err, "Failed to send a request to %s", p.Address())
	}

	reply, err := c.ReadMsg()
	if err != nil {
		poolConn.Close()
		return nil, errorx.Decorate(err, "Failed to read a request from %s", p.Address())
	}
	p.RLock()
	p.pool.Put(poolConn)
	p.RUnlock()
	return reply, nil
}

//
// DNS-over-https
//
type dnsOverHTTPS struct {
	boot bootstrapper
}

func (p *dnsOverHTTPS) Address() string { return p.boot.address }

func (p *dnsOverHTTPS) Exchange(m *dns.Msg) (*dns.Msg, error) {
	addr, tlsConfig, err := p.boot.get()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't bootstrap %s", p.boot.address)
	}

	buf, err := m.Pack()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't pack request msg")
	}
	bb := bytes.NewBuffer(buf)

	// set up a custom request with custom URL
	upstreamURL, err := url.Parse(p.boot.address)
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't parse URL %s", p.boot.address)
	}
	req := http.Request{
		Method: "POST",
		URL:    upstreamURL,
		Body:   ioutil.NopCloser(bb),
		Header: make(http.Header),
		Host:   upstreamURL.Host,
	}
	upstreamURL.Host = addr
	req.Header.Set("Content-Type", "application/dns-message")
	client := http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
	resp, err := client.Do(&req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't do a POST request to '%s'", addr)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't read body contents for '%s'", addr)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got an unexpected HTTP status code %d from '%s'", resp.StatusCode, addr)
	}
	response := dns.Msg{}
	err = response.Unpack(body)
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't unpack DNS response from '%s': body is %s", addr, string(body))
	}
	return &response, nil
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
		client = &dnscrypt.Client{Timeout: defaultTimeout, AdjustPayloadSize: true}
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

	if errorx.IsTimeout(err) {
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

// AddressToUpstream converts the specified address to an Upstream instance
// * 8.8.8.8:53 -- plain DNS
// * tcp://8.8.8.8:53 -- plain DNS over TCP
// * tls://1.1.1.1 -- DNS-over-TLS
// * https://dns.adguard.com/dns-query -- DNS-over-HTTPS
// * sdns://... -- DNS stamp that is either DNSCrypt or DNS-over-HTTPS
func AddressToUpstream(address string, bootstrap string) (Upstream, error) {
	if strings.Contains(address, "://") {
		upstreamURL, err := url.Parse(address)
		if err != nil {
			return nil, errorx.Decorate(err, "failed to parse %s", address)
		}
		return urlToUpstream(upstreamURL, bootstrap)
	}

	// we don't have scheme in the url, so it's just a plain DNS host:port
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		// doesn't have port, default to 53
		address = net.JoinHostPort(address, "53")
	}
	return &plainDNS{boot: toBoot(address, bootstrap)}, nil
}

// urlToUpstream converts a URL to an Upstream
func urlToUpstream(upstreamURL *url.URL, bootstrap string) (Upstream, error) {
	switch upstreamURL.Scheme {
	case "sdns":
		return stampToUpstream(upstreamURL.String(), bootstrap)
	case "dns":
		return &plainDNS{boot: toBoot(getHostWithPort(upstreamURL, "53"), bootstrap)}, nil
	case "tcp":
		return &plainDNS{boot: toBoot(getHostWithPort(upstreamURL, "53"), bootstrap), preferTCP: true}, nil
	case "tls":
		return &dnsOverTLS{boot: toBoot(getHostWithPort(upstreamURL, "853"), bootstrap)}, nil
	case "https":
		if upstreamURL.Port() == "" {
			upstreamURL.Host += ":443"
		}
		return &dnsOverHTTPS{boot: toBoot(upstreamURL.String(), bootstrap)}, nil
	default:
		// assume it's plain DNS
		return &plainDNS{boot: toBoot(getHostWithPort(upstreamURL, "53"), bootstrap)}, nil
	}
}

// stampToUpstream converts a DNS stamp to an Upstream
func stampToUpstream(address string, bootstrap string) (Upstream, error) {
	stamp, err := dnsstamps.NewServerStampFromString(address)
	if err != nil {
		return nil, errorx.Decorate(err, "failed to parse %s", address)
	}

	switch stamp.Proto {
	case dnsstamps.StampProtoTypeDNSCrypt:
		return &dnsCrypt{boot: toBoot(address, bootstrap)}, nil
	case dnsstamps.StampProtoTypeDoH:
		return AddressToUpstream(fmt.Sprintf("https://%s%s", stamp.ProviderName, stamp.Path), bootstrap)
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
