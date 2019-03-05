/*
Package mobile contains a simple mobile API for github.com/AdguardTeam/dnsproxy
*/
package mobile

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
)

// DNSProxy represents a proxy with it's configuration
type DNSProxy struct {
	Config *Config // Proxy configuration

	dnsProxy *proxy.Proxy
	sync.RWMutex
}

// Config is the DNS proxy configuration which uses only the subset of types that is supported by gomobile
// In Java API this structure becomes an object that needs to be configured and setted as field of DNSProxy
type Config struct {
	ListenAddr   string // IP address to listen to
	ListenPort   int    // Port to listen to
	BootstrapDNS string // A list of bootstrap DNS (i.e. 8.8.8.8:53 each on a new line)
	Fallbacks    string // A list of fallback resolvers that will be used if the main one is not available (i.e. 1.1.1.1:53 each on a new line)
	Upstreams    string // A list of upstream resolvers (each on a new line)
	Timeout      int    // Default timeout for all resolvers (milliseconds)
	CacheSize    int    // Maximum number of elements in the cache. Zero sets the default size: 2^16
	AllServers   bool   // If true, parallel queries to all configured upstream servers are enabled
}

// Start starts the DNS proxy
func (d *DNSProxy) Start() error {
	d.Lock()
	defer d.Unlock()

	if d.dnsProxy != nil {
		return errors.New("DNS proxy is already started")
	}

	c, err := createConfig(d.Config)
	if err != nil {
		return fmt.Errorf("cannot start the DNS proxy: %s", err)
	}
	d.dnsProxy = &proxy.Proxy{Config: *c}

	// Start the proxy
	return d.dnsProxy.Start()
}

// Stop stops the DNS proxy
func (d *DNSProxy) Stop() error {
	d.Lock()
	defer d.Unlock()

	var err error

	if d.dnsProxy != nil {
		err = d.dnsProxy.Stop()
		d.dnsProxy = nil
	}

	return err
}

// Addr gets the address proxy is currently listening to
func (d *DNSProxy) Addr() string {
	d.Lock()
	defer d.Unlock()

	if d.dnsProxy == nil {
		return ""
	}

	addr := d.dnsProxy.Addr(proxy.ProtoUDP)
	if addr == nil {
		return ""
	}

	return addr.String()
}

// createProxyConfig creates proxy.Config from mobile.Config values
func createConfig(config *Config) (*proxy.Config, error) {
	listenIP := net.ParseIP(config.ListenAddr)
	if listenIP == nil {
		return nil, fmt.Errorf("cannot parse %s", config.ListenAddr)
	}
	timeout := time.Duration(config.Timeout) * time.Millisecond

	// Init listen addresses and upstreams
	listenUDPAddr := &net.UDPAddr{Port: config.ListenPort, IP: listenIP}
	listenTCPAddr := &net.TCPAddr{Port: config.ListenPort, IP: listenIP}
	upstreams := make([]upstream.Upstream, 0)

	// Check bootstraps list for empty strings
	bootstrapLines := strings.Split(config.BootstrapDNS, "\n")
	var bootstraps []string
	for _, line := range bootstrapLines {
		if line == "" {
			continue
		}

		bootstraps = append(bootstraps, line)
	}

	lines := strings.Split(config.Upstreams, "\n")

	for i, line := range lines {
		if line == "" {
			continue
		}

		dnsUpstream, err := upstream.AddressToUpstream(line, upstream.Options{Bootstrap: bootstraps, Timeout: timeout})
		if err != nil {
			return nil, fmt.Errorf("cannot prepare the upstream %s (%s): %s", line, config.BootstrapDNS, err)
		}
		log.Printf("Upstream %d: %s", i, dnsUpstream.Address())
		upstreams = append(upstreams, dnsUpstream)
	}

	// Create the config
	proxyConfig := proxy.Config{
		UDPListenAddr: listenUDPAddr,
		TCPListenAddr: listenTCPAddr,
		Upstreams:     upstreams,
		AllServers:    config.AllServers,
		CacheSize:     config.CacheSize,
	}

	if config.Fallbacks != "" {
		fallbacks := []upstream.Upstream{}
		lines = strings.Split(config.Fallbacks, "\n")
		for i, line := range lines {
			if line == "" {
				continue
			}

			fallback, err := upstream.AddressToUpstream(line, upstream.Options{Timeout: timeout})
			if err != nil {
				return nil, fmt.Errorf("cannot parse the fallback %s (%s): %s", line, config.BootstrapDNS, err)
			}

			log.Printf("Fallback %d: %s", i, fallback.Address())
			fallbacks = append(fallbacks, fallback)
		}
		proxyConfig.Fallbacks = fallbacks
	}

	return &proxyConfig, nil
}
